# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ License Realtime Admin

Control-plane admin interface for the revocation mesh.

Provides @frappe.whitelist() endpoints for:
  - force_revoke_broadcast(tenant_id)       — instant hard-block broadcast
  - force_sync_all_tenants()                — trigger full reconciliation sweep
  - get_live_license_state_map()            — per-tenant license state snapshot
  - get_drift_report(tenant_id)             — inspect drift history
  - replay_event_stream(license_id, limit)  — replay last N events for a license
  - get_node_heartbeat_map()                — live node heartbeat status

All endpoints require System Manager or FrothIQ Admin role.
All operations are logged to the FrothIQ audit trail.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Frappe whitelisted endpoints
# ---------------------------------------------------------------------------

def force_revoke_broadcast(tenant_id: str, reason: str = "admin_revoke") -> dict:
    """
    Immediately broadcast a LICENSE_REVOKED event for tenant_id.

    Requires: System Manager or FrothIQ Admin role.
    Effect:   All registered edge nodes for this tenant will hard-block
              within the Redis pub/sub propagation latency (< 1s typical).
    """
    import frappe
    _require_admin()

    try:
        from orbweaver_frothiq.license_system.license_api import revoke_license
        revoke_license(tenant_id=tenant_id)
    except Exception as exc:
        logger.warning("force_revoke_broadcast: revoke_license failed: %s", exc)

    result = _broadcast_revoke_event(tenant_id, reason)
    _audit(
        event_type = "revoked",
        tenant_id  = tenant_id,
        details    = {"reason": reason, "broadcast": result, "admin": frappe.session.user},
    )
    return {"success": True, "tenant_id": tenant_id, "broadcast": result}


def force_sync_all_tenants() -> dict:
    """
    Trigger an immediate reconciliation sweep across all tenants.

    Requires: System Manager.
    Returns:  Reconciliation report dict.
    """
    import frappe
    _require_system_manager()

    report = _run_reconciliation_sweep()
    _audit(
        event_type = "sync",
        tenant_id  = "*",
        details    = {"admin": frappe.session.user, "report": report},
    )
    return {"success": True, "report": report}


def get_live_license_state_map() -> dict:
    """
    Return a snapshot of current license states for all tenants.

    Requires: System Manager or FrothIQ Admin.
    Returns:  {tenant_id → {enforcement_mode, plan, last_event_type, ...}}
    """
    _require_admin()
    return _build_state_map()


def get_drift_report(tenant_id: str) -> dict:
    """
    Return recent drift events for a tenant.

    Requires: System Manager or FrothIQ Admin.
    """
    _require_admin()
    return {
        "tenant_id": tenant_id,
        "drift_events": _get_drift_events(tenant_id),
        "ts": time.time(),
    }


def replay_event_stream(license_id: str, limit: int = 20) -> dict:
    """
    Return the last `limit` events from the event stream for a license.

    Requires: System Manager.
    """
    _require_system_manager()
    events = _get_event_history(license_id, limit)
    return {
        "license_id": license_id,
        "events":     events,
        "count":      len(events),
    }


def get_node_heartbeat_map() -> dict:
    """
    Return the current node registry with heartbeat timestamps.

    Requires: System Manager or FrothIQ Admin.
    """
    _require_admin()
    return _get_node_map()


# ---------------------------------------------------------------------------
# Frappe whitelist registration
# ---------------------------------------------------------------------------

try:
    import frappe
    force_revoke_broadcast  = frappe.whitelist()(force_revoke_broadcast)
    force_sync_all_tenants  = frappe.whitelist()(force_sync_all_tenants)
    get_live_license_state_map = frappe.whitelist()(get_live_license_state_map)
    get_drift_report        = frappe.whitelist()(get_drift_report)
    replay_event_stream     = frappe.whitelist()(replay_event_stream)
    get_node_heartbeat_map  = frappe.whitelist()(get_node_heartbeat_map)
except ImportError:
    pass   # Not in Frappe context (tests, edge deployment)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _require_admin() -> None:
    import frappe
    if not any(r in frappe.get_roles() for r in ("System Manager", "FrothIQ Admin")):
        frappe.throw("Insufficient permissions", frappe.PermissionError)


def _require_system_manager() -> None:
    import frappe
    if "System Manager" not in frappe.get_roles():
        frappe.throw("System Manager required", frappe.PermissionError)


def _broadcast_revoke_event(tenant_id: str, reason: str) -> dict:
    """Internal: build and broadcast a revocation event via the mesh."""
    try:
        from frothiq_core.license_realtime_mesh import (
            LicenseEventStream, RevocationBroadcastEngine,
            LICENSE_REVOKED,
        )
        import os
        key = os.environ.get("FROTHIQ_LICENSE_SECRET", "").encode("utf-8")
        if not key:
            return {"error": "signing_key_not_configured"}

        stream  = LicenseEventStream(signing_key=key)
        engine  = RevocationBroadcastEngine(signing_key=key)
        event   = stream.append(
            event_type     = LICENSE_REVOKED,
            license_id     = tenant_id,   # use tenant as license_id if no specific LIC
            tenant_id      = tenant_id,
            previous_state = "unknown",
            new_state      = "revoked",
        )
        result = engine.broadcast_revoke(event)

        # Push real-time update to the Frappe desk UI
        _push_realtime_update(tenant_id, "revoked")

        return {
            "event_id":        event.event_id,
            "redis_delivered": result.redis_delivered,
            "http_delivered":  result.http_delivered,
            "queued":          result.queued,
        }
    except Exception as exc:
        logger.error("_broadcast_revoke_event: %s", exc)
        return {"error": str(exc)}


def _run_reconciliation_sweep() -> dict:
    """Internal: run reconciliation engine sweep."""
    try:
        from frothiq_core.license_realtime_mesh import (
            LicenseEventStream, RevocationBroadcastEngine,
            RealTimeSyncCoordinator, LicenseReconciliationEngine,
        )
        import os
        key    = os.environ.get("FROTHIQ_LICENSE_SECRET", "").encode("utf-8")
        stream = LicenseEventStream(signing_key=key or b"fallback")
        coord  = RealTimeSyncCoordinator(signing_key=key or b"fallback")
        engine = RevocationBroadcastEngine(signing_key=key or b"fallback")
        rec    = LicenseReconciliationEngine(stream, coord, engine)
        report = rec.run_sweep()
        return {
            "licenses_checked": report.licenses_checked,
            "nodes_checked":    report.nodes_checked,
            "drifted_nodes":    report.drifted_nodes,
            "resyncs_triggered": report.resyncs_triggered,
            "pending_drained":  report.pending_drained,
            "duration_seconds": round(report.duration_seconds, 3),
        }
    except Exception as exc:
        return {"error": str(exc)}


def _build_state_map() -> dict:
    """Build a per-tenant license state map from Frappe DB."""
    try:
        import frappe
        records = frappe.db.get_all(
            "FrothIQ License Record",
            fields=["tenant", "status", "plan", "expires_at"],
            limit=500,
        )
        return {
            r["tenant"]: {
                "status":   r.get("status", "unknown"),
                "plan":     r.get("plan", "free"),
                "expires_at": str(r.get("expires_at", "")),
            }
            for r in records
        }
    except Exception as exc:
        return {"error": str(exc)}


def _get_drift_events(tenant_id: str) -> list:
    """Return recent quarantine/sig_failure audit events for tenant_id."""
    try:
        import frappe
        events = frappe.db.get_all(
            "FrothIQ Event",
            filters={"tenant_id": tenant_id,
                     "event_type": ["in", ["quarantine", "sig_failure", "cross_tenant"]]},
            fields=["event_type", "severity", "details", "creation"],
            order_by="creation desc",
            limit=50,
        )
        return events
    except Exception:
        return []


def _get_event_history(license_id: str, limit: int) -> list:
    """Return events from the in-process event stream (best-effort)."""
    try:
        from frothiq_core.license_realtime_mesh import LicenseEventStream
        import os
        key    = os.environ.get("FROTHIQ_LICENSE_SECRET", "").encode("utf-8")
        stream = LicenseEventStream(signing_key=key or b"fallback")
        events = stream.get_history(license_id)
        return [e.to_dict() for e in events[-limit:]]
    except Exception as exc:
        return [{"error": str(exc)}]


def _get_node_map() -> dict:
    """Return the current node registry."""
    try:
        from frothiq_core.license_realtime_mesh import RealTimeSyncCoordinator
        import os
        key   = os.environ.get("FROTHIQ_LICENSE_SECRET", "").encode("utf-8")
        coord = RealTimeSyncCoordinator(signing_key=key or b"fallback")
        nodes = coord.get_all_nodes()
        return {
            n.node_id: {
                "node_type":       n.node_type,
                "tenant_id":       n.tenant_id,
                "last_heartbeat":  n.last_heartbeat,
                "stale":           n.is_stale(),
                "license_version": n.license_version,
            }
            for n in nodes
        }
    except Exception as exc:
        return {"error": str(exc)}


def _push_realtime_update(tenant_id: str, event_type: str) -> None:
    """Push a Frappe real-time event to the admin desk UI."""
    try:
        import frappe
        frappe.publish_realtime(
            event     = "frothiq_license_mesh_update",
            message   = {"tenant_id": tenant_id, "event_type": event_type,
                         "ts": time.time()},
            after_commit = True,
        )
    except Exception:
        pass


def _audit(event_type: str, tenant_id: str, details: dict) -> None:
    try:
        from orbweaver_frothiq.frothiq_portal.license_control.license_audit_bridge import (
            LicenseAuditBridge,
        )
        LicenseAuditBridge().record(
            event_type = event_type,
            tenant_id  = tenant_id,
            license_id = "",
            details    = details,
        )
    except Exception:
        pass
