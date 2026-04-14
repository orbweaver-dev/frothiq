# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ Unified Envelope API — Frappe Control Plane

Whitelisted admin endpoints for the Unified Policy + License Signed Envelope.

Endpoints
---------
  get_envelope(tenant_id)
      Return the current signed envelope for a tenant (JSON).

  force_envelope_refresh(tenant_id)
      Rebuild + re-sign the envelope from live sub-systems.
      Broadcasts the new envelope via the realtime mesh.

  get_envelope_diff(tenant_id, old_version, new_version)
      Return a field-level diff between two envelope versions.

  get_envelope_audit_log(tenant_id, limit)
      Return recent envelope rebuild events from the audit trail.

All endpoints require System Manager or FrothIQ Admin role.
All rebuild operations are logged to the FrothIQ audit trail.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Whitelisted endpoints
# ---------------------------------------------------------------------------

def get_envelope(tenant_id: str) -> dict:
    """
    Return the current signed UnifiedEnvelope for *tenant_id* as a dict.

    The envelope is built from live sub-systems on demand and cached
    in Redis (TTL 300s).  If no signing key is configured, returns an error.
    """
    import frappe
    _require_admin()

    key = _get_signing_key()
    if not key:
        return {"error": "signing_key_not_configured"}

    try:
        # Try Redis cache first (300s TTL)
        cached = _load_cached_envelope(tenant_id)
        if cached:
            return {"envelope": cached, "source": "cache", "ts": time.time()}

        env  = _build_and_cache_envelope(tenant_id, key)
        return {"envelope": env.to_dict(), "source": "live", "ts": time.time()}
    except Exception as exc:
        logger.error("get_envelope: %s", exc)
        return {"error": str(exc)}


def force_envelope_refresh(tenant_id: str) -> dict:
    """
    Force rebuild of the envelope from all live sub-systems, sign it,
    broadcast via the realtime mesh, and update the cache.

    Returns the new envelope dict plus broadcast result.
    """
    import frappe
    _require_admin()

    key = _get_signing_key()
    if not key:
        return {"error": "signing_key_not_configured"}

    try:
        env    = _build_and_cache_envelope(tenant_id, key, force=True)
        result = _broadcast_envelope(env, key)
        _audit("envelope_refresh", tenant_id, {
            "admin": frappe.session.user,
            "version": env.version,
            "broadcast": result,
        })
        return {
            "success":   True,
            "tenant_id": tenant_id,
            "version":   env.version,
            "broadcast": result,
        }
    except Exception as exc:
        logger.error("force_envelope_refresh: %s", exc)
        return {"error": str(exc)}


def get_envelope_diff(
    tenant_id:   str,
    old_version: int,
    new_version: int,
) -> dict:
    """
    Return a field-level diff between two envelope versions for *tenant_id*.

    Differences are reported per section (license, policy, features, etc.).
    Versions are looked up from the audit trail.
    """
    _require_admin()

    try:
        old_env = _load_envelope_version(tenant_id, old_version)
        new_env = _load_envelope_version(tenant_id, new_version)

        if old_env is None or new_env is None:
            missing = []
            if old_env is None:
                missing.append(f"v{old_version}")
            if new_env is None:
                missing.append(f"v{new_version}")
            return {"error": f"version(s) not found: {', '.join(missing)}"}

        diff = _compute_diff(old_env.to_dict(), new_env.to_dict())
        return {
            "tenant_id":   tenant_id,
            "old_version": old_version,
            "new_version": new_version,
            "diff":        diff,
            "ts":          time.time(),
        }
    except Exception as exc:
        return {"error": str(exc)}


def get_envelope_audit_log(
    tenant_id: str = "",
    limit:     int = 50,
) -> dict:
    """
    Return recent envelope rebuild and broadcast events from the audit trail.
    """
    _require_admin()

    try:
        import frappe
        filters: dict = {"event_type": "envelope_refresh"}
        if tenant_id:
            filters["tenant_id"] = tenant_id

        events = frappe.db.get_all(
            "FrothIQ Event",
            filters   = filters,
            fields    = ["name", "tenant_id", "event_type", "severity",
                         "details", "creation"],
            order_by  = "creation desc",
            limit     = min(int(limit), 200),
        )
        return {"events": events, "count": len(events), "ts": time.time()}
    except Exception as exc:
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# Frappe whitelist registration
# ---------------------------------------------------------------------------

try:
    import frappe as _frappe
    get_envelope             = _frappe.whitelist()(get_envelope)
    force_envelope_refresh   = _frappe.whitelist()(force_envelope_refresh)
    get_envelope_diff        = _frappe.whitelist()(get_envelope_diff)
    get_envelope_audit_log   = _frappe.whitelist()(get_envelope_audit_log)
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _require_admin() -> None:
    import frappe
    if not any(r in frappe.get_roles()
               for r in ("System Manager", "FrothIQ Admin")):
        frappe.throw("Insufficient permissions", frappe.PermissionError)


def _get_signing_key() -> Optional[bytes]:
    raw = os.environ.get("FROTHIQ_LICENSE_SECRET", "")
    if not raw:
        try:
            import frappe
            raw = getattr(frappe.conf, "frothiq_license_secret", "")
        except Exception:
            pass
    return raw.encode("utf-8") if raw else None


def _load_cached_envelope(tenant_id: str):
    """Try to load a recently cached envelope from Frappe Redis."""
    try:
        import frappe
        cache_key = f"frothiq_envelope:{tenant_id}"
        data = frappe.cache().get_value(cache_key)
        if data:
            from frothiq_core.unified_envelope.envelope_schema import UnifiedEnvelope
            return UnifiedEnvelope.from_json(data) if isinstance(data, str) else None
    except Exception:
        pass
    return None


def _build_and_cache_envelope(tenant_id: str, key: bytes, force: bool = False):
    """Build, sign, and cache a new envelope."""
    from frothiq_core.unified_envelope.envelope_builder import build_envelope

    env = build_envelope(tenant_id, key)

    # Cache in Frappe Redis (300s TTL)
    try:
        import frappe
        cache_key = f"frothiq_envelope:{tenant_id}"
        frappe.cache().set_value(cache_key, env.to_json(), expires_in_sec=300)
    except Exception:
        pass

    return env


def _broadcast_envelope(env, key: bytes) -> dict:
    """Broadcast the envelope via the realtime mesh."""
    try:
        from frothiq_core.license_realtime_mesh import RevocationBroadcastEngine
        engine = RevocationBroadcastEngine(signing_key=key)
        result = engine.broadcast_envelope(env)
        # Also push to Frappe desk UI
        try:
            import frappe
            frappe.publish_realtime(
                event   = "frothiq_envelope_update",
                message = {
                    "tenant_id":   env.tenant_id,
                    "version":     env.version,
                    "envelope_id": env.envelope_id,
                    "ts":          env.issued_at,
                },
            )
        except Exception:
            pass
        return {
            "redis_delivered": result.redis_delivered,
            "queued":          result.queued,
        }
    except Exception as exc:
        return {"error": str(exc)}


def _load_envelope_version(tenant_id: str, version: int):
    """Load a specific envelope version from the audit trail (best-effort)."""
    try:
        import frappe, json
        from frothiq_core.unified_envelope.envelope_schema import UnifiedEnvelope
        events = frappe.db.get_all(
            "FrothIQ Event",
            filters  = {"tenant_id": tenant_id, "event_type": "envelope_refresh"},
            fields   = ["details"],
            order_by = "creation desc",
            limit    = 100,
        )
        for ev in events:
            try:
                details = json.loads(ev.get("details") or "{}")
                if details.get("version") == version:
                    raw = details.get("envelope_json")
                    if raw:
                        return UnifiedEnvelope.from_json(raw)
            except Exception:
                continue
    except Exception:
        pass
    return None


def _compute_diff(old: dict, new: dict, path: str = "") -> dict:
    """Recursively compute field-level diff between two dicts."""
    diff: dict = {}
    all_keys = set(old) | set(new)
    for key in sorted(all_keys):
        full_key = f"{path}.{key}" if path else key
        ov, nv = old.get(key), new.get(key)
        if isinstance(ov, dict) and isinstance(nv, dict):
            sub = _compute_diff(ov, nv, full_key)
            if sub:
                diff[full_key] = sub
        elif ov != nv:
            diff[full_key] = {"old": ov, "new": nv}
    return diff


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
