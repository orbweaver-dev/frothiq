"""
FrothIQ Portal — Global Defense Mesh API (Phase 4)

Admin mutating endpoints (trigger_propagation, push_emergency_policy,
rollback_last_policy_batch, get_audit_log) have been migrated to the
FrothIQ Control Center standalone service.

Read-only analyst endpoints remain here for portal UI consumption.
"""

from __future__ import annotations

import logging

import frappe
import requests

logger = logging.getLogger(__name__)

_TIMEOUT = 15
_ALLOWED_ROLES = {"FrothIQ Admin", "FrothIQ Analyst"}


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _get_tenant():
    """Return the FrothIQ Tenant record for the current Frappe user."""
    user = frappe.session.user
    tenant_name = frappe.db.get_value("FrothIQ Tenant", {"frappe_user": user}, "name")
    if not tenant_name:
        frappe.throw("No FrothIQ tenant associated with your account.", frappe.PermissionError)
    return frappe.get_doc("FrothIQ Tenant", tenant_name)


def _require_enterprise(tenant):
    if not tenant.feature_enabled("defense_mesh"):
        frappe.throw(
            "Global Defense Mesh requires an Enterprise plan. "
            f"Your current plan ({tenant.plan}) does not include this feature.",
            frappe.PermissionError,
        )


def _require_allowed_role():
    user_roles = set(frappe.get_roles())
    if not (user_roles & _ALLOWED_ROLES):
        frappe.throw("FrothIQ Admin or FrothIQ Analyst role required.", frappe.PermissionError)


def _core_headers(tenant) -> dict:
    return {
        "X-FrothIQ-Key": tenant.api_key,
        "Content-Type": "application/json",
    }


def _core_url(path: str) -> str:
    base = frappe.conf.get("frothiq_core_url", "http://localhost:8100")
    return f"{base.rstrip('/')}{path}"


# ---------------------------------------------------------------------------
# Read-only analyst endpoints (portal UI)
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_global_mesh_status():
    """Global Defense Mesh coordinator status."""
    _require_allowed_role()
    tenant = _get_tenant()
    _require_enterprise(tenant)

    try:
        resp = requests.get(
            _core_url("/api/v2/defense/global/status"),
            headers=_core_headers(tenant),
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.warning("global_defense_api: get_global_mesh_status failed: %s", exc)
        try:
            from frothiq_core.defense_mesh.global_mesh_coordinator import global_mesh_coordinator
            return {"ok": True, "global_mesh": global_mesh_coordinator.status()}
        except Exception as exc2:
            return {"ok": False, "error": str(exc2)}


@frappe.whitelist()
def get_global_actions(limit=50, threat_level=None, action_type=None):
    """List active global defense actions as sanitized safe packets."""
    _require_allowed_role()
    tenant = _get_tenant()
    _require_enterprise(tenant)

    params = {"limit": int(limit)}
    if threat_level:
        params["threat_level"] = threat_level
    if action_type:
        params["action_type"] = action_type

    try:
        resp = requests.get(
            _core_url("/api/v2/defense/global/actions"),
            headers=_core_headers(tenant),
            params=params,
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.warning("global_defense_api: get_global_actions failed: %s", exc)
        try:
            from frothiq_core.defense_mesh.global_mesh_coordinator import global_mesh_coordinator
            actions = global_mesh_coordinator.active_actions()
            if threat_level:
                actions = [a for a in actions if a.threat_level == threat_level]
            if action_type:
                actions = [a for a in actions if a.action_type == action_type]
            packets = [a.to_safe_packet().to_dict() for a in actions[:int(limit)]]
            return {"actions": packets, "count": len(packets), "total_active": len(actions)}
        except Exception as exc2:
            return {"actions": [], "count": 0, "error": str(exc2)}


@frappe.whitelist()
def get_similarity_map(threshold=0.0):
    """Pairwise cluster similarity graph for visualization."""
    _require_allowed_role()
    tenant = _get_tenant()
    _require_enterprise(tenant)

    try:
        resp = requests.get(
            _core_url("/api/v2/defense/global/similarity-map"),
            headers=_core_headers(tenant),
            params={"threshold": float(threshold)},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.warning("global_defense_api: get_similarity_map failed: %s", exc)
        try:
            from frothiq_core.defense_mesh.coordination_engine import defense_coordination
            from frothiq_core.defense_mesh.similarity_propagation_engine import propagation_engine
            clusters = defense_coordination.clusters()
            edges = propagation_engine.similarity_map(clusters, threshold=float(threshold))
            nodes = [
                {
                    "cluster_id": c.cluster_id,
                    "threat_level": c.threat_level,
                    "attack_vectors": c.attack_vectors,
                    "affected_site_count": c.affected_site_count,
                    "similarity_score": c.similarity_score,
                }
                for c in clusters
            ]
            return {"nodes": nodes, "edges": edges, "threshold": float(threshold)}
        except Exception as exc2:
            return {"nodes": [], "edges": [], "threshold": float(threshold), "error": str(exc2)}


@frappe.whitelist()
def get_policy_distribution_status():
    """Return global policy version and per-agent version delivery stats."""
    _require_allowed_role()
    tenant = _get_tenant()
    _require_enterprise(tenant)

    try:
        from frothiq_core.policy_mesh.policy_distribution_engine import policy_distribution_engine
        return {
            "global_version": policy_distribution_engine.global_version(),
            "ok": True,
        }
    except Exception as exc:
        logger.warning("global_defense_api: get_policy_distribution_status failed: %s", exc)
        return {"ok": False, "error": str(exc)}
