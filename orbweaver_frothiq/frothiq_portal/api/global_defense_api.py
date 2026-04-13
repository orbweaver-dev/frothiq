"""
FrothIQ Portal — Global Defense Mesh API (Phase 4)

Whitelisted methods for the Global Defense Mesh tab in the Frappe desk.
Enterprise-only: all endpoints gate on the defense_mesh feature flag.

Methods
-------
  get_global_mesh_status()          — coordinator status + active action summary
  get_global_actions(limit, threat_level, action_type)
                                    — active global defense actions (safe packets)
  get_similarity_map(threshold)     — pairwise cluster similarity graph (nodes + edges)
  trigger_propagation(cluster_id, action_type)
                                    — manually propagate from cluster (Admin only)
  push_emergency_policy(rule_name, namespace, priority, conditions, action)
                                    — push emergency global policy rule (Admin only)
  rollback_last_policy_batch(namespace)
                                    — rollback all active rules in namespace (Admin only)
  get_policy_distribution_status()  — global policy version + per-agent delivery counts
  get_audit_log(limit)              — global action audit log (Admin only)

Access model
------------
  All methods: FrothIQ Admin or FrothIQ Analyst role + enterprise plan
  Admin-only methods: FrothIQ Admin role additionally required
"""

from __future__ import annotations

import logging

import frappe
import requests

logger = logging.getLogger(__name__)

_TIMEOUT = 15
_FEATURE = "defense_mesh"
_ADMIN_ROLES = {"FrothIQ Admin"}
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


def _require_admin_role():
    user_roles = set(frappe.get_roles())
    if not (user_roles & _ADMIN_ROLES):
        frappe.throw("FrothIQ Admin role required for this action.", frappe.PermissionError)


def _core_headers(tenant) -> dict:
    """Build auth headers for frothiq-core API calls."""
    return {
        "X-FrothIQ-Key": tenant.api_key,
        "Content-Type": "application/json",
    }


def _core_url(path: str) -> str:
    """Build URL to the local frothiq-core service."""
    base = frappe.conf.get("frothiq_core_url", "http://localhost:8100")
    return f"{base.rstrip('/')}{path}"


# ---------------------------------------------------------------------------
# Public endpoints
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_global_mesh_status():
    """
    Global Defense Mesh coordinator status.

    Returns active action counts, threat level breakdown, propagation stats,
    and the time since last coordinator refresh.
    """
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
        data = resp.json()
    except Exception as exc:
        logger.warning("global_defense_api: get_global_mesh_status failed: %s", exc)
        # Fallback: call core directly in-process if available
        try:
            from frothiq_core.defense_mesh.global_mesh_coordinator import global_mesh_coordinator
            data = {
                "ok": True,
                "global_mesh": global_mesh_coordinator.status(),
            }
        except Exception as exc2:
            return {"ok": False, "error": str(exc2)}

    return data


@frappe.whitelist()
def get_global_actions(limit=50, threat_level=None, action_type=None):
    """
    List active global defense actions as sanitized safe packets.

    All returned data is tenant-agnostic: no IPs, no tenant IDs.
    """
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
    """
    Pairwise cluster similarity graph for visualization.

    Returns nodes (clusters) and edges (similarity links ≥ threshold).
    No tenant data in either — cluster IDs and aggregate counts only.
    """
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
    """
    Return global policy version and per-agent version delivery stats.

    Shows current global_version and a summary of agent policy versions.
    Admin + Analyst access.
    """
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


# ---------------------------------------------------------------------------
# Admin-only endpoints
# ---------------------------------------------------------------------------

@frappe.whitelist()
def trigger_propagation(cluster_id: str, action_type: str = "soft_harden",
                        propagation_chain_id: str = None):
    """
    Manually trigger similarity-based propagation from a specific cluster.

    OrbWeaver Admin only. Used for manual escalation or testing.
    Returns the list of newly created propagated actions.
    """
    _require_admin_role()
    tenant = _get_tenant()
    _require_enterprise(tenant)

    valid_actions = {"harden", "soft_harden", "monitor_boost", "rate_limit_boost"}
    if action_type not in valid_actions:
        frappe.throw(f"action_type must be one of: {sorted(valid_actions)}")

    try:
        payload = {"cluster_id": cluster_id, "action_type": action_type}
        if propagation_chain_id:
            payload["propagation_chain_id"] = propagation_chain_id

        resp = requests.post(
            _core_url("/api/v2/defense/global/propagate"),
            headers={**_core_headers(tenant), "X-FrothIQ-Key": frappe.conf.get("frothiq_admin_key", "changeme")},
            json=payload,
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.warning("global_defense_api: trigger_propagation failed: %s", exc)
        try:
            from frothiq_core.defense_mesh.global_mesh_coordinator import global_mesh_coordinator
            propagated = global_mesh_coordinator.propagate_action(
                cluster_id=cluster_id,
                action_type=action_type,
                propagation_chain_id=propagation_chain_id,
            )
            packets = [a.to_safe_packet().to_dict() for a in propagated]
            return {"propagated_count": len(packets), "actions": packets}
        except Exception as exc2:
            frappe.throw(f"Propagation failed: {exc2}")


@frappe.whitelist()
def push_emergency_policy(rule_name: str, priority: int = 5,
                          condition_field: str = "score",
                          condition_operator: str = "gte",
                          condition_value: str = "80",
                          action_type: str = "block"):
    """
    Push an emergency global policy rule (priority 1–10).

    Immediately distributed to all agents on next heartbeat.
    OrbWeaver Admin only.
    """
    _require_admin_role()
    tenant = _get_tenant()
    _require_enterprise(tenant)

    priority = int(priority)
    if not (1 <= priority <= 10):
        frappe.throw("Emergency policy priority must be between 1 and 10.")

    try:
        from frothiq_core.policy_mesh.policy_schema import (
            PolicyRule, PolicyCondition, PolicyAction, PolicyStatus,
        )
        from frothiq_core.policy_mesh.policy_registry import policy_registry
        from frothiq_core.policy_mesh.policy_distribution_engine import policy_distribution_engine

        rule = PolicyRule(
            rule_id=f"emergency-{rule_name}-{int(__import__('time').time())}",
            name=rule_name,
            namespace="global",
            priority=priority,
            conditions=[PolicyCondition(condition_field, condition_operator, condition_value)],
            action=PolicyAction(action_type, {}),
            status=PolicyStatus.ACTIVE,
        )
        policy_registry.register(rule)
        resolved = policy_distribution_engine.push_emergency_policy(rule)

        logger.warning(
            "global_defense_api: emergency policy pushed by %s: '%s' priority=%d",
            frappe.session.user, rule_name, priority,
        )
        return {
            "ok": True,
            "rule_id": rule.rule_id,
            "rule_name": rule_name,
            "priority": priority,
            "new_global_version": resolved.policy_version,
        }
    except Exception as exc:
        logger.error("global_defense_api: push_emergency_policy failed: %s", exc, exc_info=True)
        frappe.throw(f"Failed to push emergency policy: {exc}")


@frappe.whitelist()
def rollback_last_policy_batch(namespace: str = "global"):
    """
    Rollback all ACTIVE rules in a namespace to ROLLED_BACK status.

    Emergency use: reverts any mis-applied policy batch.
    OrbWeaver Admin only.
    """
    _require_admin_role()
    tenant = _get_tenant()
    _require_enterprise(tenant)

    if namespace not in ("global", tenant.tenant_id):
        frappe.throw(f"Invalid namespace: {namespace!r}. Use 'global' or your tenant ID.")

    try:
        from frothiq_core.policy_mesh.policy_distribution_engine import policy_distribution_engine
        count = policy_distribution_engine.rollback_last_batch(namespace=namespace)
        logger.warning(
            "global_defense_api: policy rollback by %s — namespace=%s, %d rules rolled back",
            frappe.session.user, namespace, count,
        )
        return {"ok": True, "rolled_back_count": count, "namespace": namespace}
    except Exception as exc:
        logger.error("global_defense_api: rollback_last_policy_batch failed: %s", exc, exc_info=True)
        frappe.throw(f"Rollback failed: {exc}")


@frappe.whitelist()
def get_audit_log(limit=100):
    """
    Return the global action audit log (last N entries).

    OrbWeaver Admin only. Contains action_id, cluster_id, action_type,
    propagation_chain_id, timestamp, reason_code. No tenant data.
    """
    _require_admin_role()
    tenant = _get_tenant()
    _require_enterprise(tenant)

    try:
        resp = requests.get(
            _core_url("/api/v2/defense/global/audit-log"),
            headers={**_core_headers(tenant), "X-FrothIQ-Key": frappe.conf.get("frothiq_admin_key", "changeme")},
            params={"limit": int(limit)},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.warning("global_defense_api: get_audit_log failed: %s", exc)
        try:
            from frothiq_core.defense_mesh.global_mesh_coordinator import global_mesh_coordinator
            log = global_mesh_coordinator.audit_log(limit=int(limit))
            return {"audit_log": log, "count": len(log)}
        except Exception as exc2:
            return {"audit_log": [], "count": 0, "error": str(exc2)}
