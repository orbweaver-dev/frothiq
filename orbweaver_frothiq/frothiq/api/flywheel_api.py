# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ Flywheel — Frappe API Layer

Exposes the Autonomous Security Intelligence Flywheel state to the Frappe
desk UI via whitelisted methods.

Plan gating:
  free       — current state only (24h signal window filtered)
  pro        — 7-day history + correlation heatmap
  enterprise — full correlation matrix + reinforcement vectors + export

Tenant isolation:
  - get_flywheel_events() always filters to the calling tenant's signals only.
  - Global health / correlation data is always anonymized (no tenant_id).
  - Raw cross-tenant signals are never returned.
"""

from __future__ import annotations

import sys
import os

import frappe

_FROTHIQ_CORE_PATH = "/opt/frothiq-core"
if _FROTHIQ_CORE_PATH not in sys.path:
    sys.path.insert(0, _FROTHIQ_CORE_PATH)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_tenant():
    """Resolve the FrothIQ Tenant for the current user. Raises 403 if none."""
    user = frappe.session.user
    name = frappe.db.get_value("FrothIQ Tenant", {"account_owner": user}, "name")
    if not name:
        frappe.throw("No FrothIQ Tenant account found.", frappe.PermissionError)
    return frappe.get_doc("FrothIQ Tenant", name)


def _get_plan(tenant=None) -> str:
    if tenant is None:
        tenant = _get_tenant()
    return (tenant.plan or "free").lower()


def _plan_allows(plan: str, required: str) -> bool:
    order = ["free", "pro", "enterprise"]
    try:
        return order.index(plan) >= order.index(required)
    except ValueError:
        return False


def _get_flywheel():
    """Lazy import of flywheel module — never fails if core is unreachable."""
    from frothiq_core.flywheel import flywheel_state_store, reinforcement_engine, correlation_engine
    return flywheel_state_store, reinforcement_engine, correlation_engine


# ---------------------------------------------------------------------------
# Whitelisted endpoints
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_flywheel_state():
    """
    Return global system health, subsystem momentum, and instability index.

    Available to all plans. Free plan gets current state only (no history).

    Response:
    {
      "global_health_score": float,
      "system_momentum":     {system: float, ...},
      "instability_index":   float,
      "drift_alerts":        [str, ...],
      "plan":                str,
      "last_updated":        float | null,
    }
    """
    tenant = _get_tenant()
    plan   = _get_plan(tenant)

    try:
        state_store, _, _ = _get_flywheel()
        state = state_store.get_state()
        return {
            "global_health_score": state.get("global_health_score", 75.0),
            "system_momentum":     state.get("system_momentum", {}),
            "instability_index":   state.get("instability_index", 0.0),
            "drift_alerts":        state.get("drift_alerts", []),
            "plan":                plan,
            "last_updated":        state.get("last_updated"),
        }
    except Exception as exc:
        frappe.log_error(f"flywheel_api.get_flywheel_state: {exc}", "Flywheel API")
        return {
            "global_health_score": None,
            "system_momentum":     {},
            "instability_index":   None,
            "drift_alerts":        [],
            "plan":                plan,
            "last_updated":        None,
            "error":               "Flywheel state unavailable",
        }


@frappe.whitelist()
def get_system_reinforcement_map():
    """
    Return the 5-system correlation heatmap and reinforcement bias map.

    Requires: pro or enterprise plan.
    Free plan receives an upgrade prompt.

    Response (pro/enterprise):
    {
      "heatmap": {
        "systems": [str, ...],
        "matrix":  [[float, ...], ...],
        "triggers": [str, ...],
        "anomalies": [...],
      },
      "bias_map":   {system: float, ...},
      "instability_index": float,
      "plan": str,
    }
    """
    tenant = _get_tenant()
    plan   = _get_plan(tenant)

    if not _plan_allows(plan, "pro"):
        return {
            "access":   "upgrade_required",
            "plan":     plan,
            "required": "pro",
            "message":  "Upgrade to Pro to access the system correlation heatmap.",
        }

    try:
        state_store, reinforce, corr = _get_flywheel()
        instability = state_store.get_instability_index()
        vector      = reinforce.compute(instability_index=instability)
        heatmap     = corr.get_heatmap()

        result = {
            "heatmap":          heatmap,
            "bias_map":         vector.system_bias_map,
            "instability_index": vector.instability_index,
            "plan":             plan,
        }

        # Enterprise: include full reinforcement vector
        if _plan_allows(plan, "enterprise"):
            result["reinforcement_vector"] = vector.to_dict()

        return result
    except Exception as exc:
        frappe.log_error(f"flywheel_api.get_system_reinforcement_map: {exc}", "Flywheel API")
        return {"error": "Reinforcement map unavailable", "plan": plan}


@frappe.whitelist()
def get_flywheel_events(limit: int = 100):
    """
    Return normalized FlywheelSignal history for the calling tenant.

    Signals are always filtered to the calling tenant's own data — no
    cross-tenant signal leakage.

    Plan gating:
      free:       last 24h only (by timestamp_bucket)
      pro:        7-day window
      enterprise: full history (up to limit)

    Response:
    {
      "events": [{
        "ts": int,
        "type": str,
        "origin": str,
        "delta": float,
        "severity": str,
      }, ...],
      "plan": str,
      "window_hours": int,
    }
    """
    tenant    = _get_tenant()
    plan      = _get_plan(tenant)
    limit     = min(int(limit), 1000)

    window_map = {"free": 24, "pro": 168, "enterprise": 8760}
    window_h   = window_map.get(plan, 24)

    try:
        import time, math
        state_store, _, _ = _get_flywheel()
        cutoff_bucket = int(math.floor((time.time() - window_h * 3600) / 3600)) * 3600

        # get_recent_signals filters by tenant_id and strips cross-tenant data
        all_events = state_store.get_recent_signals(limit=limit, tenant_id=tenant.name)
        # Apply window filter
        filtered = [e for e in all_events if e.get("ts", 0) >= cutoff_bucket]

        return {
            "events":       filtered[:limit],
            "plan":         plan,
            "window_hours": window_h,
        }
    except Exception as exc:
        frappe.log_error(f"flywheel_api.get_flywheel_events: {exc}", "Flywheel API")
        return {"events": [], "plan": plan, "window_hours": window_h, "error": "Events unavailable"}


@frappe.whitelist()
def get_optimization_suggestions():
    """
    Return prioritized optimization suggestions from the reinforcement engine.

    Available to all plans. Free plan receives max 2 suggestions.
    Pro/Enterprise receive the full suggestion list.

    Response:
    {
      "suggestions": [{
        "priority": str,
        "system":   str,
        "action":   str,
        "reason":   str,
      }, ...],
      "plan": str,
    }
    """
    tenant = _get_tenant()
    plan   = _get_plan(tenant)

    try:
        state_store, _, _ = _get_flywheel()
        suggestions = state_store.get_optimization_suggestions()

        # Free plan: cap at 2 suggestions
        if not _plan_allows(plan, "pro"):
            suggestions = suggestions[:2]

        return {"suggestions": suggestions, "plan": plan}
    except Exception as exc:
        frappe.log_error(f"flywheel_api.get_optimization_suggestions: {exc}", "Flywheel API")
        return {"suggestions": [], "plan": plan, "error": "Suggestions unavailable"}
