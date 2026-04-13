"""
Hybrid Orchestration Intelligence Layer — Frappe API  (Phase 3)

Whitelisted endpoints for the Orchestration Intelligence UI.

Access model
------------
  Admin panel endpoints (OrbWeaver Dashboard):
    - Require "System Manager" or "FrothIQ Admin" role.
    - Provide global orchestration status, decision stream, rule heatmap.

  Tenant inspector endpoint:
    - Requires any authenticated FrothIQ session.
    - Returns orchestration decision for the calling tenant only.

All endpoints are read-only — orchestration itself is automatic and
deterministic.  No API call can directly override a rule or invariant.
"""

from __future__ import annotations

import time

import frappe
from frappe import _

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ADMIN_ROLES = frozenset(["System Manager", "FrothIQ Admin"])


def _require_admin():
    if not any(r in frappe.get_roles() for r in _ADMIN_ROLES):
        frappe.throw(_("Access denied — FrothIQ Admin role required"), frappe.PermissionError)


def _get_core():
    """Import frothiq_core with a helpful error if not installed."""
    try:
        import frothiq_core  # noqa: F401
        return frothiq_core
    except ImportError:
        frappe.throw(_("frothiq-core is not installed on this server"), frappe.ValidationError)


# ---------------------------------------------------------------------------
# Admin endpoints — Decision Stream
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_decision_stream(limit: int = 50, tenant_id: str | None = None):
    """
    Return recent orchestration decisions from the audit log.

    Parameters
    ----------
    limit     : int — max records to return (default 50, max 200)
    tenant_id : str — filter to a single tenant (admin sees all; None = all)

    Returns
    -------
    list[dict] — newest first
    """
    _require_admin()
    _get_core()

    from frothiq_core.orchestration import audit_log

    limit = min(int(limit), 200)
    records = audit_log.recent(tenant_id=tenant_id or None, limit=limit)

    return [r.to_dict() for r in records]


@frappe.whitelist()
def get_rule_activation_heatmap(window_hours: int = 24):
    """
    Return rule activation counts for the heatmap panel.

    Parameters
    ----------
    window_hours : int — look-back window in hours (default 24)

    Returns
    -------
    dict — {rule_name: activation_count} sorted by count descending
    """
    _require_admin()
    _get_core()

    from frothiq_core.orchestration import audit_log

    since = time.time() - int(window_hours) * 3600
    counts = audit_log.rule_activation_counts(since=since)
    # Sort descending by count
    return dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True))


@frappe.whitelist()
def get_suppression_flag_summary(window_hours: int = 24):
    """
    Return suppression flag counts for the audit panel.

    Parameters
    ----------
    window_hours : int — look-back window in hours (default 24)

    Returns
    -------
    dict — {flag: count}
    """
    _require_admin()
    _get_core()

    from frothiq_core.orchestration import audit_log

    since = time.time() - int(window_hours) * 3600
    return audit_log.suppression_flag_counts(since=since)


@frappe.whitelist()
def get_system_balance_indicator():
    """
    Return a global system balance snapshot for the System Balance Indicator panel.

    Evaluates orchestration for the _system_ pseudo-tenant to surface
    current defense state, simulation health, and monetization posture.

    Returns
    -------
    dict — balance snapshot
    """
    _require_admin()
    _get_core()

    from frothiq_core.orchestration import build_context, evaluate_orchestration

    ctx      = build_context("_system_", current_plan="enterprise")
    decision = evaluate_orchestration(ctx)

    return {
        "defense_state":         ctx.defense_state.value,
        "threat_level":          round(ctx.threat_level, 1),
        "simulation_healthy":    not ctx.simulation_degraded,
        "simulation_scores": {
            "DAS": round(ctx.simulation_scores.DAS, 1),
            "DEI": round(ctx.simulation_scores.DEI, 1),
            "PPS": round(ctx.simulation_scores.PPS, 1),
        },
        "allow_defense_actions": decision.allow_defense_actions,
        "allow_policy_updates":  decision.allow_policy_updates,
        "allow_monetization":    decision.allow_monetization,
        "monetization_mode":     decision.monetization_mode,
        "short_circuited":       decision.short_circuited,
        "triggered_rules":       list(decision.triggered_rules),
        "active_campaigns":      ctx.active_campaigns_count,
        "active_policies":       ctx.active_policies_count,
        "evaluated_at":          decision.evaluated_at,
    }


@frappe.whitelist()
def get_audit_stats(window_hours: int = 24):
    """
    Return aggregate audit statistics for the admin dashboard.

    Returns
    -------
    dict — totals, monetization block rate, defense escalation rate
    """
    _require_admin()
    _get_core()

    from frothiq_core.orchestration import audit_log

    since = time.time() - int(window_hours) * 3600
    records = audit_log.recent(limit=10_000, since=since)

    total = len(records)
    if total == 0:
        return {
            "total_evaluations":       0,
            "monetization_block_rate": 0.0,
            "defense_escalation_rate": 0.0,
            "short_circuit_rate":      0.0,
            "window_hours":            window_hours,
        }

    blocked     = sum(1 for r in records if not r.allow_monetization)
    escalated   = sum(1 for r in records if "defense_priority" in r.suppression_flags)
    short_circ  = sum(1 for r in records if r.short_circuited)

    return {
        "total_evaluations":       total,
        "monetization_block_rate": round(blocked    / total, 3),
        "defense_escalation_rate": round(escalated  / total, 3),
        "short_circuit_rate":      round(short_circ / total, 3),
        "window_hours":            window_hours,
    }


# ---------------------------------------------------------------------------
# Per-Tenant Inspector endpoint
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_my_orchestration_decision(
    revenue_score: float = 0.0,
    churn_risk: float = 0.0,
    upgrade_probability: float = 0.0,
):
    """
    Return the current orchestration decision for the calling tenant.

    Available to any authenticated FrothIQ session.  Revenue-related fields
    are passed in by the caller (from the Frappe monetization layer).

    Returns
    -------
    dict — subset of OrchestrationDecision (no audit metadata)
    """
    tenant_id = frappe.session.user

    _get_core()

    from frothiq_core.orchestration import build_context, evaluate_orchestration, record_decision

    # Resolve plan from billing API if available
    current_plan = "free"
    try:
        from orbweaver_frothiq.frothiq_portal.api.billing_api import get_current_plan
        current_plan = get_current_plan(tenant_id) or "free"
    except Exception:
        pass

    ctx      = build_context(
        tenant_id,
        current_plan,
        revenue_score=         float(revenue_score),
        churn_risk=            float(churn_risk),
        upgrade_probability=   float(upgrade_probability),
    )
    decision = evaluate_orchestration(ctx)
    record_decision(ctx, decision)

    return {
        "allow_defense_actions": decision.allow_defense_actions,
        "allow_monetization":    decision.allow_monetization,
        "monetization_mode":     decision.monetization_mode,
        "suppression_flags":     list(decision.suppression_flags),
        "triggered_rules":       list(decision.triggered_rules),
        "short_circuited":       decision.short_circuited,
        "decision_summary":      decision.decision_summary,
        "evaluated_at":          decision.evaluated_at,
    }
