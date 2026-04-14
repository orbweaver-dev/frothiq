"""
Hybrid Orchestration Intelligence Layer — Frappe API  (Phase 3)

Admin orchestration endpoints have been migrated to the FrothIQ Control Center
(standalone service). Only the per-tenant inspector endpoint remains here.
"""

from __future__ import annotations

import frappe
from frappe import _


def _get_core():
    """Import frothiq_core with a helpful error if not installed."""
    try:
        import frothiq_core  # noqa: F401
        return frothiq_core
    except ImportError:
        frappe.throw(_("frothiq-core is not installed on this server"), frappe.ValidationError)


# ---------------------------------------------------------------------------
# Per-Tenant Inspector endpoint — available to any authenticated FrothIQ session
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
