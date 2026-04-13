# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ Conversion Engine — Revenue Signal Scoring Engine  (Phase 2)

Converts system telemetry and feature-usage patterns into monetizable signals.
All inputs are system metrics only — no personal or sensitive user data.

Revenue score formula
---------------------
  revenue_score =
    (threat_intensity      * 0.35) +
    (feature_usage_pressure * 0.25) +
    (intel_consumption_rate * 0.20) +
    (simulation_value_gap  * 0.20)

Each component is normalised to 0–100 before weighting.

Public API
----------
  compute_tenant_revenue_pressure(tenant_id)   -> dict
  compute_feature_upgrade_probability(tenant_id) -> float (0–1)
  compute_churn_risk_if_not_upgraded(tenant_id)  -> float (0–1)
  get_revenue_signal_summary(tenant_id)          -> dict   (all three)

Design constraints
------------------
  - MUST NOT use personal or sensitive user data
  - ONLY system telemetry + feature usage + event counts
  - Deterministic: same input always produces the same output
  - All results are tenant-scoped; no cross-tenant comparison
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

import frappe

logger = logging.getLogger("frothiq_conversion")

_PLAN_ORDER = {"free": 0, "pro": 1, "enterprise": 2}

# Weight constants
_W_THREAT      = 0.35
_W_FEATURE     = 0.25
_W_INTEL       = 0.20
_W_SIMULATION  = 0.20


@dataclass
class RevenueSignal:
    """
    Full revenue signal for a single tenant.

    All scores are 0–100 (higher = more monetization pressure / value gap).
    """
    tenant_id:                str
    revenue_score:            float   # composite 0–100
    threat_intensity:         float   # 0–100
    feature_usage_pressure:   float   # 0–100
    intel_consumption_rate:   float   # 0–100
    simulation_value_gap:     float   # 0–100
    upgrade_probability:      float   # 0–1
    churn_risk:               float   # 0–1
    current_plan:             str
    signals:                  list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "tenant_id":              self.tenant_id,
            "revenue_score":          round(self.revenue_score,          1),
            "threat_intensity":       round(self.threat_intensity,       1),
            "feature_usage_pressure": round(self.feature_usage_pressure, 1),
            "intel_consumption_rate": round(self.intel_consumption_rate, 1),
            "simulation_value_gap":   round(self.simulation_value_gap,   1),
            "upgrade_probability":    round(self.upgrade_probability,    3),
            "churn_risk":             round(self.churn_risk,             3),
            "current_plan":           self.current_plan,
            "signals":                self.signals,
        }


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

def compute_tenant_revenue_pressure(tenant_id: str) -> dict:
    """
    Compute the full revenue pressure profile for a tenant.

    Parameters
    ----------
    tenant_id : str — FrothIQ Tenant name

    Returns
    -------
    dict — RevenueSignal.to_dict()
    """
    signal = _build_signal(tenant_id)
    return signal.to_dict()


def compute_feature_upgrade_probability(tenant_id: str) -> float:
    """
    Estimate the probability (0–1) that this tenant would benefit from upgrading
    based on feature usage patterns and plan gaps.

    Formula: logistic(revenue_score / 100)
    Range: 0 (no pressure) → 1 (very high pressure)
    """
    signal = _build_signal(tenant_id)
    return signal.upgrade_probability


def compute_churn_risk_if_not_upgraded(tenant_id: str) -> float:
    """
    Estimate the probability (0–1) that this tenant will churn if NOT upgraded
    to a plan that covers their feature needs.

    Tenants hitting repeated feature limits without upgrading are at risk.
    """
    signal = _build_signal(tenant_id)
    return signal.churn_risk


def get_revenue_signal_summary(tenant_id: str) -> dict:
    """
    Return the full revenue signal summary for a tenant.
    Includes all component scores, composite score, upgrade probability,
    and churn risk.
    """
    return compute_tenant_revenue_pressure(tenant_id)


# ---------------------------------------------------------------------------
# Internal: signal construction
# ---------------------------------------------------------------------------

def _build_signal(tenant_id: str) -> RevenueSignal:
    """Compute all components and assemble a RevenueSignal."""
    try:
        tenant = frappe.get_doc("FrothIQ Tenant", tenant_id)
    except Exception as exc:
        logger.warning("revenue_signal_engine: tenant not found: %s — %s", tenant_id, exc)
        return _empty_signal(tenant_id)

    current_plan = tenant.plan or "free"
    signals: list[str] = []

    threat      = _score_threat_intensity(tenant, signals)
    feature     = _score_feature_usage_pressure(tenant, signals)
    intel       = _score_intel_consumption(tenant, signals)
    simulation  = _score_simulation_value_gap(tenant, signals)

    composite = (
        threat     * _W_THREAT     +
        feature    * _W_FEATURE    +
        intel      * _W_INTEL      +
        simulation * _W_SIMULATION
    )
    composite = min(composite, 100.0)

    upgrade_prob = _logistic(composite / 100.0, k=10, x0=0.55)
    churn_risk   = _compute_churn_risk(composite, feature, current_plan)

    return RevenueSignal(
        tenant_id              = tenant_id,
        revenue_score          = composite,
        threat_intensity       = threat,
        feature_usage_pressure = feature,
        intel_consumption_rate = intel,
        simulation_value_gap   = simulation,
        upgrade_probability    = upgrade_prob,
        churn_risk             = churn_risk,
        current_plan           = current_plan,
        signals                = signals,
    )


def _score_threat_intensity(tenant, signals: list) -> float:
    """
    Score 0–100 based on threat event counts.

    High critical/high event rate → high threat intensity → strong upgrade signal.
    """
    try:
        critical_24h = frappe.db.count(
            "FrothIQ Event",
            {
                "tenant":          tenant.name,
                "severity":        ["in", ["high", "critical"]],
                "event_timestamp": [">=", frappe.utils.add_days(frappe.utils.now(), -1)],
            },
        )
        total_7d = frappe.db.count(
            "FrothIQ Event",
            {
                "tenant":          tenant.name,
                "event_timestamp": [">=", frappe.utils.add_days(frappe.utils.now(), -7)],
            },
        )
    except Exception:
        return 0.0

    # Score: 10 pts per critical event (cap 60), 1 pt per 10 total (cap 40)
    score = min(critical_24h * 10, 60) + min(total_7d / 10, 40)
    score = min(score, 100.0)

    if critical_24h >= 5:
        signals.append(f"High threat intensity: {critical_24h} critical events in 24h")
    if total_7d >= 50:
        signals.append(f"Elevated event volume: {total_7d} events in 7 days")

    return score


def _score_feature_usage_pressure(tenant, signals: list) -> float:
    """
    Score 0–100 based on how often the tenant hits feature gates.

    Counts feature-blocked event types in FrothIQ Events over last 7 days.
    Also scores plan-level feature gaps: how many high-value features are locked.
    """
    from orbweaver_frothiq.frothiq_portal.api.billing_api import PLAN_LIMITS

    current_plan = tenant.plan or "free"
    plan_rank    = _PLAN_ORDER.get(current_plan, 0)
    max_rank     = _PLAN_ORDER.get("enterprise", 2)

    # Feature gap score: 0 for enterprise, 50 for free
    gap_score = (max_rank - plan_rank) / max_rank * 50.0

    # Blocked events in last 7 days
    try:
        blocked = frappe.db.count(
            "FrothIQ Event",
            {
                "tenant":          tenant.name,
                "event_type":      "feature_blocked",
                "event_timestamp": [">=", frappe.utils.add_days(frappe.utils.now(), -7)],
            },
        )
    except Exception:
        blocked = 0

    block_score = min(blocked * 5, 50.0)
    score = min(gap_score + block_score, 100.0)

    if gap_score >= 40:
        signals.append(f"Plan ({current_plan}) has significant feature gaps vs Enterprise")
    if blocked >= 5:
        signals.append(f"Feature gate hits: {blocked} blocked events in 7 days")

    return score


def _score_intel_consumption(tenant, signals: list) -> float:
    """
    Score 0–100 based on intel feed consumption relative to plan limits.

    Uses events_contributed and intel_contribution_score as proxies for usage.
    """
    contributed = int(getattr(tenant, "events_contributed", 0) or 0)
    intel_score = float(getattr(tenant, "intel_contribution_score", 0.0) or 0.0)

    # Pro advisory limit: 1000 events; enterprise: unlimited
    current_plan = tenant.plan or "free"
    if current_plan == "enterprise":
        return 0.0  # enterprise has no consumption pressure

    pro_limit = 1000
    utilisation = contributed / max(pro_limit, 1)

    score = min(utilisation * 100, 100.0)
    # Bonus: high intel score = deep engagement
    score = min(score + intel_score * 0.3, 100.0)

    if utilisation >= 0.8:
        signals.append(f"Intel consumption at {utilisation:.0%} of advisory limit")

    return score


def _score_simulation_value_gap(tenant, signals: list) -> float:
    """
    Score 0–100 representing the value gap from NOT having simulation access.

    Enterprise tenants with simulation have 0 gap.
    Non-enterprise tenants get a gap score based on:
    - DAS trend from the global regression tracker (if accessible)
    - Whether the tenant has simulation_engine feature enabled
    """
    features = (
        frappe.parse_json(tenant.features)
        if isinstance(tenant.features, str)
        else (tenant.features or {})
    )
    has_simulation = features.get("simulation_engine", False)

    if has_simulation:
        return 0.0  # No gap — already has simulation

    # Base gap: non-enterprise tenants miss simulation entirely
    current_plan = tenant.plan or "free"
    base_gap = {"free": 80.0, "pro": 55.0, "enterprise": 0.0}.get(current_plan, 80.0)

    # Enhance gap score if global DAS trend shows meaningful changes
    try:
        from frothiq_core.simulation_validation.regression_tracker import RegressionTracker
        tracker = RegressionTracker()
        agg = tracker.get_aggregate("balanced")
        if agg and agg.get("run_count", 0) >= 2:
            das_trend = abs(agg.get("das_trend_slope", 0.0))
            if das_trend > 5:
                base_gap = min(base_gap + das_trend * 2, 100.0)
                signals.append(
                    f"Simulation gap: DAS trend slope {das_trend:.1f} — "
                    "simulation would reveal underlying detection shifts"
                )
    except Exception:
        pass

    if base_gap >= 50:
        signals.append(f"Simulation engine not enabled ({current_plan} plan)")

    return base_gap


def _compute_churn_risk(composite: float, feature_pressure: float, plan: str) -> float:
    """
    Estimate churn risk if the tenant is NOT upgraded.

    High feature pressure + low composite score = frustration without value.
    Very high composite = strong need for upgrade → churn if unsatisfied.
    """
    # Churn is high when feature pressure is high but no upgrade path taken
    # Also high when composite is very high (tenant clearly outgrows plan)
    base_risk = (
        feature_pressure * 0.4 +   # main driver: hitting gates
        composite        * 0.3 +   # secondary: overall pressure
        (100 - composite) * 0.1    # low composite can mean "doesn't see value"
    ) / 100.0

    # Plan modifier: free tenants churn fastest, enterprise rarely churns
    plan_mod = {"free": 1.3, "pro": 1.0, "enterprise": 0.6}.get(plan, 1.0)
    return min(base_risk * plan_mod, 1.0)


def _logistic(x: float, k: float = 10.0, x0: float = 0.5) -> float:
    """Sigmoid / logistic function. Maps any float → (0, 1)."""
    import math
    try:
        return 1.0 / (1.0 + math.exp(-k * (x - x0)))
    except OverflowError:
        return 1.0 if x > x0 else 0.0


def _empty_signal(tenant_id: str) -> RevenueSignal:
    return RevenueSignal(
        tenant_id              = tenant_id,
        revenue_score          = 0.0,
        threat_intensity       = 0.0,
        feature_usage_pressure = 0.0,
        intel_consumption_rate = 0.0,
        simulation_value_gap   = 0.0,
        upgrade_probability    = 0.0,
        churn_risk             = 0.0,
        current_plan           = "free",
        signals                = [],
    )
