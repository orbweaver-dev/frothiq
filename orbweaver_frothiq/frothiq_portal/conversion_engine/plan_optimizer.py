# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ Conversion Engine — Plan Optimizer

Scores each available plan against a tenant's observed usage and returns
a ranked recommendation.

Scoring model
-------------
  For each plan tier (free / pro / enterprise) we compute:
    utilisation_score  : how well the tenant fits inside the plan's limits
    feature_gap_score  : how many gated features they've hit recently
    cost_efficiency    : value per dollar (normalised inverse of overage risk)
    threat_alignment   : whether threat severity warrants this plan's response tools

  Final score = Σ(weight × sub-score), normalised to 0–100.

Output
------
  PlanScore(plan, score, reasons, upgrade_blockers)
    plan            : "free" | "pro" | "enterprise"
    score           : float 0–100 (higher = better fit)
    reasons         : list[str] — human-readable explanation bullets
    is_recommended  : bool — True for the highest-scoring plan above current

The optimizer never downgrades: it only recommends same or higher plans.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import frappe

_PLAN_ORDER = {"free": 0, "pro": 1, "enterprise": 2}


@dataclass
class PlanScore:
    plan:            str
    score:           float
    reasons:         list[str] = field(default_factory=list)
    is_recommended:  bool = False

    def to_dict(self) -> dict:
        return {
            "plan":           self.plan,
            "score":          round(self.score, 1),
            "reasons":        self.reasons,
            "is_recommended": self.is_recommended,
        }


def recommend_plan(tenant) -> list[PlanScore]:
    """
    Evaluate all plan tiers against this tenant's usage profile.

    Returns a list of PlanScore objects, sorted from best to least fit.
    The `is_recommended` flag is set on the single best plan that is also
    higher than the tenant's current plan.

    Parameters
    ----------
    tenant : FrothIQ Tenant doc

    Returns
    -------
    list[PlanScore] — 3 entries (free, pro, enterprise), sorted by score desc
    """
    current_plan = tenant.plan or "free"
    profile = _build_usage_profile(tenant)
    scores = [
        _score_plan("free",       profile, current_plan),
        _score_plan("pro",        profile, current_plan),
        _score_plan("enterprise", profile, current_plan),
    ]
    scores.sort(key=lambda s: s.score, reverse=True)

    # Mark the top-scoring plan that is strictly above current as recommended
    current_rank = _PLAN_ORDER.get(current_plan, 0)
    for ps in scores:
        if _PLAN_ORDER.get(ps.plan, 0) > current_rank:
            ps.is_recommended = True
            break

    return scores


def _build_usage_profile(tenant) -> dict:
    """Collect usage signals into a single dict for scoring."""
    from orbweaver_frothiq.frothiq_portal.api.billing_api import plan_limits
    limits = plan_limits(tenant.plan or "free")

    site_count = frappe.db.count("FrothIQ Agent Site", {"tenant": tenant.name})
    event_count_7d = frappe.db.count(
        "FrothIQ Event",
        {"tenant": tenant.name,
         "event_timestamp": [">=", frappe.utils.add_days(frappe.utils.now(), -7)]},
    )
    critical_7d = frappe.db.count(
        "FrothIQ Event",
        {"tenant": tenant.name,
         "severity": ["in", ["high", "critical"]],
         "event_timestamp": [">=", frappe.utils.add_days(frappe.utils.now(), -7)]},
    )

    return {
        "plan":             tenant.plan or "free",
        "site_count":       site_count,
        "max_sites":        limits.get("max_sites", 1),
        "site_utilisation": site_count / max(limits.get("max_sites", 1), 1),
        "event_count_7d":   event_count_7d,
        "critical_7d":      critical_7d,
        "events_contributed": int(tenant.events_contributed or 0),
        "intel_score":      float(tenant.intel_contribution_score or 0.0),
    }


def _score_plan(plan: str, profile: dict, current_plan: str) -> PlanScore:
    """Compute a 0–100 fit score for the given plan against usage profile."""
    from orbweaver_frothiq.frothiq_portal.api.billing_api import plan_limits, PLAN_LIMITS

    plan_data = PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])
    max_sites  = plan_data.get("max_sites", 1)
    features   = plan_data.get("features", {})
    reasons: list[str] = []
    score = 0.0

    # --- Utilisation fit (30 points) ---
    # Perfect score = using 40–80% of capacity; penalty for <20% or >90%
    util = profile["site_count"] / max(max_sites, 1)
    if util <= 0.20:
        util_score = 20.0  # under-utilised
        reasons.append(f"Site capacity is largely unused ({profile['site_count']}/{max_sites} sites).")
    elif util <= 0.80:
        util_score = 30.0  # sweet spot
        reasons.append(f"Site usage ({profile['site_count']}/{max_sites}) is a good fit.")
    elif util <= 1.0:
        util_score = 10.0  # near limit
        reasons.append(f"You are near the site limit ({profile['site_count']}/{max_sites}).")
    else:
        util_score = 0.0   # over limit
        reasons.append(f"Your {profile['site_count']} sites exceed this plan's {max_sites}-site limit.")
    score += util_score

    # --- Feature alignment (40 points) ---
    # Score based on whether gated features match the tenant's threat level
    feature_score = 0.0
    if profile["critical_7d"] >= 5:
        # High threat volume → needs response_engine
        if features.get("response_engine"):
            feature_score += 20
            reasons.append("Automated response engine matches your high threat volume.")
        else:
            reasons.append("Automated response engine not included — needed for your threat level.")
        if features.get("defense_mesh"):
            feature_score += 10
            reasons.append("Defense Mesh cluster detection is included.")
        if features.get("intel_market"):
            feature_score += 10
            reasons.append("Threat Intelligence feed helps correlate these attacks.")
    elif profile["event_count_7d"] >= 20:
        # Moderate activity → needs campaigns + federation
        if features.get("campaigns"):
            feature_score += 20
            reasons.append("Campaign correlation is included — important at your activity level.")
        if features.get("intel_market"):
            feature_score += 10
            reasons.append("Intel Marketplace provides additional context.")
        if features.get("defense_mesh"):
            feature_score += 10
    else:
        # Low activity → basic features are fine
        feature_score += 30
        reasons.append("Feature set is appropriate for your current activity level.")
    score += feature_score

    # --- Cost efficiency (30 points) ---
    monthly = plan_data.get("monthly_price", 0)
    if monthly == 0:
        cost_score = 15.0  # free is always cheap but limited
    elif profile["event_count_7d"] >= 50 or profile["critical_7d"] >= 10:
        cost_score = 30.0  # high-traffic tenant: enterprise cost is justified
    elif monthly <= 49:
        cost_score = 25.0  # pro: good value for most tenants
    else:
        cost_score = 10.0  # enterprise: only worthwhile at high usage
    score += cost_score

    return PlanScore(plan=plan, score=min(score, 100.0), reasons=reasons)
