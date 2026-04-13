# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ Conversion Engine — Value Event Detector

Identifies moments when a tenant is most likely to benefit from an upgrade:
  - SITE_LIMIT_REACHED          : tenant has used all available site slots
  - FEATURE_BLOCKED             : tenant tried to access a gated feature
  - HIGH_THREAT_DETECTED        : a high/critical threat cluster is active
  - INTEL_NEAR_LIMIT            : pro tenant has seen ≥80% of their intel quota
  - EVENTS_SPIKE                : security events this week are 2× last week's average
  - CAMPAIGNS_ACTIVE            : tenant has active campaigns (pro/enterprise insight)
  - TRIAL_NEARING_END           : (future) free-tier day limit approaching
  - GLOBAL_INTEL_SPIKE          : global intelligence score increased >threshold in 10 min
  - CAMPAIGN_PROPAGATION_EVENT  : defense_mesh propagation crossed ≥3 clusters
  - SIMULATION_INSIGHT_EVENT    : simulation DAS improved or dropped significantly (>10 delta)
  - POLICY_UPGRADE_OPPORTUNITY  : policy_mesh detected repeated rule fallback to higher tier

Detector design
---------------
  Each check takes a FrothIQ Tenant doc and returns a ValueEvent or None.
  ValueEvents accumulate in the caller and are de-duped by event_type +
  a 7-day cooldown per (tenant, event_type) stored in frappe.cache().

Events never trigger spam — each event_type is suppressed for 7 days after
first firing, regardless of how many checks run in that window.

Extended ValueEvent fields (Phase 1 additions)
----------------------------------------------
  intensity_score     : 0–100, how strongly the event signals upgrade value
  trigger_source      : component that triggered the event
  recommended_action  : upgrade | educate | nudge | lock_preview
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional

import frappe

# Cooldown: once an event fires for a tenant, suppress for this many seconds
_COOLDOWN_SECONDS = 7 * 24 * 3600  # 7 days

# Site utilisation threshold to fire SITE_LIMIT_REACHED
_SITE_LIMIT_PCT = 0.90   # ≥ 90% of site slots used

# Intel quota threshold (pro plan) to fire INTEL_NEAR_LIMIT
_INTEL_QUOTA_PCT = 0.80

# Event spike multiplier
_SPIKE_MULTIPLIER = 2.0

# Global intel spike: min score delta over 10-min window
_GLOBAL_INTEL_SPIKE_THRESHOLD = 15

# Propagation cluster count to fire CAMPAIGN_PROPAGATION_EVENT
_PROPAGATION_CLUSTER_MIN = 3

# Simulation DAS delta to fire SIMULATION_INSIGHT_EVENT
_SIMULATION_DAS_DELTA = 10

# Policy fallback count in 24h to fire POLICY_UPGRADE_OPPORTUNITY
_POLICY_FALLBACK_MIN = 3


@dataclass
class ValueEvent:
    """
    A detected high-value moment for a tenant.

    event_type         : str  — machine-readable event type key
    title              : str  — short human-readable label
    body               : str  — explanatory paragraph for the notification
    cta_label          : str  — call-to-action button label
    cta_plan           : str  — plan to recommend (pro | enterprise)
    priority           : int  — 1 (most urgent) … 10 (least urgent)
    metadata           : dict — additional context (thresholds, counts, etc.)
    intensity_score    : int  — 0–100, signal strength for monetization routing
    trigger_source     : str  — component that originated the event
    recommended_action : str  — upgrade | educate | nudge | lock_preview
    """
    event_type:         str
    title:              str
    body:               str
    cta_label:          str
    cta_plan:           str
    priority:           int  = 5
    metadata:           dict = field(default_factory=dict)
    intensity_score:    int  = 50
    trigger_source:     str  = "value_event_detector"
    recommended_action: str  = "nudge"


def _suppressed(tenant_name: str, event_type: str) -> bool:
    """Return True if this event has fired recently and is in cooldown."""
    key = f"ce:vev:{tenant_name}:{event_type}"
    return bool(frappe.cache().get(key))


def _mark_fired(tenant_name: str, event_type: str) -> None:
    """Mark an event as fired; suppress for COOLDOWN_SECONDS."""
    key = f"ce:vev:{tenant_name}:{event_type}"
    frappe.cache().set(key, 1, expires_in_sec=_COOLDOWN_SECONDS)


def detect_events(tenant) -> list[ValueEvent]:
    """
    Run all value-event detectors against a FrothIQ Tenant doc.

    Returns a list of ValueEvents that fired (not suppressed).
    Each fired event is immediately marked in the cache to enforce cooldown.

    Parameters
    ----------
    tenant : FrothIQ Tenant doc (frappe.get_doc result)

    Returns
    -------
    list[ValueEvent]  — may be empty
    """
    detectors = [
        _check_site_limit,
        _check_high_threat,
        _check_intel_near_limit,
        _check_events_spike,
        _check_campaigns_active,
        # Phase 1 additions — system-level intelligence events
        _check_global_intel_spike,
        _check_campaign_propagation,
        _check_simulation_insight,
        _check_policy_upgrade_opportunity,
    ]
    events: list[ValueEvent] = []
    for detector in detectors:
        try:
            event = detector(tenant)
            if event and not _suppressed(tenant.name, event.event_type):
                _mark_fired(tenant.name, event.event_type)
                events.append(event)
        except Exception as exc:
            frappe.logger("frothiq_conversion").debug(
                "value_event_detector: %s failed for %s: %s",
                detector.__name__, tenant.name, exc,
            )
    return sorted(events, key=lambda e: e.priority)


# ---------------------------------------------------------------------------
# Individual detectors
# ---------------------------------------------------------------------------

def _check_site_limit(tenant) -> Optional[ValueEvent]:
    """Fire if the tenant is using ≥90% of their site slots."""
    from orbweaver_frothiq.frothiq_portal.api.billing_api import plan_limits

    limits = plan_limits(tenant.plan or "free")
    max_sites = limits.get("max_sites", 1)
    used_sites = frappe.db.count("FrothIQ Agent Site", {"tenant": tenant.name})

    if used_sites / max(max_sites, 1) < _SITE_LIMIT_PCT:
        return None

    next_plan = "enterprise" if tenant.plan == "pro" else "pro"
    return ValueEvent(
        event_type = "SITE_LIMIT_REACHED",
        title      = "You're approaching your site limit",
        body       = (
            f"You're using {used_sites} of your {max_sites} available site slots. "
            f"Upgrade to {next_plan.capitalize()} for significantly more capacity."
        ),
        cta_label  = f"Upgrade to {next_plan.capitalize()}",
        cta_plan   = next_plan,
        priority   = 1,
        metadata   = {"used_sites": used_sites, "max_sites": max_sites},
    )


def _check_high_threat(tenant) -> Optional[ValueEvent]:
    """Fire if a high/critical defense mesh cluster exists for this tenant's campaigns."""
    if tenant.plan not in ("pro", "enterprise"):
        return None

    # Check if defense_mesh feature is enabled
    features = frappe.parse_json(tenant.features) if isinstance(tenant.features, str) else (tenant.features or {})
    if not features.get("defense_mesh"):
        # Free tenants don't see defense mesh — trigger conversion
        pass

    # Query recent FrothIQ Events for high/critical severity
    recent_critical = frappe.db.count(
        "FrothIQ Event",
        {
            "tenant": tenant.name,
            "severity": ["in", ["high", "critical"]],
            "event_timestamp": [">=", frappe.utils.add_days(frappe.utils.now(), -1)],
        },
    )
    if recent_critical < 3:
        return None

    if tenant.plan == "free":
        next_plan = "pro"
        body = (
            f"We've detected {recent_critical} high-severity security events in the last 24 hours. "
            "Upgrade to Pro to see coordinated attack clusters and get defensive recommendations."
        )
    else:
        return None  # Pro/Enterprise already have access

    return ValueEvent(
        event_type = "HIGH_THREAT_DETECTED",
        title      = "Active security threats detected on your site",
        body       = body,
        cta_label  = f"Upgrade to {next_plan.capitalize()}",
        cta_plan   = next_plan,
        priority   = 1,
        metadata   = {"recent_critical_events": recent_critical},
    )


def _check_intel_near_limit(tenant) -> Optional[ValueEvent]:
    """Fire if a Pro tenant has consumed ≥80% of their intel quota."""
    if tenant.plan != "pro":
        return None

    # Intel contribution score is a proxy for usage; Pro limit is implicitly 100 queries/day
    # We track events_contributed as the usage indicator
    contributed = int(tenant.events_contributed or 0)
    # Pro plan: advisory limit of 1000 intel lookups; fire at 800
    _PRO_INTEL_ADVISORY_LIMIT = 1000
    if contributed < _PRO_INTEL_ADVISORY_LIMIT * _INTEL_QUOTA_PCT:
        return None

    return ValueEvent(
        event_type = "INTEL_NEAR_LIMIT",
        title      = "You're making heavy use of the Threat Intel feed",
        body       = (
            f"You've contributed {contributed} data points to the threat feed. "
            "Enterprise plan includes unlimited intel access plus IP drill-downs and campaign analysis."
        ),
        cta_label  = "Upgrade to Enterprise",
        cta_plan   = "enterprise",
        priority   = 3,
        metadata   = {"events_contributed": contributed},
    )


def _check_events_spike(tenant) -> Optional[ValueEvent]:
    """Fire if this week's event count is 2× last week's."""
    from frappe.utils import add_days, now

    now_str   = now()
    week_ago  = add_days(now_str, -7)
    two_weeks = add_days(now_str, -14)

    this_week = frappe.db.count(
        "FrothIQ Event",
        {"tenant": tenant.name, "event_timestamp": [">=", week_ago]},
    )
    last_week = frappe.db.count(
        "FrothIQ Event",
        {"tenant": tenant.name, "event_timestamp": ["between", [two_weeks, week_ago]]},
    )
    if last_week < 10 or this_week < last_week * _SPIKE_MULTIPLIER:
        return None

    next_plan = "enterprise" if tenant.plan == "pro" else "pro"
    return ValueEvent(
        event_type = "EVENTS_SPIKE",
        title      = "Your security events have spiked significantly",
        body       = (
            f"Security events this week ({this_week}) are more than double last week's ({last_week}). "
            f"Upgrade to {next_plan.capitalize()} for deeper investigation tools and automated response."
        ),
        cta_label  = f"Upgrade to {next_plan.capitalize()}",
        cta_plan   = next_plan,
        priority   = 2,
        metadata   = {"this_week": this_week, "last_week": last_week},
    )


def _check_campaigns_active(tenant) -> Optional[ValueEvent]:
    """Fire for free tenants when campaigns would be visible but are gated."""
    if tenant.plan != "free":
        return None  # Pro/Enterprise already have campaigns

    # Check if there are any recent high-severity events (proxy for campaign activity)
    recent_events = frappe.db.count(
        "FrothIQ Event",
        {"tenant": tenant.name, "severity": ["in", ["medium", "high", "critical"]]},
    )
    if recent_events < 5:
        return None

    return ValueEvent(
        event_type         = "CAMPAIGNS_ACTIVE",
        title              = "Coordinated attacks may be targeting your site",
        body               = (
            f"With {recent_events} flagged security events, coordinated bot campaign detection "
            "is available on the Pro plan. Identify attack patterns before they escalate."
        ),
        cta_label          = "Upgrade to Pro",
        cta_plan           = "pro",
        priority           = 2,
        metadata           = {"flagged_events": recent_events},
        intensity_score    = min(30 + recent_events * 3, 75),
        trigger_source     = "events_monitor",
        recommended_action = "upgrade",
    )


# ---------------------------------------------------------------------------
# Phase 1: System-level intelligence event detectors
# ---------------------------------------------------------------------------

def _check_global_intel_spike(tenant) -> Optional[ValueEvent]:
    """
    Fire when the global intelligence score has spiked significantly in the
    last 10 minutes — signalling that a major threat is being tracked globally
    and the tenant may want upgraded detection.

    Uses a Redis rolling counter written by the billing/sync job.
    """
    # Only relevant for non-enterprise tenants
    if tenant.plan == "enterprise":
        return None

    try:
        # Read the 10-minute intel spike counter from Redis
        # Key is written by billing_api.sync_events_from_core() when global score rises
        spike_key = "frothiq:global_intel_spike:delta"
        raw = frappe.cache().get(spike_key)
        delta = int(raw or 0)
    except Exception:
        delta = 0

    if delta < _GLOBAL_INTEL_SPIKE_THRESHOLD:
        return None

    next_plan = "enterprise" if tenant.plan == "pro" else "pro"
    intensity = min(50 + delta, 100)

    return ValueEvent(
        event_type         = "GLOBAL_INTEL_SPIKE",
        title              = "Global threat intelligence activity is spiking",
        body               = (
            f"The global FrothIQ threat network has registered a {delta}-point intelligence surge "
            f"in the last 10 minutes. Upgrade to {next_plan.capitalize()} to see coordinated "
            "attack patterns and get ahead of threats before they reach your site."
        ),
        cta_label          = f"Upgrade to {next_plan.capitalize()}",
        cta_plan           = next_plan,
        priority           = 1,
        metadata           = {"global_intel_delta": delta},
        intensity_score    = intensity,
        trigger_source     = "global_mesh_coordinator",
        recommended_action = "upgrade" if intensity >= 75 else "educate",
    )


def _check_campaign_propagation(tenant) -> Optional[ValueEvent]:
    """
    Fire when the defense mesh has propagated a threat action across ≥3 clusters,
    indicating a coordinated, multi-vector attack the tenant may be unaware of.
    """
    if tenant.plan == "enterprise":
        return None  # Enterprise already has full mesh access

    try:
        from frothiq_core.defense_mesh.global_mesh_coordinator import global_mesh_coordinator
        active = global_mesh_coordinator.active_actions()
        # Count propagated (non-origin) actions — indicates cross-cluster spread
        propagated_count = sum(1 for a in active if a.is_propagated)
        total_clusters   = len(set(a.cluster_id for a in active))
    except Exception:
        return None

    if total_clusters < _PROPAGATION_CLUSTER_MIN:
        return None

    next_plan = "enterprise" if tenant.plan == "pro" else "pro"
    intensity = min(40 + total_clusters * 8, 95)

    return ValueEvent(
        event_type         = "CAMPAIGN_PROPAGATION_EVENT",
        title              = "Active threat is spreading across multiple attack clusters",
        body               = (
            f"The FrothIQ Global Defense Mesh has detected coordinated activity across "
            f"{total_clusters} attack clusters ({propagated_count} propagated actions). "
            f"Upgrade to {next_plan.capitalize()} to see which clusters may affect your site "
            "and receive automatic defensive hardening."
        ),
        cta_label          = f"View Threat Clusters — Upgrade to {next_plan.capitalize()}",
        cta_plan           = next_plan,
        priority           = 1,
        metadata           = {
            "active_clusters":    total_clusters,
            "propagated_actions": propagated_count,
        },
        intensity_score    = intensity,
        trigger_source     = "defense_mesh_propagation",
        recommended_action = "upgrade",
    )


def _check_simulation_insight(tenant) -> Optional[ValueEvent]:
    """
    Fire when the simulation engine detects a significant DAS change (>10 delta)
    compared to the previous run — either a regression or improvement that the
    tenant should act on.
    """
    if tenant.plan not in ("pro", "enterprise"):
        # Simulation is enterprise; for pro tenants, show the value gate
        pass

    try:
        from frothiq_core.simulation_validation.regression_tracker import RegressionTracker
        tracker = RegressionTracker()
        agg = tracker.get_aggregate("balanced")
        if not agg:
            return None

        das_trend = agg.get("das_trend_slope", 0.0)
        das_mean  = agg.get("das_mean", 0.0)
        run_count = agg.get("run_count", 0)

        if run_count < 2:
            return None

        # DAS trend slope per run: significant if |slope| > 10
        abs_delta = abs(das_trend) * 10  # scale to approximate 10-run delta
        if abs_delta < _SIMULATION_DAS_DELTA:
            return None

        is_regression = das_trend < 0
        direction     = "dropped" if is_regression else "improved"
        intensity     = min(int(50 + abs_delta * 2), 95)

    except Exception:
        return None

    features = frappe.parse_json(tenant.features) if isinstance(tenant.features, str) else (tenant.features or {})
    has_simulation = features.get("simulation_engine", False)

    if has_simulation:
        # Already has simulation — educate on what the change means
        return ValueEvent(
            event_type         = "SIMULATION_INSIGHT_EVENT",
            title              = f"Detection score {direction} significantly in simulation",
            body               = (
                f"Your simulation baseline DAS has {direction} by ~{abs_delta:.0f} points. "
                "Review the Simulation Center to identify which scenarios are driving the change "
                "and tune your policy configuration."
            ),
            cta_label          = "View Simulation Results",
            cta_plan           = "enterprise",
            priority           = 3,
            metadata           = {
                "das_mean": round(das_mean, 1),
                "das_trend_slope": round(das_trend, 3),
                "direction": direction,
            },
            intensity_score    = intensity,
            trigger_source     = "simulation_regression_tracker",
            recommended_action = "educate",
        )
    else:
        # Doesn't have simulation — use the insight to drive upgrade
        return ValueEvent(
            event_type         = "SIMULATION_INSIGHT_EVENT",
            title              = "Simulation shows your detection posture is shifting",
            body               = (
                f"Our simulation engine has detected a significant change in detection accuracy "
                f"patterns relevant to your site type. Upgrade to Enterprise to run your own "
                "simulations and validate your defenses continuously."
            ),
            cta_label          = "Upgrade to Enterprise — Run Simulations",
            cta_plan           = "enterprise",
            priority           = 2,
            metadata           = {"direction": direction, "abs_delta": round(abs_delta, 1)},
            intensity_score    = intensity,
            trigger_source     = "simulation_regression_tracker",
            recommended_action = "upgrade",
        )


def _check_policy_upgrade_opportunity(tenant) -> Optional[ValueEvent]:
    """
    Fire when the policy mesh is detecting repeated rule fallbacks to higher
    tier actions — indicating the tenant's current policies are insufficient.

    Reads the policy distribution engine's global version counter as a proxy
    for policy churn rate; high churn with low-tier plan = upgrade opportunity.
    """
    if tenant.plan == "enterprise":
        return None

    try:
        from frothiq_core.policy_mesh.policy_distribution_engine import policy_distribution_engine
        global_version = policy_distribution_engine.global_version()
        # Count recent emergency-priority policy events in FrothIQ Events
        escalation_events = frappe.db.count(
            "FrothIQ Event",
            {
                "tenant":          tenant.name,
                "event_type":      ["in", ["block_applied", "rate_limited"]],
                "event_timestamp": [">=", frappe.utils.add_days(frappe.utils.now(), -1)],
            },
        )
    except Exception:
        return None

    if escalation_events < _POLICY_FALLBACK_MIN:
        return None

    features = frappe.parse_json(tenant.features) if isinstance(tenant.features, str) else (tenant.features or {})
    has_policy_mesh = features.get("policy_mesh", False)
    next_plan = "enterprise" if tenant.plan == "pro" else "pro"
    intensity = min(40 + escalation_events * 6, 90)

    if not has_policy_mesh:
        body = (
            f"Your site has had {escalation_events} rate-limit and block escalations in the last 24 hours, "
            "but you don't have Policy-as-Code enabled. Upgrade to Pro to define custom rules "
            "that automatically tune your defenses."
        )
        action = "upgrade"
    else:
        body = (
            f"With {escalation_events} enforcement escalations in 24 hours and policy version "
            f"{global_version} active, your site is operating at the edge of its policy coverage. "
            "Enterprise plan includes emergency global policy overrides and real-time policy propagation."
        )
        action = "nudge" if intensity < 70 else "upgrade"

    return ValueEvent(
        event_type         = "POLICY_UPGRADE_OPPORTUNITY",
        title              = "Your security policies are under pressure",
        body               = body,
        cta_label          = f"Upgrade to {next_plan.capitalize()} — Enable Policy Engine",
        cta_plan           = next_plan,
        priority           = 2,
        metadata           = {
            "escalation_events_24h": escalation_events,
            "global_policy_version": global_version,
        },
        intensity_score    = intensity,
        trigger_source     = "policy_distribution_engine",
        recommended_action = action,
    )
