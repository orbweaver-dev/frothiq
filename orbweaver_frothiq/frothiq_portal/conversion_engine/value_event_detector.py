# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ Conversion Engine — Value Event Detector

Identifies moments when a tenant is most likely to benefit from an upgrade:
  - SITE_LIMIT_REACHED      : tenant has used all available site slots
  - FEATURE_BLOCKED         : tenant tried to access a gated feature
  - HIGH_THREAT_DETECTED    : a high/critical threat cluster is active
  - INTEL_NEAR_LIMIT        : pro tenant has seen ≥80% of their intel quota
  - EVENTS_SPIKE            : security events this week are 2× last week's average
  - CAMPAIGNS_ACTIVE        : tenant has active campaigns (pro/enterprise insight)
  - TRIAL_NEARING_END       : (future) free-tier day limit approaching

Detector design
---------------
  Each check takes a FrothIQ Tenant doc and returns a ValueEvent or None.
  ValueEvents accumulate in the caller and are de-duped by event_type +
  a 7-day cooldown per (tenant, event_type) stored in frappe.cache().

Events never trigger spam — each event_type is suppressed for 7 days after
first firing, regardless of how many checks run in that window.
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


@dataclass
class ValueEvent:
    """
    A detected high-value moment for a tenant.

    event_type : str  — machine-readable event type key
    title      : str  — short human-readable label
    body       : str  — explanatory paragraph for the notification
    cta_label  : str  — call-to-action button label
    cta_plan   : str  — plan to recommend (pro | enterprise)
    priority   : int  — 1 (most urgent) … 10 (least urgent)
    metadata   : dict — additional context (thresholds, counts, etc.)
    """
    event_type: str
    title:      str
    body:       str
    cta_label:  str
    cta_plan:   str
    priority:   int = 5
    metadata:   dict = field(default_factory=dict)


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
        event_type = "CAMPAIGNS_ACTIVE",
        title      = "Coordinated attacks may be targeting your site",
        body       = (
            f"With {recent_events} flagged security events, coordinated bot campaign detection "
            "is available on the Pro plan. Identify attack patterns before they escalate."
        ),
        cta_label  = "Upgrade to Pro",
        cta_plan   = "pro",
        priority   = 2,
        metadata   = {"flagged_events": recent_events},
    )
