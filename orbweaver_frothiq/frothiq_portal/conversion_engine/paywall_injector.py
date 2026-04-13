# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ Conversion Engine — Paywall Injector  (Phase 3: smart orchestration)

Generates soft-paywall metadata to embed in API responses when a tenant
requests a gated feature they don't have access to.

Design principles
-----------------
  - No hard paywalls in API responses; return metadata + HTTP 200 unless
    the caller explicitly needs a 403 (e.g. bulk export, destructive ops).
  - The portal JS reads "paywall" keys and renders upgrade banners inline.
  - Soft paywalls include a preview: limited data + upgrade CTA.
  - Metadata is lightweight — never include another tenant's data.

Paywall types (Phase 3)
-----------------------
  soft_banner            — subtle top-bar banner, lowest friction
  inline_lock            — locks a specific UI section with overlay CTA
  modal_upgrade_prompt   — interstitial modal, shown only at peak moments
  delayed_email_nudge    — deferred email trigger (no UI element shown now)

Smart gating rules (Phase 3)
-----------------------------
  - Never show more than 2 paywalls per 24h per tenant
  - Suppress for enterprise tenants (they have everything)
  - Suppress if churn risk is already high (avoid annoyance loop)
  - Inject only at "value peaks": after high severity event, after simulation
    insight, after campaign detection, or after repeated feature limits

Paywall metadata format
-----------------------
  {
    "paywall": {
      "feature":       str,   — machine-readable feature key
      "required_plan": str,   — "pro" | "enterprise"
      "title":         str,   — short banner headline
      "body":          str,   — explanation paragraph
      "cta_label":     str,   — button label
      "preview_count": int,   — how many preview items are included (0 = none)
      "upgrade_url":   str,   — relative URL to the upgrade page
      "paywall_type":  str,   — soft_banner | inline_lock | modal_upgrade_prompt | delayed_email_nudge
    }
  }
"""

from __future__ import annotations

import time
from typing import Optional

import frappe


# Feature key → required plan
_FEATURE_PLANS: dict[str, str] = {
    "intel_market":           "pro",
    "defense_mesh":           "pro",
    "policy_mesh":            "pro",
    "campaigns":              "pro",
    "federation":             "pro",
    "response_engine":        "enterprise",
    "defense_mesh_auto_apply":"enterprise",
}

# Feature key → copy
_FEATURE_COPY: dict[str, dict] = {
    "intel_market": {
        "title":     "Threat Intelligence feed is a Pro feature",
        "body":      ("See how your site's threat actors rank globally. "
                      "Pro and Enterprise plans include the anonymized global threat feed."),
        "cta_label": "Upgrade to Pro",
    },
    "defense_mesh": {
        "title":     "Defense Mesh requires a Pro plan",
        "body":      ("Coordinated attack clusters are visible across the tenant estate. "
                      "Upgrade to Pro to see clusters affecting your site and get defensive recommendations."),
        "cta_label": "Upgrade to Pro",
    },
    "campaigns": {
        "title":     "Campaign correlation is a Pro feature",
        "body":      ("FrothIQ can group related bot requests into coordinated attack campaigns. "
                      "Upgrade to Pro to see active campaigns and track attacker behaviour over time."),
        "cta_label": "Upgrade to Pro",
    },
    "response_engine": {
        "title":     "Automated response requires an Enterprise plan",
        "body":      ("The response engine can automatically adjust rate limits and block thresholds "
                      "in response to active attacks. Enterprise plan only."),
        "cta_label": "Upgrade to Enterprise",
    },
    "policy_mesh": {
        "title":     "Policy-as-Code is a Pro feature",
        "body":      ("Define custom security rules that are pushed to your agents automatically. "
                      "Pro and Enterprise plans include the policy rules engine."),
        "cta_label": "Upgrade to Pro",
    },
    "federation": {
        "title":     "Federation is a Pro feature",
        "body":      ("Share threat intelligence across multiple sites and coordinate responses. "
                      "Upgrade to Pro to enable cross-site federation."),
        "cta_label": "Upgrade to Pro",
    },
}

_DEFAULT_COPY = {
    "title":     "This feature requires a higher plan",
    "body":      "Upgrade your plan to unlock this feature.",
    "cta_label": "View Plans",
}

_UPGRADE_URL = "/portal/billing/upgrade"

# Smart gating: max paywall impressions per tenant per 24h
_MAX_PAYWALLS_24H     = 2
_PAYWALL_WINDOW_SECS  = 24 * 3600
_PAYWALL_COUNT_KEY    = "ce:paywall_count:{tenant_name}"

# Value-peak triggers that allow modal_upgrade_prompt
_PEAK_EVENT_TYPES = frozenset({
    "HIGH_THREAT_DETECTED",
    "CAMPAIGN_PROPAGATION_EVENT",
    "GLOBAL_INTEL_SPIKE",
    "SIMULATION_INSIGHT_EVENT",
    "EVENTS_SPIKE",
})

# Churn risk threshold above which we suppress paywalls to avoid annoyance
_CHURN_SUPPRESS_THRESHOLD = 0.75


def is_safe_to_show_paywall(tenant_name: str, tenant_plan: str = "free") -> bool:
    """
    Phase 7 safety guard — determine whether it is safe and appropriate to
    show a paywall to this tenant right now.

    Returns False (suppress) when ANY of:
      - Tenant is on enterprise plan (already has everything)
      - Tenant has already seen ≥2 paywalls in the last 24 hours
      - Churn risk is critically high (suppress to avoid alienating tenant)
      - Tenant is currently in an active critical attack condition

    Parameters
    ----------
    tenant_name : str — FrothIQ Tenant name (for Redis lookup)
    tenant_plan : str — tenant's current plan

    Returns
    -------
    bool — True = safe to show, False = suppress
    """
    # Rule 1: never show to enterprise tenants
    if tenant_plan == "enterprise":
        return False

    # Rule 2: rate limit — max 2 per 24h
    count_key = _PAYWALL_COUNT_KEY.format(tenant_name=tenant_name)
    try:
        count = int(frappe.cache().get(count_key) or 0)
        if count >= _MAX_PAYWALLS_24H:
            return False
    except Exception:
        pass

    # Rule 3: suppress if churn risk is critically high
    try:
        from .revenue_signal_engine import compute_churn_risk_if_not_upgraded
        churn_risk = compute_churn_risk_if_not_upgraded(tenant_name)
        if churn_risk >= _CHURN_SUPPRESS_THRESHOLD:
            return False
    except Exception:
        pass

    # Rule 4: suppress during active critical attack (no monetization during crisis)
    try:
        critical_now = frappe.db.count(
            "FrothIQ Event",
            {
                "tenant":          tenant_name,
                "severity":        "critical",
                "event_timestamp": [">=", frappe.utils.add_days(frappe.utils.now(), -0.5 / 24)],
            },
        )
        if critical_now >= 3:
            return False
    except Exception:
        pass

    return True


def _record_paywall_shown(tenant_name: str) -> None:
    """Increment the 24h paywall impression counter for a tenant."""
    count_key = _PAYWALL_COUNT_KEY.format(tenant_name=tenant_name)
    try:
        current = int(frappe.cache().get(count_key) or 0)
        frappe.cache().set(count_key, current + 1, expires_in_sec=_PAYWALL_WINDOW_SECS)
    except Exception:
        pass


def select_paywall_type(
    feature: str,
    intensity_score: int = 50,
    trigger_event_type: Optional[str] = None,
) -> str:
    """
    Select the appropriate paywall display type based on context.

    Rules:
    - Value peak (peak event type) + high intensity → modal_upgrade_prompt
    - High intensity (≥70) without peak → inline_lock
    - Low intensity (< 40) → soft_banner
    - Feature blocked during usage → inline_lock
    - Default → soft_banner
    """
    is_peak = trigger_event_type in _PEAK_EVENT_TYPES

    if is_peak and intensity_score >= 70:
        return "modal_upgrade_prompt"
    if intensity_score >= 70:
        return "inline_lock"
    if intensity_score < 40:
        return "soft_banner"
    if feature in ("defense_mesh", "response_engine", "simulation_engine"):
        return "inline_lock"
    return "soft_banner"


def build_paywall(
    feature: str,
    current_plan: str,
    preview_count: int = 0,
    paywall_type: str = "soft_banner",
    tenant_name: Optional[str] = None,
    intensity_score: int = 50,
    trigger_event_type: Optional[str] = None,
) -> dict:
    """
    Build a soft-paywall metadata dict for the given feature.

    Parameters
    ----------
    feature             : machine-readable feature key (e.g. "intel_market")
    current_plan        : tenant's current plan
    preview_count       : number of preview items to signal to the frontend
    paywall_type        : soft_banner | inline_lock | modal_upgrade_prompt | delayed_email_nudge
    tenant_name         : optional — if provided, enforces smart gating + rate limiting
    intensity_score     : 0–100 signal intensity (used to auto-select paywall_type if not given)
    trigger_event_type  : ValueEvent type that caused this paywall (for peak detection)

    Returns
    -------
    dict  — the "paywall" metadata dict (to be embedded in API response)
            Returns None if smart gating suppresses the paywall.
    """
    # Smart gating: check if safe to show before building
    if tenant_name:
        if not is_safe_to_show_paywall(tenant_name, current_plan):
            return None

    # Auto-select paywall type if caller passes default
    if paywall_type == "soft_banner":
        paywall_type = select_paywall_type(feature, intensity_score, trigger_event_type)

    required_plan = _FEATURE_PLANS.get(feature, "pro")
    copy = _FEATURE_COPY.get(feature, _DEFAULT_COPY)

    result = {
        "feature":            feature,
        "required_plan":      required_plan,
        "current_plan":       current_plan,
        "title":              copy["title"],
        "body":               copy["body"],
        "cta_label":          copy["cta_label"],
        "preview_count":      preview_count,
        "upgrade_url":        _UPGRADE_URL,
        "paywall_type":       paywall_type,
        "intensity_score":    intensity_score,
        "trigger_event_type": trigger_event_type,
    }

    # Record impression for rate limiting
    if tenant_name:
        _record_paywall_shown(tenant_name)

    return result


def inject_paywall(
    response: dict,
    feature: str,
    current_plan: str,
    preview_count: int = 0,
    paywall_type: str = "soft_banner",
    tenant_name: Optional[str] = None,
    intensity_score: int = 50,
    trigger_event_type: Optional[str] = None,
) -> dict:
    """
    Embed a paywall key into an existing response dict.

    Returns the response dict with "paywall" added.
    If smart gating suppresses the paywall, "paywall" key is absent.
    """
    paywall = build_paywall(
        feature,
        current_plan,
        preview_count,
        paywall_type=paywall_type,
        tenant_name=tenant_name,
        intensity_score=intensity_score,
        trigger_event_type=trigger_event_type,
    )
    if paywall is not None:
        response["paywall"] = paywall
    return response


def is_gated(feature: str, plan: str) -> bool:
    """
    Return True if the feature is not included in the given plan.

    Safe to call before feature-flag checks when the tenant registry
    is unavailable (e.g. in template rendering).
    """
    required = _FEATURE_PLANS.get(feature, "pro")
    plan_rank = {"free": 0, "pro": 1, "enterprise": 2}
    return plan_rank.get(plan, 0) < plan_rank.get(required, 1)
