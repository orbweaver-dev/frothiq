# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ Conversion Engine — Paywall Injector

Generates soft-paywall metadata to embed in API responses when a tenant
requests a gated feature they don't have access to.

Design principles
-----------------
  - No hard paywalls in API responses; return metadata + HTTP 200 unless
    the caller explicitly needs a 403 (e.g. bulk export, destructive ops).
  - The portal JS reads "paywall" keys and renders upgrade banners inline.
  - Soft paywalls include a preview: limited data + upgrade CTA.
  - Metadata is lightweight — never include another tenant's data.

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
    }
  }
"""

from __future__ import annotations

from typing import Optional


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


def build_paywall(
    feature: str,
    current_plan: str,
    preview_count: int = 0,
) -> dict:
    """
    Build a soft-paywall metadata dict for the given feature.

    Parameters
    ----------
    feature       : machine-readable feature key (e.g. "intel_market")
    current_plan  : tenant's current plan
    preview_count : number of preview items to signal to the frontend

    Returns
    -------
    dict  — the "paywall" metadata dict (to be embedded in API response)
    """
    required_plan = _FEATURE_PLANS.get(feature, "pro")
    copy = _FEATURE_COPY.get(feature, _DEFAULT_COPY)

    return {
        "feature":       feature,
        "required_plan": required_plan,
        "current_plan":  current_plan,
        "title":         copy["title"],
        "body":          copy["body"],
        "cta_label":     copy["cta_label"],
        "preview_count": preview_count,
        "upgrade_url":   _UPGRADE_URL,
    }


def inject_paywall(
    response: dict,
    feature: str,
    current_plan: str,
    preview_count: int = 0,
) -> dict:
    """
    Embed a paywall key into an existing response dict.

    Returns the response dict with "paywall" added.
    """
    response["paywall"] = build_paywall(feature, current_plan, preview_count)
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
