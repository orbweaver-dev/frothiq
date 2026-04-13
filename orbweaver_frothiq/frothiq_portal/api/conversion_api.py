# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ Conversion Engine — Portal API

Whitelisted methods for the portal conversion and upgrade flow.

Methods
-------
  get_upgrade_banners()          — active upgrade banners for the current tenant
  dismiss_upgrade_banner(id)     — dismiss a banner by ID
  get_plan_recommendation()      — plan optimizer output for the current tenant
  get_paywall_metadata(feature)  — soft-paywall metadata for a gated feature
  run_conversion_check()         — manual trigger for conversion orchestration (admin)
  get_upgrade_preview(feature)   — preview data + paywall for a gated feature

Security contract
-----------------
  - Every method resolves the calling user's tenant first.
  - No cross-tenant data ever returned.
  - run_conversion_check() is System Manager / FrothIQ Admin only.
"""

import frappe

_ADMIN_ROLES = {"System Manager", "FrothIQ Admin"}


def _is_admin(user=None):
    user = user or frappe.session.user
    return bool(_ADMIN_ROLES & set(frappe.get_roles(user)))


def _get_my_tenant(user=None):
    user = user or frappe.session.user
    name = frappe.db.get_value("FrothIQ Tenant", {"account_owner": user}, "name")
    if not name:
        frappe.throw(
            "No FrothIQ Tenant account found for your user.",
            frappe.DoesNotExistError,
        )
    return frappe.get_doc("FrothIQ Tenant", name)


# ---------------------------------------------------------------------------
# Banner API
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_upgrade_banners():
    """
    Return active (non-dismissed) upgrade banners for the current tenant.

    Called by the portal header on every page load to display nudges.
    Returns an empty list if no banners are active.
    """
    tenant = _get_my_tenant()
    from orbweaver_frothiq.frothiq_portal.conversion_engine.upgrade_orchestrator import (
        get_active_banners,
    )
    banners = get_active_banners(tenant.name)
    return {"banners": banners, "count": len(banners)}


@frappe.whitelist()
def dismiss_upgrade_banner(banner_id: str):
    """
    Dismiss an upgrade banner so it no longer appears in the portal.

    The banner remains in the cooldown window so it doesn't re-fire.
    """
    if not banner_id:
        frappe.throw("banner_id is required.")

    tenant = _get_my_tenant()
    from orbweaver_frothiq.frothiq_portal.conversion_engine.upgrade_orchestrator import (
        dismiss_banner,
    )
    dismissed = dismiss_banner(tenant.name, banner_id)
    return {"dismissed": dismissed}


# ---------------------------------------------------------------------------
# Plan Recommendation
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_plan_recommendation():
    """
    Return plan optimizer scores for the current tenant.

    Analyzes usage, threat level, and feature needs to recommend the best plan.

    Returns
    -------
    {
      "current_plan": str,
      "scores": [PlanScore.to_dict(), ...],  — sorted by score desc
      "recommended_plan": str | None,
    }
    """
    tenant = _get_my_tenant()
    from orbweaver_frothiq.frothiq_portal.conversion_engine.plan_optimizer import recommend_plan

    scores = recommend_plan(tenant)
    recommended = next((s.plan for s in scores if s.is_recommended), None)

    return {
        "current_plan":     tenant.plan or "free",
        "scores":           [s.to_dict() for s in scores],
        "recommended_plan": recommended,
    }


# ---------------------------------------------------------------------------
# Paywall metadata
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_paywall_metadata(feature: str):
    """
    Return soft-paywall metadata for a gated feature.

    The portal uses this to render an upgrade banner inline when a
    feature card is clicked by a tenant who doesn't have access.

    Parameters
    ----------
    feature : str  — machine-readable feature key (e.g. "intel_market")
    """
    if not feature:
        frappe.throw("feature parameter is required.")

    tenant = _get_my_tenant()
    from orbweaver_frothiq.frothiq_portal.conversion_engine.paywall_injector import (
        build_paywall,
        is_gated,
    )

    plan = tenant.plan or "free"
    gated = is_gated(feature, plan)

    return {
        "gated":   gated,
        "feature": feature,
        "plan":    plan,
        "paywall": build_paywall(feature, plan) if gated else None,
    }


# ---------------------------------------------------------------------------
# Upgrade preview
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_upgrade_preview(feature: str):
    """
    Return a sample/preview response for a gated feature, plus paywall metadata.

    This allows the portal to show "what you'd get" with a partial data preview
    before the tenant upgrades. The preview is safe — it contains no other
    tenants' data.

    Currently supported features:
      intel_market  — top-5 sample threat records (anonymized)
      defense_mesh  — cluster count and severity breakdown
      campaigns     — campaign count (no details)

    For unsupported features, returns paywall metadata only.
    """
    if not feature:
        frappe.throw("feature parameter is required.")

    tenant = _get_my_tenant()
    from orbweaver_frothiq.frothiq_portal.conversion_engine.paywall_injector import (
        build_paywall,
        is_gated,
    )

    plan = tenant.plan or "free"
    if not is_gated(feature, plan):
        return {"gated": False, "feature": feature}

    preview = _build_preview(feature)
    paywall = build_paywall(feature, plan, preview_count=len(preview.get("items", [])))

    return {
        "gated":   True,
        "feature": feature,
        "preview": preview,
        "paywall": paywall,
    }


def _build_preview(feature: str) -> dict:
    """Build safe preview data for a gated feature."""
    if feature == "intel_market":
        try:
            import os
            import requests
            core_url = os.getenv("FROTHIQ_CORE_URL", "http://127.0.0.1:8001")
            admin_key = frappe.conf.get("frothiq_api_key") or os.getenv("FROTHIQ_API_KEY", "")
            resp = requests.get(
                f"{core_url}/api/v2/intel/global-top",
                headers={"X-FrothIQ-Key": admin_key},
                params={"n": 5},
                timeout=4,
            )
            if resp.ok:
                data = resp.json()
                items = data.get("records", [])[:5]
                return {"items": items, "total": data.get("store_total", 0)}
        except Exception:
            pass
        return {"items": [], "total": 0}

    if feature == "defense_mesh":
        try:
            import os
            import requests
            core_url = os.getenv("FROTHIQ_CORE_URL", "http://127.0.0.1:8001")
            admin_key = frappe.conf.get("frothiq_api_key") or os.getenv("FROTHIQ_API_KEY", "")
            resp = requests.get(
                f"{core_url}/api/v2/defense/status",
                headers={"X-FrothIQ-Key": admin_key},
                timeout=4,
            )
            if resp.ok:
                return resp.json()
        except Exception:
            pass
        return {}

    if feature == "campaigns":
        count = frappe.db.count("FrothIQ Event", {
            "event_type": "campaign_detected",
        })
        return {"active_campaign_count": count}

    return {}


# ---------------------------------------------------------------------------
# Admin: manual orchestration trigger
# ---------------------------------------------------------------------------

def run_daily_conversion_check():
    """
    Scheduled daily job: run conversion orchestration for all active tenants.

    Called by the Frappe scheduler (hooks.py daily). Does NOT send emails
    (emails are only sent when a new high-priority event fires for the first time).
    Uses the existing per-event cooldown to prevent spam.
    """
    tenants = frappe.get_all(
        "FrothIQ Tenant",
        filters={"is_active": 1},
        fields=["name"],
    )
    results = {"checked": 0, "events_detected": 0}
    for row in tenants:
        try:
            tenant = frappe.get_doc("FrothIQ Tenant", row["name"])
            from orbweaver_frothiq.frothiq_portal.conversion_engine.upgrade_orchestrator import orchestrate
            result = orchestrate(tenant, send_email=True)
            results["checked"] += 1
            results["events_detected"] += len(result.get("events", []))
        except Exception as exc:
            frappe.logger("frothiq_conversion").warning(
                "run_daily_conversion_check: error for %s: %s", row["name"], exc
            )
    frappe.logger("frothiq_conversion").info(
        "run_daily_conversion_check: checked=%d events_detected=%d",
        results["checked"], results["events_detected"],
    )


@frappe.whitelist()
def run_conversion_check(tenant_name: str | None = None):
    """
    Manually trigger conversion orchestration for a tenant.

    System Manager / FrothIQ Admin only.
    If tenant_name is omitted, runs for the calling user's own tenant.
    """
    if not _is_admin() and tenant_name:
        frappe.throw("Only admins can run conversion checks for other tenants.", frappe.PermissionError)

    if tenant_name:
        tenant = frappe.get_doc("FrothIQ Tenant", tenant_name)
    else:
        tenant = _get_my_tenant()

    from orbweaver_frothiq.frothiq_portal.conversion_engine.upgrade_orchestrator import orchestrate
    result = orchestrate(tenant, send_email=False)

    return {
        "tenant": tenant.name,
        "plan":   tenant.plan,
        **result,
    }
