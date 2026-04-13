# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ Portal — Growth & Monetization API  (Phase 6)

Whitelisted methods for the Growth & Monetization tab in the FrothIQ Control Center.
Admin-only dashboard; returns aggregate monetization intelligence.

Methods
-------
  get_revenue_heatmap()            — all tenants ranked by revenue_score (Admin)
  get_upgrade_funnel()             — observed → converted state distribution (Admin)
  get_value_event_stream(limit)    — recent value events across tenants (Admin)
  get_paywall_activity()           — impression/conversion/dismissal stats (Admin)
  get_plan_recommendation_panel()  — per-tenant plan recommendations (Admin)
  get_my_revenue_signal()          — own tenant revenue signal (any tenant)
  get_my_optimal_plan()            — own tenant plan optimization (any tenant)
  get_my_conversion_state()        — own upgrade funnel state (any tenant)
  record_plan_upgrade(tenant_name) — mark tenant as converted (Admin)

Privacy contract
----------------
  Admin endpoints return aggregate and per-tenant-name data (no cross-tenant
  personal data). No IP addresses, no raw request data.
  Tenant self-service endpoints return only the calling tenant's own data.
"""

from __future__ import annotations

import logging

import frappe

logger = logging.getLogger("frothiq_conversion")

_ADMIN_ROLES = {"System Manager", "FrothIQ Admin"}
_ALLOWED_ROLES = {"System Manager", "FrothIQ Admin", "FrothIQ Analyst"}


def _is_admin():
    return bool(_ADMIN_ROLES & set(frappe.get_roles()))


def _require_admin():
    if not _is_admin():
        frappe.throw("FrothIQ Admin role required.", frappe.PermissionError)


def _require_allowed():
    if not (set(frappe.get_roles()) & _ALLOWED_ROLES):
        frappe.throw("FrothIQ Admin or Analyst role required.", frappe.PermissionError)


def _get_my_tenant():
    user = frappe.session.user
    name = frappe.db.get_value("FrothIQ Tenant", {"account_owner": user}, "name")
    if not name:
        frappe.throw("No FrothIQ Tenant found for your user.", frappe.DoesNotExistError)
    return frappe.get_doc("FrothIQ Tenant", name)


# ---------------------------------------------------------------------------
# Admin endpoints
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_revenue_heatmap(limit: int = 50):
    """
    Return all active tenants ranked by revenue_score (highest pressure first).

    Color bands:
      red    revenue_score ≥ 70
      orange revenue_score 40–69
      green  revenue_score < 40

    Admin only.
    """
    _require_admin()
    from orbweaver_frothiq.frothiq_portal.conversion_engine.revenue_signal_engine import (
        compute_tenant_revenue_pressure,
    )

    tenants = frappe.get_all(
        "FrothIQ Tenant",
        filters={"is_active": 1},
        fields=["name", "plan"],
        limit_page_length=int(limit),
    )

    rows = []
    for row in tenants:
        try:
            signal = compute_tenant_revenue_pressure(row["name"])
            score  = signal["revenue_score"]
            color  = "red" if score >= 70 else ("orange" if score >= 40 else "green")
            rows.append({
                "tenant_id":              row["name"],
                "plan":                   row["plan"] or "free",
                "revenue_score":          score,
                "color_band":             color,
                "threat_intensity":       signal["threat_intensity"],
                "feature_usage_pressure": signal["feature_usage_pressure"],
                "upgrade_probability":    signal["upgrade_probability"],
                "churn_risk":             signal["churn_risk"],
                "signals":                signal["signals"][:3],  # top 3 signals
            })
        except Exception as exc:
            logger.debug("get_revenue_heatmap: error for %s: %s", row["name"], exc)

    rows.sort(key=lambda r: r["revenue_score"], reverse=True)
    return {"tenants": rows, "count": len(rows)}


@frappe.whitelist()
def get_upgrade_funnel():
    """
    Return aggregate upgrade funnel state distribution.

    Shows how many tenants are in each state:
    observed → nudged → engaged → converted → retained

    Admin only.
    """
    _require_admin()
    from orbweaver_frothiq.frothiq_portal.conversion_engine.upgrade_orchestrator import (
        get_funnel_summary,
    )
    return get_funnel_summary()


@frappe.whitelist()
def get_value_event_stream(limit: int = 100):
    """
    Return recent value events across all tenants.

    Sourced from the FrothIQ Event log where event_type is a monetization signal.
    Shows only event metadata — no personal data, no IPs.

    Admin + Analyst access.
    """
    _require_allowed()

    monetization_types = [
        "GLOBAL_INTEL_SPIKE",
        "CAMPAIGN_PROPAGATION_EVENT",
        "SIMULATION_INSIGHT_EVENT",
        "POLICY_UPGRADE_OPPORTUNITY",
        "SITE_LIMIT_REACHED",
        "HIGH_THREAT_DETECTED",
        "EVENTS_SPIKE",
        "CAMPAIGNS_ACTIVE",
        "INTEL_NEAR_LIMIT",
    ]

    events = frappe.get_all(
        "FrothIQ Event",
        filters={"event_type": ["in", monetization_types]},
        fields=["name", "tenant", "event_type", "severity", "event_timestamp"],
        order_by="event_timestamp desc",
        limit_page_length=int(limit),
    )

    # Aggregate counts per event_type
    type_counts: dict[str, int] = {}
    for ev in events:
        type_counts[ev["event_type"]] = type_counts.get(ev["event_type"], 0) + 1

    return {
        "events":        events,
        "count":         len(events),
        "type_counts":   type_counts,
    }


@frappe.whitelist()
def get_paywall_activity():
    """
    Return paywall impression, conversion, and dismissal statistics.

    Pulls from Redis banner counters across all active tenants.
    Admin only.
    """
    _require_admin()
    from orbweaver_frothiq.frothiq_portal.conversion_engine.upgrade_orchestrator import (
        get_active_banners,
    )

    tenants = frappe.get_all("FrothIQ Tenant", filters={"is_active": 1}, fields=["name"])

    total_active   = 0
    total_shown    = 0
    by_event_type: dict[str, int] = {}

    for row in tenants:
        try:
            banners = get_active_banners(row["name"])
            total_active += len(banners)
            for b in banners:
                etype = b.get("event_type", "unknown")
                by_event_type[etype] = by_event_type.get(etype, 0) + 1

            # Count impressions from Redis paywall counter
            count_key = f"ce:paywall_count:{row['name']}"
            count = int(frappe.cache().get(count_key) or 0)
            total_shown += count
        except Exception:
            pass

    return {
        "total_active_banners":  total_active,
        "total_impressions_24h": total_shown,
        "by_event_type":         by_event_type,
    }


@frappe.whitelist()
def get_plan_recommendation_panel(limit: int = 50):
    """
    Return per-tenant plan recommendation summary for the Admin dashboard.

    Shows current plan, recommended plan, and upgrade delta value estimate.
    Admin only.
    """
    _require_admin()
    from orbweaver_frothiq.frothiq_portal.conversion_engine.plan_optimizer import (
        recommend_optimal_plan,
    )

    tenants = frappe.get_all(
        "FrothIQ Tenant",
        filters={"is_active": 1},
        fields=["name", "plan"],
        limit_page_length=int(limit),
    )

    rows = []
    for row in tenants:
        try:
            rec = recommend_optimal_plan(row["name"])
            if not rec.get("error") and rec.get("recommended_plan"):
                rows.append({
                    "tenant_id":           row["name"],
                    "current_plan":        rec["current_plan"],
                    "recommended_plan":    rec["recommended_plan"],
                    "upgrade_delta_value": rec["upgrade_delta_value"],
                    "lost_value_monthly":  rec["lost_value_estimate"].get("monthly_usd", 0),
                    "inefficiency_count":  len(rec["inefficiencies"]),
                    "upgrade_path":        rec["upgrade_path"],
                })
        except Exception as exc:
            logger.debug("get_plan_recommendation_panel: error for %s: %s", row["name"], exc)

    rows.sort(key=lambda r: r["upgrade_delta_value"], reverse=True)
    return {"recommendations": rows, "count": len(rows)}


@frappe.whitelist()
def record_plan_upgrade(tenant_name: str):
    """
    Mark a tenant as converted in the upgrade funnel (Admin only).

    Called when billing confirms a successful plan upgrade.
    """
    _require_admin()
    from orbweaver_frothiq.frothiq_portal.conversion_engine.upgrade_orchestrator import (
        mark_tenant_converted,
    )
    converted = mark_tenant_converted(tenant_name)
    return {"tenant": tenant_name, "converted": converted}


# ---------------------------------------------------------------------------
# Tenant self-service endpoints
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_my_revenue_signal():
    """Return the revenue signal for the calling user's own tenant."""
    tenant = _get_my_tenant()
    from orbweaver_frothiq.frothiq_portal.conversion_engine.revenue_signal_engine import (
        compute_tenant_revenue_pressure,
    )
    return compute_tenant_revenue_pressure(tenant.name)


@frappe.whitelist()
def get_my_optimal_plan():
    """Return the optimal plan recommendation for the calling user's own tenant."""
    tenant = _get_my_tenant()
    from orbweaver_frothiq.frothiq_portal.conversion_engine.plan_optimizer import (
        recommend_optimal_plan,
    )
    return recommend_optimal_plan(tenant.name)


@frappe.whitelist()
def get_my_conversion_state():
    """Return the upgrade funnel state for the calling user's own tenant."""
    tenant = _get_my_tenant()
    from orbweaver_frothiq.frothiq_portal.conversion_engine.upgrade_orchestrator import (
        get_upgrade_state,
    )
    return {
        "tenant":  tenant.name,
        "plan":    tenant.plan or "free",
        "state":   get_upgrade_state(tenant.name),
    }
