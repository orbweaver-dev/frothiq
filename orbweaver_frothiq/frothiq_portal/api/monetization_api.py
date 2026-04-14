# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ Portal — Growth & Monetization API  (Phase 6)

Admin aggregate endpoints (revenue heatmap, upgrade funnel, value event stream,
paywall activity, plan recommendation panel, record_plan_upgrade) have been
migrated to the FrothIQ Control Center standalone service.

Only tenant self-service endpoints remain here.
"""

from __future__ import annotations

import logging

import frappe

logger = logging.getLogger("frothiq_conversion")


def _get_my_tenant():
    user = frappe.session.user
    name = frappe.db.get_value("FrothIQ Tenant", {"account_owner": user}, "name")
    if not name:
        frappe.throw("No FrothIQ Tenant found for your user.", frappe.DoesNotExistError)
    return frappe.get_doc("FrothIQ Tenant", name)


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
