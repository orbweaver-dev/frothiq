# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ Flywheel — Frappe API Layer  (Phase 5 refactored)

Exposes tenant-scoped Flywheel state to the Frappe portal via HTTP calls
to frothiq-core. The previous version directly imported frothiq_core.flywheel
modules — that coupling is removed as part of the Phase 5 architectural
boundary enforcement.

BOUNDARY CONTRACT: Frappe is the customer SaaS portal only. It must not
import or execute business logic from frothiq_core. All flywheel data is
fetched via authenticated HTTP calls to frothiq-core.

Plan gating is enforced by frothiq-core (it returns plan-gated responses).
Frappe forwards the tenant API key and trusts core's response.
"""

from __future__ import annotations

import os

import frappe
import requests as _requests

_CORE_URL = os.getenv("FROTHIQ_CORE_URL", "http://127.0.0.1:8001")
_TIMEOUT = 10


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_tenant():
    user = frappe.session.user
    name = frappe.db.get_value("FrothIQ Tenant", {"account_owner": user}, "name")
    if not name:
        frappe.throw("No FrothIQ Tenant account found.", frappe.PermissionError)
    return frappe.get_doc("FrothIQ Tenant", name)


def _tenant_headers(tenant) -> dict:
    """Build auth headers for frothiq-core API calls scoped to this tenant."""
    key = frappe.db.get_value(
        "FrothIQ API Key",
        {"tenant": tenant.name, "is_active": 1},
        "api_key",
    ) or ""
    return {"X-FrothIQ-Key": key, "Content-Type": "application/json"}


def _core_get(path: str, tenant) -> dict:
    resp = _requests.get(
        f"{_CORE_URL}{path}",
        headers=_tenant_headers(tenant),
        timeout=_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Whitelisted endpoints — all data from frothiq-core via HTTP
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_flywheel_state():
    """Return global Flywheel state for the calling tenant from frothiq-core."""
    tenant = _get_tenant()
    try:
        return _core_get("/api/v2/flywheel/state", tenant)
    except Exception as exc:
        frappe.log_error(f"flywheel_api.get_flywheel_state: {exc}", "Flywheel API")
        return {
            "global_health_score": None,
            "system_momentum": {},
            "instability_index": None,
            "drift_alerts": [],
            "last_updated": None,
            "error": "Flywheel state unavailable",
        }


@frappe.whitelist()
def get_system_reinforcement_map():
    """Return correlation heatmap + reinforcement map for the calling tenant."""
    tenant = _get_tenant()
    try:
        return _core_get("/api/v2/flywheel/reinforcement-map", tenant)
    except Exception as exc:
        frappe.log_error(f"flywheel_api.get_system_reinforcement_map: {exc}", "Flywheel API")
        return {"error": "Reinforcement map unavailable"}


@frappe.whitelist()
def get_flywheel_events(limit: int = 100):
    """Return normalized Flywheel signal history for the calling tenant."""
    tenant = _get_tenant()
    try:
        return _core_get(f"/api/v2/flywheel/events?limit={min(int(limit), 1000)}", tenant)
    except Exception as exc:
        frappe.log_error(f"flywheel_api.get_flywheel_events: {exc}", "Flywheel API")
        return {"events": [], "error": "Events unavailable"}


@frappe.whitelist()
def get_optimization_suggestions():
    """Return optimization suggestions for the calling tenant from frothiq-core."""
    tenant = _get_tenant()
    try:
        return _core_get("/api/v2/flywheel/optimization-suggestions", tenant)
    except Exception as exc:
        frappe.log_error(f"flywheel_api.get_optimization_suggestions: {exc}", "Flywheel API")
        return {"suggestions": [], "error": "Suggestions unavailable"}
