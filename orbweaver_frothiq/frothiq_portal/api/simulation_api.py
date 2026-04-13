"""
FrothIQ Portal — Simulation API (Phase D4)

Whitelisted methods for the Simulation Center in the Frappe desk.
Enterprise-only: all endpoints gate on the simulation_engine feature flag.

Methods
-------
  get_simulation_status()          — engine status + last nightly summary
  get_simulation_scenarios()       — list available scenarios
  run_simulation(scenario_name)    — trigger a single scenario run
  get_simulation_runs(limit, type) — list recent runs
  get_simulation_metrics()         — rolling aggregate by scenario type
  get_simulation_alerts(limit)     — recent threshold-breach alerts
  get_nightly_summary()            — last nightly batch summary

Access pattern (mirrors conversion_api.py)
------------------------------------------
  Current Frappe user → FrothIQ Tenant → plan → feature flag check
"""

from __future__ import annotations

import json
import logging

import frappe
import requests

logger = logging.getLogger(__name__)

# Timeout for calls to frothiq-core
_TIMEOUT = 15

# Feature name required in tenant's features dict
_FEATURE = "simulation_engine"

# Required role for running simulations (writing action)
_WRITE_ROLES = {"FrothIQ Admin", "FrothIQ Analyst"}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _core_url() -> str:
    """Return frothiq-core base URL from site config."""
    return frappe.conf.get("frothiq_core_url", "http://127.0.0.1:8001")


def _current_tenant_api_key() -> str | None:
    """Return the active API key for the current user's tenant, or None."""
    try:
        tenant_name = frappe.db.get_value(
            "FrothIQ Tenant", {"owner": frappe.session.user}, "name"
        )
        if not tenant_name:
            return None
        key = frappe.db.get_value(
            "FrothIQ API Key",
            {"tenant": tenant_name, "is_active": 1},
            "api_key",
        )
        return key
    except Exception:
        return None


def _core_get(path: str) -> dict:
    """GET request to frothiq-core with tenant API key auth."""
    api_key = _current_tenant_api_key()
    headers = {"X-API-Key": api_key} if api_key else {}
    resp = requests.get(f"{_core_url()}{path}", headers=headers, timeout=_TIMEOUT)
    resp.raise_for_status()
    return resp.json()


def _core_post(path: str, payload: dict) -> dict:
    """POST request to frothiq-core with tenant API key auth."""
    api_key = _current_tenant_api_key()
    headers = {"X-API-Key": api_key, "Content-Type": "application/json"} if api_key else {}
    resp = requests.post(
        f"{_core_url()}{path}",
        headers=headers,
        data=json.dumps(payload),
        timeout=_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


def _require_enterprise() -> None:
    """
    Raise frappe.PermissionError if the current user's tenant does not have
    simulation_engine enabled.
    """
    try:
        tenant_name = frappe.db.get_value(
            "FrothIQ Tenant", {"owner": frappe.session.user}, "name"
        )
        if not tenant_name:
            frappe.throw("No FrothIQ Tenant found for this user.", frappe.PermissionError)

        plan = frappe.db.get_value("FrothIQ Tenant", tenant_name, "plan") or "free"
        if plan != "enterprise":
            frappe.throw(
                "Simulation Engine is available on the Enterprise plan only. "
                "Please upgrade to access attack simulation and accuracy validation.",
                frappe.PermissionError,
            )
    except frappe.PermissionError:
        raise
    except Exception as exc:
        frappe.throw(f"Could not verify simulation access: {exc}", frappe.PermissionError)


def _require_write_role() -> None:
    """Raise frappe.PermissionError if user cannot trigger simulation runs."""
    user_roles = set(frappe.get_roles(frappe.session.user))
    if not (user_roles & _WRITE_ROLES):
        frappe.throw(
            "Running simulations requires the FrothIQ Admin or FrothIQ Analyst role.",
            frappe.PermissionError,
        )


# ---------------------------------------------------------------------------
# Whitelisted API methods
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_simulation_status():
    """
    Return simulation engine status and last nightly summary.

    Accessible to all authenticated users (summary is aggregate data).
    Returns plan gating info so the UI can show the upgrade prompt.
    """
    try:
        tenant_name = frappe.db.get_value(
            "FrothIQ Tenant", {"owner": frappe.session.user}, "name"
        )
        plan = "free"
        if tenant_name:
            plan = frappe.db.get_value("FrothIQ Tenant", tenant_name, "plan") or "free"

        is_enterprise = plan == "enterprise"

        if is_enterprise:
            data = _core_get("/api/v2/simulation/status")
        else:
            data = {
                "simulation_engine_enabled": False,
                "plan": plan,
                "last_nightly_summary": None,
            }

        return {
            "ok": True,
            "plan": plan,
            "is_enterprise": is_enterprise,
            **data,
        }
    except Exception as exc:
        logger.warning("simulation_api.get_simulation_status: %s", exc)
        return {"ok": False, "error": str(exc)}


@frappe.whitelist()
def get_simulation_scenarios():
    """Return all available simulation scenarios. Enterprise only."""
    _require_enterprise()
    try:
        return _core_get("/api/v2/simulation/scenarios")
    except Exception as exc:
        logger.error("simulation_api.get_simulation_scenarios: %s", exc)
        frappe.throw(f"Failed to fetch scenarios: {exc}")


@frappe.whitelist()
def run_simulation(scenario_name: str, use_replay: bool = False, synthetic_count: int = 5):
    """
    Trigger a single simulation run.

    Parameters
    ----------
    scenario_name   : str  — key from SCENARIO_LIBRARY
    use_replay      : bool — if True, replay from live correlator
    synthetic_count : int  — number of synthetic campaigns (1–20)

    Returns SimulationResult dict on success.
    Enterprise + FrothIQ Admin/Analyst only.
    """
    _require_enterprise()
    _require_write_role()

    payload = {
        "scenario_name":   scenario_name,
        "use_replay":      bool(use_replay),
        "synthetic_count": max(1, min(int(synthetic_count), 20)),
        "persist":         True,
    }
    try:
        result = _core_post("/api/v2/simulation/run", payload)
        frappe.publish_realtime(
            event="frothiq_simulation_complete",
            message={
                "scenario": scenario_name,
                "das":       result.get("das"),
                "dei":       result.get("dei"),
                "pps":       result.get("pps"),
                "alerts":    result.get("alerts", []),
            },
            user=frappe.session.user,
        )
        return result
    except requests.HTTPError as exc:
        frappe.throw(f"Simulation failed: {exc.response.text if exc.response else exc}")
    except Exception as exc:
        logger.error("simulation_api.run_simulation: %s", exc)
        frappe.throw(f"Simulation failed: {exc}")


@frappe.whitelist()
def get_simulation_runs(limit: int = 20, scenario_type: str = None):
    """
    List recent simulation runs, newest first.

    Parameters
    ----------
    limit         : int  — max results (1–100)
    scenario_type : str  — optional scenario type filter
    """
    _require_enterprise()
    limit = max(1, min(int(limit), 100))
    path = f"/api/v2/simulation/runs?limit={limit}"
    if scenario_type:
        path += f"&scenario_type={scenario_type}"
    try:
        return _core_get(path)
    except Exception as exc:
        logger.error("simulation_api.get_simulation_runs: %s", exc)
        frappe.throw(f"Failed to fetch runs: {exc}")


@frappe.whitelist()
def get_simulation_run(simulation_id: str):
    """Return a single simulation run result by ID. Enterprise only."""
    _require_enterprise()
    try:
        return _core_get(f"/api/v2/simulation/runs/{simulation_id}")
    except requests.HTTPError as exc:
        if exc.response and exc.response.status_code == 404:
            frappe.throw(f"Simulation run '{simulation_id}' not found.", frappe.DoesNotExistError)
        frappe.throw(str(exc))
    except Exception as exc:
        frappe.throw(f"Failed to fetch run: {exc}")


@frappe.whitelist()
def get_simulation_metrics():
    """
    Return rolling aggregate metrics by scenario type (last 30 days).
    Enterprise only.
    """
    _require_enterprise()
    try:
        return _core_get("/api/v2/simulation/metrics")
    except Exception as exc:
        logger.error("simulation_api.get_simulation_metrics: %s", exc)
        frappe.throw(f"Failed to fetch metrics: {exc}")


@frappe.whitelist()
def get_simulation_alerts(limit: int = 20):
    """Return recent threshold-breach alerts. Enterprise only."""
    _require_enterprise()
    limit = max(1, min(int(limit), 100))
    try:
        return _core_get(f"/api/v2/simulation/alerts?limit={limit}")
    except Exception as exc:
        logger.error("simulation_api.get_simulation_alerts: %s", exc)
        frappe.throw(f"Failed to fetch alerts: {exc}")


@frappe.whitelist()
def get_nightly_summary():
    """Return the most recently completed nightly simulation summary. Enterprise only."""
    _require_enterprise()
    try:
        status = _core_get("/api/v2/simulation/status")
        return status.get("last_nightly_summary") or {}
    except Exception as exc:
        logger.error("simulation_api.get_nightly_summary: %s", exc)
        return {}


# ---------------------------------------------------------------------------
# Scheduled entry point (NOT whitelisted — called by Frappe scheduler)
# ---------------------------------------------------------------------------

def run_nightly_simulation_check():
    """
    Nightly scheduled job: trigger all scenarios via frothiq-core.

    Called from hooks.py scheduler_events daily list.
    Uses the internal frothiq-core API with no tenant key (internal call).
    """
    logger.info("frothiq_portal: starting nightly simulation check")
    try:
        resp = requests.post(
            f"{_core_url()}/api/v2/simulation/run",
            headers={"Content-Type": "application/json"},
            data=json.dumps({
                "scenario_name":   "brute_force_standard",
                "use_replay":      False,
                "synthetic_count": 5,
                "persist":         True,
            }),
            timeout=120,
        )
        logger.info(
            "frothiq_portal: nightly simulation complete, status=%d", resp.status_code
        )
    except Exception as exc:
        logger.error("frothiq_portal: nightly simulation check failed: %s", exc)
