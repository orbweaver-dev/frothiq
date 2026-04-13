# Copyright (c) 2026, OrbWeaver
# License: Proprietary

"""
FrothIQ Command Center — backend API proxy

All methods are whitelisted and called via frappe.call() from the
command center page JS. They proxy to the frothiq-core FastAPI service
and/or query Frappe DocTypes directly.
"""

import os

import frappe
import requests as _requests
from frappe.utils import add_to_date, now_datetime

_FROTHIQ_CORE_URL = os.getenv("FROTHIQ_CORE_URL", "http://127.0.0.1:8001")
_TIMEOUT = 8  # seconds


def _key():
    return frappe.conf.get("frothiq_api_key") or os.getenv("FROTHIQ_API_KEY", "")


def _headers():
    return {"X-FrothIQ-Key": _key()}


def _since(hours: int):
    return add_to_date(now_datetime(), hours=-int(hours))


def _get(path, **kwargs):
    resp = _requests.get(
        f"{_FROTHIQ_CORE_URL}{path}",
        headers=_headers(),
        timeout=_TIMEOUT,
        **kwargs,
    )
    resp.raise_for_status()
    return resp.json()


def _post(path, json=None):
    resp = _requests.post(
        f"{_FROTHIQ_CORE_URL}{path}",
        headers=_headers(),
        json=json or {},
        timeout=_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


def _delete(path):
    resp = _requests.delete(
        f"{_FROTHIQ_CORE_URL}{path}",
        headers=_headers(),
        timeout=_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


def _is_admin():
    """True if the current user has FrothIQ Admin or System Manager role."""
    return frappe.has_role(frappe.session.user, ["FrothIQ Admin", "System Manager"])


# ---------------------------------------------------------------------------
# Section 1 — Overview stat cards
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_overview_stats(hours=24):
    """
    Combined stat payload for the overview panel:
      - Frappe DB stats (requests, blocks, unique IPs, top offender)
      - frothiq-core: active campaigns count, system status
    """
    hours = int(hours)
    since = _since(hours)

    total = frappe.db.count("FrothIQ Log", filters={"creation": [">=", since]})
    blocked = frappe.db.count("FrothIQ Log", filters={
        "creation": [">=", since], "blocked": 1
    })
    unique_ips = frappe.db.sql(
        "SELECT COUNT(DISTINCT ip_address) FROM `tabFrothIQ Log` WHERE creation >= %s",
        since,
    )[0][0] or 0

    top_row = frappe.db.sql(
        """SELECT ip_address, MAX(threat_score) AS top_score
           FROM `tabFrothIQ Log` WHERE creation >= %s
           GROUP BY ip_address ORDER BY top_score DESC LIMIT 1""",
        since, as_dict=True,
    )
    top_offender = top_row[0] if top_row else {"ip_address": "—", "top_score": 0}

    active_blocks = frappe.db.count("FrothIQ Blocklist", filters={"status": "active"})

    # frothiq-core: campaign summary
    campaign_count = 0
    core_status = "unknown"
    try:
        camp_data = _get("/campaigns/summary")
        campaign_count = camp_data.get("active_campaigns", 0)
    except Exception:
        pass

    try:
        health = _get("/health")
        core_status = health.get("status", "unknown")
    except Exception:
        core_status = "unreachable"

    return {
        "total_requests": total,
        "blocked_count": blocked,
        "unique_ips": unique_ips,
        "active_blocks": active_blocks,
        "active_campaigns": campaign_count,
        "top_offender": top_offender,
        "core_status": core_status,
        "hours": hours,
    }


# ---------------------------------------------------------------------------
# Section 2 — Live Threat Feed
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_live_feed(limit=80, after_name=None):
    """
    Return recent FrothIQ Log entries, newest first.
    If after_name is given, return only records newer than that document.
    """
    limit = min(int(limit), 200)
    filters = {}
    if after_name:
        anchor_ts = frappe.db.get_value("FrothIQ Log", after_name, "creation")
        if anchor_ts:
            filters["creation"] = [">", anchor_ts]

    rows = frappe.get_all(
        "FrothIQ Log",
        filters=filters,
        fields=[
            "name", "creation", "ip_address", "source",
            "threat_score", "blocked", "event_type", "severity",
            "request_method", "request_path", "reason",
        ],
        order_by="creation desc",
        limit=limit,
    )
    return rows


@frappe.whitelist()
def get_log_detail(log_name):
    """Return all fields of a single FrothIQ Log record for the modal."""
    doc = frappe.get_doc("FrothIQ Log", log_name)
    frappe.has_permission("FrothIQ Log", ptype="read", doc=doc, throw=True)
    return doc.as_dict()


# ---------------------------------------------------------------------------
# Section 3 — IP Intelligence
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_ip_intelligence(ip):
    """
    Full intelligence dossier for an IP:
      - frothiq-core: reputation, adaptive state, temporal context, campaign context,
        current response action
      - Frappe DB: recent log entries, blocklist entries
    """
    ip = (ip or "").strip()
    if not ip:
        frappe.throw("IP address required")

    result = {
        "ip": ip,
        "reputation": None,
        "adaptive": None,
        "temporal": None,
        "campaign": None,
        "response_action": None,
        "recent_logs": [],
        "blocklist": [],
    }

    # frothiq-core data
    try:
        result["reputation"] = _get(f"/reputation/{ip}")
    except Exception as e:
        result["reputation"] = {"error": str(e)}

    try:
        result["adaptive"] = _get(f"/adaptive/{ip}")
    except Exception as e:
        result["adaptive"] = {"error": str(e)}

    try:
        result["temporal"] = _get(f"/temporal/{ip}")
    except Exception as e:
        result["temporal"] = {"error": str(e)}

    try:
        # campaigns filtered to this IP
        all_camps = _get("/campaigns/active")
        result["campaign"] = [
            c for c in all_camps
            if ip in (c.get("participating_ips") or [])
        ]
    except Exception:
        result["campaign"] = []

    try:
        result["response_action"] = _get(f"/response/timeline?ip={ip}&limit=5")
    except Exception:
        result["response_action"] = []

    # Frappe DB data
    result["recent_logs"] = frappe.get_all(
        "FrothIQ Log",
        filters={"ip_address": ip},
        fields=["name", "creation", "threat_score", "blocked",
                "event_type", "request_method", "request_path", "reason"],
        order_by="creation desc",
        limit=20,
    )
    result["blocklist"] = frappe.get_all(
        "FrothIQ Blocklist",
        filters={"ip_address": ip},
        fields=["name", "creation", "list_type", "status",
                "pushed_to_csf", "reason", "expires_on"],
        order_by="creation desc",
        limit=10,
    )

    return result


@frappe.whitelist()
def block_ip(ip, reason="Manual block from FrothIQ Command Center", duration=3600):
    """Admin-only: manually add an IP to the blocklist via frothiq-core."""
    if not _is_admin():
        frappe.throw("FrothIQ Admin role required", frappe.PermissionError)
    ip = (ip or "").strip()
    try:
        return _post("/response/block", json={"ip": ip, "reason": reason, "duration": int(duration)})
    except Exception as e:
        frappe.throw(str(e))


@frappe.whitelist()
def unblock_ip(ip):
    """Admin-only: remove an active block for an IP."""
    if not _is_admin():
        frappe.throw("FrothIQ Admin role required", frappe.PermissionError)
    ip = (ip or "").strip()
    try:
        return _post(f"/response/unblock/{ip}")
    except Exception as e:
        frappe.throw(str(e))


@frappe.whitelist()
def trust_ip(ip):
    """Admin-only: add an IP to the trusted set (always OBSERVE)."""
    if not _is_admin():
        frappe.throw("FrothIQ Admin role required", frappe.PermissionError)
    ip = (ip or "").strip()
    try:
        return _post("/response/trust", json={"ip": ip})
    except Exception as e:
        frappe.throw(str(e))


@frappe.whitelist()
def untrust_ip(ip):
    """Admin-only: remove an IP from the trusted set."""
    if not _is_admin():
        frappe.throw("FrothIQ Admin role required", frappe.PermissionError)
    ip = (ip or "").strip()
    try:
        return _delete(f"/response/trust/{ip}")
    except Exception as e:
        frappe.throw(str(e))


# ---------------------------------------------------------------------------
# Section 4 — Campaigns panel
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_campaigns(status="active"):
    """Return all campaigns (active or archived)."""
    try:
        if status == "active":
            return _get("/campaigns/active")
        else:
            return _get("/campaigns")
    except Exception as e:
        return {"error": str(e), "campaigns": []}


@frappe.whitelist()
def get_campaign_detail(campaign_id):
    """Return full detail for a single campaign."""
    try:
        return _get(f"/campaigns/{campaign_id}")
    except Exception as e:
        frappe.throw(str(e))


@frappe.whitelist()
def get_campaigns_summary():
    """Return campaign summary counts."""
    try:
        return _get("/campaigns/summary")
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Section 5 — Response Engine panel
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_active_blocks():
    """Return currently active blocks from the response engine."""
    try:
        return _get("/response/active-blocks")
    except Exception as e:
        return {"error": str(e), "blocks": []}


@frappe.whitelist()
def get_response_summary():
    """Return response engine summary stats."""
    try:
        return _get("/response/summary")
    except Exception as e:
        return {"error": str(e)}


@frappe.whitelist()
def get_response_timeline(ip=None, limit=50):
    """Return the response action timeline, optionally filtered by IP."""
    params = {"limit": int(limit)}
    if ip:
        params["ip"] = ip
    try:
        return _get("/response/timeline", params=params)
    except Exception as e:
        return {"error": str(e), "timeline": []}


@frappe.whitelist()
def get_reversal_log(limit=20):
    """Return the block reversal log."""
    try:
        return _get("/response/reversals", params={"limit": int(limit)})
    except Exception as e:
        return {"error": str(e), "reversals": []}


# ---------------------------------------------------------------------------
# Section 6 — System Health
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_system_health():
    """
    Return combined system health:
      - frothiq-core /health
      - Frappe site info (site name, frappe version)
      - frothiq-core version
    """
    health = {}
    try:
        health = _get("/health")
    except Exception as e:
        health = {"status": "unreachable", "error": str(e)}

    health["site"] = frappe.local.site
    health["frappe_version"] = frappe.__version__

    return health


@frappe.whitelist()
def get_intelligence_stats():
    """Return intelligence engine statistics from frothiq-core."""
    try:
        return _get("/stats")
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Realtime publisher — called by background hook when blocks change
# ---------------------------------------------------------------------------

def notify_block_action(ip: str, strategy: str, reason: str):
    """Publish a realtime event when a block or unblock occurs."""
    try:
        frappe.publish_realtime(
            event="frothiq_block_action",
            message={
                "ip": ip,
                "strategy": strategy,
                "reason": reason,
            },
            after_commit=True,
        )
    except Exception:
        pass


def notify_campaign_update(campaign_id: str, campaign_type: str, confidence: int):
    """Publish a realtime event when a campaign is detected or updated."""
    try:
        frappe.publish_realtime(
            event="frothiq_campaign_update",
            message={
                "campaign_id": campaign_id,
                "campaign_type": campaign_type,
                "confidence_score": confidence,
            },
            after_commit=True,
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Section 7 — Agents Overview (Phase 7)
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_agents(status_filter=None):
    """
    Return all registered FrothIQ agents visible to this user.

    OrbWeaver Admin / System Manager → all agents (cross-tenant).
    FrothIQ Analyst → own tenant agents only.

    Phase 8 visibility rule enforced by frothiq-core (admin key vs. tenant key).
    """
    try:
        data = _get("/agents/agents")
        agents = data.get("agents", data) if isinstance(data, dict) else data
        if status_filter and status_filter != "all":
            agents = [a for a in agents if a.get("status") == status_filter]
        return {"agents": agents, "count": len(agents)}
    except Exception as e:
        return {"error": str(e), "agents": [], "count": 0}


@frappe.whitelist()
def get_agents_summary():
    """Return aggregate agent statistics (admin-only at core; returns what core allows)."""
    try:
        return _get("/agents/summary")
    except Exception as e:
        return {"error": str(e)}


@frappe.whitelist()
def get_agent_detail(agent_id):
    """
    Return detail for a single agent — its metrics, capabilities, and recent activity.
    The core /agents/agents list provides all fields; we filter client-side.
    """
    try:
        data = _get("/agents/agents")
        agents = data.get("agents", data) if isinstance(data, dict) else data
        for a in agents:
            if a.get("agent_id") == agent_id:
                return a
        frappe.throw(f"Agent {agent_id!r} not found")
    except Exception as e:
        frappe.throw(str(e))


def notify_agent_update(agent_id: str, agent_type: str, status: str):
    """Publish a realtime event when an agent comes online or goes offline."""
    try:
        frappe.publish_realtime(
            event="frothiq_agent_update",
            message={
                "agent_id":   agent_id,
                "agent_type": agent_type,
                "status":     status,
            },
            after_commit=True,
        )
    except Exception:
        pass
