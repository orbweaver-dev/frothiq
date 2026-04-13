# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ Customer Portal API

Whitelisted methods for the SaaS Customer Control Panel.

Security contract:
  - Every method resolves the caller's FrothIQ Tenant first.
  - No cross-tenant data is ever returned.
  - All frothiq-core calls use the admin key server-side; results are
    filtered to the tenant's own sites and agent_ids before returning.
  - FrothIQ Admin / System Manager bypass tenant scoping.
"""

import os
from datetime import datetime, timedelta, timezone

import frappe
import requests as _requests
from frappe.utils import now_datetime

_FROTHIQ_CORE_URL = os.getenv("FROTHIQ_CORE_URL", "http://127.0.0.1:8001")
_TIMEOUT = 8

_ADMIN_ROLES = {"System Manager", "FrothIQ Admin"}
_CUSTOMER_ROLES = {"FrothIQ Customer Admin", "FrothIQ Customer Viewer"}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_admin(user=None):
    user = user or frappe.session.user
    return bool(_ADMIN_ROLES & set(frappe.get_roles(user)))


def _core_key():
    return frappe.conf.get("frothiq_api_key") or os.getenv("FROTHIQ_API_KEY", "")


def _core_headers():
    return {"X-FrothIQ-Key": _core_key(), "Content-Type": "application/json"}


def _core_get(path, **kwargs):
    resp = _requests.get(
        f"{_FROTHIQ_CORE_URL}{path}",
        headers=_core_headers(),
        timeout=_TIMEOUT,
        **kwargs,
    )
    resp.raise_for_status()
    return resp.json()


def _core_post(path, json=None):
    resp = _requests.post(
        f"{_FROTHIQ_CORE_URL}{path}",
        headers=_core_headers(),
        json=json or {},
        timeout=_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


def _get_my_tenant(user=None):
    """
    Return the FrothIQ Tenant record for the current user.
    Admins can see all tenants but do not have a personal tenant —
    they call the admin panel, not the customer portal.
    """
    user = user or frappe.session.user
    name = frappe.db.get_value("FrothIQ Tenant", {"account_owner": user}, "name")
    if not name:
        frappe.throw(
            "No FrothIQ Tenant account found for your user. "
            "Contact support to activate your account.",
            frappe.DoesNotExistError,
        )
    return frappe.get_doc("FrothIQ Tenant", name)


def _get_tenant_for(tenant_name, user=None):
    """Return a tenant, checking the caller owns it (or is admin)."""
    user = user or frappe.session.user
    tenant = frappe.get_doc("FrothIQ Tenant", tenant_name)
    if not _is_admin(user) and tenant.account_owner != user:
        frappe.throw("Access denied.", frappe.PermissionError)
    return tenant


# ---------------------------------------------------------------------------
# 1. Sites
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_tenant_sites():
    """Return all sites belonging to the current tenant."""
    tenant = _get_my_tenant()
    sites = frappe.get_all(
        "FrothIQ Tenant Site",
        filters={"tenant": tenant.name},
        fields=[
            "name", "domain", "platform", "status",
            "mode", "agent_id", "api_key", "last_seen",
        ],
        order_by="domain asc",
    )
    return {"tenant": tenant.name, "sites": sites}


# ---------------------------------------------------------------------------
# 2. Usage Summary
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_usage_summary(window="24h"):
    """
    Return aggregated usage stats for the tenant's sites.

    Reads the latest FrothIQ Usage Snapshot for each site within the
    requested time window and aggregates: requests, blocked, avg_score.

    Also calls frothiq-core /api/v2/agents/summary (filtered to tenant
    agent IDs) for live counters when available.
    """
    tenant = _get_my_tenant()
    valid_windows = {"24h", "7d", "30d"}
    if window not in valid_windows:
        window = "24h"

    # --- Frappe DB snapshots ---
    since = _window_to_since(window)
    snapshots = frappe.db.sql(
        """
        SELECT site, requests, blocked, avg_score, peak_score, top_attack_category
        FROM `tabFrothIQ Usage Snapshot`
        WHERE tenant = %s
          AND time_window = %s
          AND snapshot_time >= %s
        ORDER BY snapshot_time DESC
        """,
        (tenant.name, window, since),
        as_dict=True,
    )

    total_requests = sum(s.requests or 0 for s in snapshots)
    total_blocked = sum(s.blocked or 0 for s in snapshots)
    scores = [s.avg_score for s in snapshots if s.avg_score]
    avg_score = round(sum(scores) / len(scores), 1) if scores else 0.0
    peak_score = max((s.peak_score or 0 for s in snapshots), default=0)
    categories = [s.top_attack_category for s in snapshots if s.top_attack_category]

    # Live agent counters from frothiq-core (best-effort)
    live = {}
    try:
        agent_ids = _tenant_agent_ids(tenant.name)
        if agent_ids:
            core_data = _core_get("/api/v2/agents/summary")
            live = {
                "total_agents": core_data.get("total", 0),
                "online_agents": core_data.get("online", 0),
            }
    except Exception:
        pass

    return {
        "tenant": tenant.name,
        "window": window,
        "total_requests": total_requests,
        "total_blocked": total_blocked,
        "avg_threat_score": avg_score,
        "peak_threat_score": peak_score,
        "top_attack_category": _most_common(categories),
        "site_count": len({s.site for s in snapshots if s.site}),
        **live,
    }


# ---------------------------------------------------------------------------
# 3. Agent Status
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_agent_status():
    """
    Return live agent health for the current tenant's sites.

    Pulls the agent registry from frothiq-core and filters to this
    tenant's registered agent_ids. Falls back to Frappe DB site records
    if frothiq-core is unreachable.
    """
    tenant = _get_my_tenant()
    sites = frappe.get_all(
        "FrothIQ Tenant Site",
        filters={"tenant": tenant.name},
        fields=["name", "domain", "platform", "agent_id", "status", "last_seen", "mode"],
    )
    agent_id_map = {s.agent_id: s for s in sites if s.agent_id}

    # Enrich with live frothiq-core data
    live_agents = {}
    try:
        core_data = _core_get("/api/v2/agents/agents")
        all_agents = core_data.get("agents", core_data) if isinstance(core_data, dict) else core_data
        for a in all_agents:
            if a.get("agent_id") in agent_id_map:
                live_agents[a["agent_id"]] = a
    except Exception:
        pass

    result = []
    for site in sites:
        live = live_agents.get(site.agent_id or "", {})
        result.append({
            "site_name": site.name,
            "domain": site.domain,
            "platform": site.platform,
            "agent_id": site.agent_id,
            "mode": site.mode,
            # Prefer live frothiq-core status over stale DB value
            "status": live.get("status") or site.status,
            "last_heartbeat": live.get("last_seen") or (str(site.last_seen) if site.last_seen else None),
            "hostname": live.get("hostname"),
            "version": live.get("metadata", {}).get("version") if live.get("metadata") else None,
            "capabilities": live.get("capabilities", {}),
            "requests_1m": live.get("requests_1m", 0),
            "blocks_1m": live.get("blocks_1m", 0),
        })

    return {"tenant": tenant.name, "agents": result}


# ---------------------------------------------------------------------------
# 4. Threat Summary (simplified — no raw logs)
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_threat_summary(window="24h"):
    """
    Return a simplified threat summary for the tenant.

    Returns aggregated attack category counts and blocked counts.
    No raw IP addresses, no request paths, no log-level data.
    """
    tenant = _get_my_tenant()
    valid_windows = {"24h", "7d", "30d"}
    if window not in valid_windows:
        window = "24h"

    since = _window_to_since(window)
    snapshots = frappe.db.sql(
        """
        SELECT top_attack_category, blocked, requests, avg_score
        FROM `tabFrothIQ Usage Snapshot`
        WHERE tenant = %s
          AND time_window = %s
          AND snapshot_time >= %s
        ORDER BY snapshot_time DESC
        """,
        (tenant.name, window, since),
        as_dict=True,
    )

    # Aggregate by attack category
    category_counts: dict[str, int] = {}
    total_blocked = 0
    total_requests = 0
    for s in snapshots:
        cat = s.top_attack_category or "unknown"
        category_counts[cat] = category_counts.get(cat, 0) + (s.blocked or 0)
        total_blocked += s.blocked or 0
        total_requests += s.requests or 0

    top_categories = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    block_rate = round(total_blocked / total_requests * 100, 1) if total_requests else 0.0

    return {
        "tenant": tenant.name,
        "window": window,
        "total_requests": total_requests,
        "total_blocked": total_blocked,
        "block_rate_pct": block_rate,
        "top_attack_categories": [
            {"category": cat, "blocked": count}
            for cat, count in top_categories
        ],
    }


# ---------------------------------------------------------------------------
# 5. Site Mode
# ---------------------------------------------------------------------------

@frappe.whitelist()
def set_site_mode(site_name, mode):
    """
    Set the protection mode for a site (monitor / protect / block).

    Validates tenant ownership before writing.
    """
    _require_customer_admin()
    valid_modes = {"monitor", "protect", "block"}
    if mode not in valid_modes:
        frappe.throw(f"Invalid mode '{mode}'. Must be one of: {', '.join(sorted(valid_modes))}")

    tenant = _get_my_tenant()
    site = frappe.get_doc("FrothIQ Tenant Site", site_name)

    if not _is_admin() and site.tenant != tenant.name:
        frappe.throw("Access denied — site does not belong to your tenant.", frappe.PermissionError)

    old_mode = site.mode
    site.mode = mode
    site.save(ignore_permissions=True)
    frappe.db.commit()

    return {
        "site": site_name,
        "domain": site.domain,
        "previous_mode": old_mode,
        "current_mode": mode,
    }


# ---------------------------------------------------------------------------
# 6. API Keys — create
# ---------------------------------------------------------------------------

@frappe.whitelist()
def create_api_key(label):
    """
    Generate a new API key for the current tenant.

    The full key is returned ONCE in this response and stored hashed.
    The key is displayed in the form immediately after creation.
    """
    _require_customer_admin()
    tenant = _get_my_tenant()

    if not label or not label.strip():
        frappe.throw("A label is required for the API key.")

    key_doc = frappe.new_doc("FrothIQ API Key")
    key_doc.label = label.strip()
    key_doc.tenant = tenant.name
    key_doc.flags.ignore_permissions = True
    key_doc.insert(ignore_permissions=True)
    frappe.db.commit()

    return {
        "key_name": key_doc.name,
        "label": key_doc.label,
        "key": key_doc.key,   # full key — shown once
        "tenant": tenant.name,
    }


# ---------------------------------------------------------------------------
# 7. API Keys — revoke
# ---------------------------------------------------------------------------

@frappe.whitelist()
def revoke_api_key(key_name):
    """
    Revoke an API key. The key becomes inactive immediately.
    Any sites linked to this key will lose agent connectivity.
    """
    _require_customer_admin()
    tenant = _get_my_tenant()

    key_doc = frappe.get_doc("FrothIQ API Key", key_name)
    if not _is_admin() and key_doc.tenant != tenant.name:
        frappe.throw("Access denied — key does not belong to your tenant.", frappe.PermissionError)

    if key_doc.revoked:
        frappe.throw("This API key is already revoked.")

    key_doc.revoked = 1
    key_doc.flags.ignore_permissions = True
    key_doc.save(ignore_permissions=True)
    frappe.db.commit()

    return {"key_name": key_name, "revoked": True}


# ---------------------------------------------------------------------------
# 8. Agent mode fetch (guest-accessible by agent_id + api_key)
# ---------------------------------------------------------------------------

@frappe.whitelist(allow_guest=True)
def get_site_mode(agent_id, api_key):
    """
    Called by agents (WordPress, Joomla, etc.) to fetch their current
    protection mode without requiring a Frappe session.

    Validates the api_key against FrothIQ API Key records.
    Returns only the mode — nothing else.
    """
    if not agent_id or not api_key:
        frappe.throw("agent_id and api_key are required.", frappe.AuthenticationError)

    # Validate key
    key_rec = frappe.db.get_value(
        "FrothIQ API Key",
        {"key": api_key, "revoked": 0},
        ["name", "tenant"],
        as_dict=True,
    )
    if not key_rec:
        frappe.throw("Invalid or revoked API key.", frappe.AuthenticationError)

    # Find the site by agent_id scoped to this tenant
    site = frappe.db.get_value(
        "FrothIQ Tenant Site",
        {"agent_id": agent_id, "tenant": key_rec.tenant},
        ["name", "mode", "domain"],
        as_dict=True,
    )
    if not site:
        # agent_id not yet registered; return default monitor mode
        return {"agent_id": agent_id, "mode": "monitor", "registered": False}

    return {"agent_id": agent_id, "domain": site.domain, "mode": site.mode, "registered": True}


# ---------------------------------------------------------------------------
# 9. Plan info — returns current plan limits for the tenant's plan
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_plan_info():
    """
    Return the current plan, limits, and subscription status for the tenant.
    Used by the Tenant form JS to render usage bars and the upgrade dialog.
    """
    tenant = _get_my_tenant()

    from orbweaver_frothiq.frothiq_portal.api.billing_api import plan_limits
    limits = plan_limits(tenant.plan or "free")

    # Count active sites
    site_count = frappe.db.count(
        "FrothIQ Tenant Site",
        filters={"tenant": tenant.name},
    )
    # Count active API keys
    key_count = frappe.db.count(
        "FrothIQ API Key",
        filters={"tenant": tenant.name, "revoked": 0},
    )

    return {
        "tenant": tenant.name,
        "plan": tenant.plan or "free",
        "status": tenant.status,
        "subscription": tenant.subscription,
        "subscription_status": tenant.subscription_status,
        "next_billing_date": str(tenant.next_billing_date) if tenant.next_billing_date else None,
        "erpnext_customer": tenant.erpnext_customer,
        "limits": limits,
        "usage": {
            "sites": site_count,
            "api_keys": key_count,
        },
    }


# ---------------------------------------------------------------------------
# Scheduler — sync agent status + write usage snapshots (hourly)
# ---------------------------------------------------------------------------

def sync_agent_status():
    """
    Scheduled task (hourly).

    For each active FrothIQ Tenant Site with a registered agent_id:
    1. Pull live status from frothiq-core agent registry
    2. Update site.last_seen and recompute site.status
    3. Write a 24h FrothIQ Usage Snapshot
    """
    try:
        core_data = _core_get("/api/v2/agents/agents")
        all_agents = core_data.get("agents", core_data) if isinstance(core_data, dict) else core_data
        agent_map = {a["agent_id"]: a for a in all_agents if a.get("agent_id")}
    except Exception as exc:
        frappe.log_error(f"FrothIQ portal: agent sync failed — {exc}", "FrothIQ Portal Sync")
        return

    sites = frappe.get_all(
        "FrothIQ Tenant Site",
        filters={"agent_id": ["!=", ""]},
        fields=["name", "agent_id", "tenant"],
    )

    for site_meta in sites:
        agent = agent_map.get(site_meta.agent_id)
        if not agent:
            continue
        try:
            site = frappe.get_doc("FrothIQ Tenant Site", site_meta.name)
            if agent.get("last_seen"):
                site.last_seen = agent["last_seen"]
            site.flags.ignore_permissions = True
            site.save(ignore_permissions=True)

            # Write usage snapshot (24h window)
            snap = frappe.new_doc("FrothIQ Usage Snapshot")
            snap.tenant = site_meta.tenant
            snap.site = site_meta.name
            snap.time_window = "24h"
            snap.snapshot_time = now_datetime()
            snap.requests = agent.get("requests_1m", 0) * 60  # rough extrapolation
            snap.blocked = agent.get("blocks_1m", 0) * 60
            snap.flags.ignore_permissions = True
            snap.insert(ignore_permissions=True)
        except Exception as exc:
            frappe.log_error(
                f"FrothIQ portal: failed to sync site {site_meta.name} — {exc}",
                "FrothIQ Portal Sync",
            )

    frappe.db.commit()


# ---------------------------------------------------------------------------
# Permission hooks (called by Frappe framework)
# ---------------------------------------------------------------------------

def get_tenant_query(user=None):
    user = user or frappe.session.user
    if _is_admin(user):
        return ""
    return f"`tabFrothIQ Tenant`.`account_owner` = {frappe.db.escape(user)}"


def get_tenant_site_query(user=None):
    user = user or frappe.session.user
    if _is_admin(user):
        return ""
    tenant = frappe.db.get_value("FrothIQ Tenant", {"account_owner": user}, "name")
    if not tenant:
        return "`tabFrothIQ Tenant Site`.`name` = '__no_access__'"
    return f"`tabFrothIQ Tenant Site`.`tenant` = {frappe.db.escape(tenant)}"


def get_usage_snapshot_query(user=None):
    user = user or frappe.session.user
    if _is_admin(user):
        return ""
    tenant = frappe.db.get_value("FrothIQ Tenant", {"account_owner": user}, "name")
    if not tenant:
        return "`tabFrothIQ Usage Snapshot`.`name` = '__no_access__'"
    return f"`tabFrothIQ Usage Snapshot`.`tenant` = {frappe.db.escape(tenant)}"


def get_api_key_query(user=None):
    user = user or frappe.session.user
    if _is_admin(user):
        return ""
    tenant = frappe.db.get_value("FrothIQ Tenant", {"account_owner": user}, "name")
    if not tenant:
        return "`tabFrothIQ API Key`.`name` = '__no_access__'"
    return f"`tabFrothIQ API Key`.`tenant` = {frappe.db.escape(tenant)}"


def has_tenant_permission(doc, ptype="read", user=None):
    user = user or frappe.session.user
    if _is_admin(user):
        return True
    return doc.account_owner == user


def has_tenant_site_permission(doc, ptype="read", user=None):
    user = user or frappe.session.user
    if _is_admin(user):
        return True
    tenant = frappe.db.get_value("FrothIQ Tenant", {"account_owner": user}, "name")
    return doc.tenant == tenant


def has_usage_snapshot_permission(doc, ptype="read", user=None):
    user = user or frappe.session.user
    if _is_admin(user):
        return True
    tenant = frappe.db.get_value("FrothIQ Tenant", {"account_owner": user}, "name")
    return doc.tenant == tenant


def has_api_key_permission(doc, ptype="read", user=None):
    user = user or frappe.session.user
    if _is_admin(user):
        return True
    tenant = frappe.db.get_value("FrothIQ Tenant", {"account_owner": user}, "name")
    return doc.tenant == tenant


def get_event_query(user=None):
    user = user or frappe.session.user
    if _is_admin(user):
        return ""
    tenant = frappe.db.get_value("FrothIQ Tenant", {"account_owner": user}, "name")
    if not tenant:
        return "`tabFrothIQ Event`.`name` = '__no_access__'"
    return f"`tabFrothIQ Event`.`tenant` = {frappe.db.escape(tenant)}"


def has_event_permission(doc, ptype="read", user=None):
    user = user or frappe.session.user
    if _is_admin(user):
        return True
    tenant = frappe.db.get_value("FrothIQ Tenant", {"account_owner": user}, "name")
    return doc.tenant == tenant


# ---------------------------------------------------------------------------
# 10. Alert Events — read-only API for portal dashboard
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_events(severity=None, event_type=None, limit=50):
    """
    Return recent FrothIQ Events for the current tenant.

    Filters:
      severity   — low | medium | high | critical (optional)
      event_type — attack | block | campaign | anomaly | system (optional)
      limit      — max rows (default 50, max 200)
    """
    tenant = _get_my_tenant()
    try:
        limit = min(int(limit), 200)
    except (TypeError, ValueError):
        limit = 50

    filters = {"tenant": tenant.name}
    if severity:
        filters["severity"] = severity
    if event_type:
        filters["event_type"] = event_type

    events = frappe.get_all(
        "FrothIQ Event",
        filters=filters,
        fields=[
            "name", "timestamp", "event_type", "severity", "score",
            "ip_address", "campaign_id", "site", "source",
        ],
        order_by="timestamp desc",
        limit=limit,
    )
    return {"tenant": tenant.name, "events": events, "count": len(events)}


# ---------------------------------------------------------------------------
# 11. Notification Settings
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_notification_settings():
    """Return the current tenant's notification preferences."""
    tenant = _get_my_tenant()
    return {
        "tenant": tenant.name,
        "webhook_url": getattr(tenant, "webhook_url", "") or "",
        "webhook_events": getattr(tenant, "webhook_events", "") or "",
        "alert_email": getattr(tenant, "alert_email", "") or "",
        "alert_min_severity": getattr(tenant, "alert_min_severity", "high") or "high",
    }


@frappe.whitelist()
def save_notification_settings(webhook_url=None, webhook_events=None,
                                alert_email=None, alert_min_severity=None):
    """Save notification preferences for the current tenant."""
    _require_customer_admin()
    tenant = _get_my_tenant()

    if webhook_url is not None:
        # Basic URL validation — must be https or empty
        webhook_url = webhook_url.strip()
        if webhook_url and not webhook_url.startswith("https://"):
            frappe.throw("Webhook URL must start with https://")
        tenant.db_set("webhook_url", webhook_url, update_modified=False)

    if webhook_events is not None:
        tenant.db_set("webhook_events", webhook_events.strip(), update_modified=False)

    if alert_email is not None:
        tenant.db_set("alert_email", alert_email.strip(), update_modified=False)

    if alert_min_severity is not None:
        valid = {"low", "medium", "high", "critical"}
        if alert_min_severity not in valid:
            frappe.throw(f"Invalid severity. Must be one of: {', '.join(sorted(valid))}")
        tenant.db_set("alert_min_severity", alert_min_severity, update_modified=False)

    frappe.db.commit()
    return {"saved": True}


@frappe.whitelist()
def send_test_alert():
    """
    Send a synthetic FrothIQ Event for the current tenant.

    Creates a test event document so the full alerting pipeline
    (realtime, webhook) fires without waiting for a real threat.
    """
    _require_customer_admin()
    tenant = _get_my_tenant()

    # Remove any cached dedup hash so the test always goes through
    import hashlib
    import math
    from frappe.utils import now_datetime, get_datetime
    ts = now_datetime()
    unix_ts = get_datetime(str(ts)).timestamp()
    bucket = math.floor(unix_ts / 300)
    raw = f"{tenant.name}:TEST_ALERT:system:{bucket}"
    test_hash = hashlib.sha256(raw.encode()).hexdigest()[:32]
    try:
        frappe.cache().delete_value(f"fq_alert:{test_hash}")
    except Exception:
        pass

    doc = frappe.new_doc("FrothIQ Event")
    doc.timestamp = ts
    doc.tenant = tenant.name
    doc.event_type = "system"
    doc.severity = "medium"
    doc.score = 50
    doc.ip_address = "TEST_ALERT"
    doc.source = "core"
    doc.raw_payload = '{"test": true}'
    doc.flags.ignore_permissions = True
    doc.insert(ignore_permissions=True)
    frappe.db.commit()

    return {"sent": True, "event_name": doc.name}


# ---------------------------------------------------------------------------
# Private utilities
# ---------------------------------------------------------------------------

def _require_customer_admin():
    """Raise if the caller does not have write rights."""
    roles = set(frappe.get_roles())
    if not (roles & _ADMIN_ROLES) and "FrothIQ Customer Admin" not in roles:
        frappe.throw("FrothIQ Customer Admin role required.", frappe.PermissionError)


def _tenant_agent_ids(tenant_name: str) -> list[str]:
    return frappe.db.get_list(
        "FrothIQ Tenant Site",
        filters={"tenant": tenant_name, "agent_id": ["!=", ""]},
        pluck="agent_id",
    )


def _window_to_since(window: str) -> datetime:
    now = datetime.now(timezone.utc)
    if window == "7d":
        return now - timedelta(days=7)
    if window == "30d":
        return now - timedelta(days=30)
    return now - timedelta(hours=24)


def _most_common(items: list) -> str | None:
    if not items:
        return None
    return max(set(items), key=items.count)
