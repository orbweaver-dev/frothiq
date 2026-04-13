# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ Billing API

Bridges FrothIQ Tenant records ↔ ERPNext Subscription/Customer/Item
and drives the tenant-config sync to frothiq-core.

Responsibilities:
  - Ensure ERPNext Items + Subscription Plans exist for each FrothIQ plan tier
  - Auto-create ERPNext Customer when a FrothIQ Tenant is created
  - Create / update ERPNext Subscription when a tenant activates or changes plan
  - Scheduled job: sync_tenants_to_core() — pushes plan limits + API keys every 5 min
  - plan_limits(plan) — canonical limits dict for a given plan
"""

import os

import frappe
import requests as _requests
from frappe.utils import today

# ---------------------------------------------------------------------------
# Plan configuration — single source of truth
# ---------------------------------------------------------------------------

PLAN_LIMITS: dict[str, dict] = {
    "free": {
        "rpm": 120,
        "max_sites": 1,
        "block_score": 100,
        "monthly_price": 0,
        "features": {
            "federation": False,
            "campaigns": False,
            "response_engine": False,
            "adaptive_scoring": True,
        },
    },
    "pro": {
        "rpm": 600,
        "max_sites": 10,
        "block_score": 80,
        "monthly_price": 49,
        "features": {
            "federation": True,
            "campaigns": True,
            "response_engine": False,
            "adaptive_scoring": True,
        },
    },
    "enterprise": {
        "rpm": 2000,
        "max_sites": 100,
        "block_score": 60,
        "monthly_price": 199,
        "features": {
            "federation": True,
            "campaigns": True,
            "response_engine": True,
            "adaptive_scoring": True,
        },
    },
}

# Maps plan key → ERPNext Item name
_PLAN_ITEMS: dict[str, str] = {
    "free":       "FrothIQ Free Plan",
    "pro":        "FrothIQ Pro Plan",
    "enterprise": "FrothIQ Enterprise Plan",
}

# Maps plan key → ERPNext Subscription Plan name
_SUBSCRIPTION_PLANS: dict[str, str] = {
    "free":       "FrothIQ Free Monthly",
    "pro":        "FrothIQ Pro Monthly",
    "enterprise": "FrothIQ Enterprise Monthly",
}

_FROTHIQ_CORE_URL = os.getenv("FROTHIQ_CORE_URL", "http://127.0.0.1:8001")
_TIMEOUT = 8


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def plan_limits(plan: str) -> dict:
    """Return the canonical limits dict for a plan tier."""
    return PLAN_LIMITS.get(plan or "free", PLAN_LIMITS["free"])


def ensure_erpnext_customer(tenant_doc) -> str | None:
    """
    Find or create an ERPNext Customer for this FrothIQ Tenant.

    Returns the Customer name, or None if ERPNext is unavailable.
    Safe to call from validate/after_insert.
    """
    if not _erpnext_available():
        return None

    if tenant_doc.erpnext_customer:
        return tenant_doc.erpnext_customer

    # Resolve owner email
    owner_email = frappe.db.get_value("User", tenant_doc.account_owner, "email") or tenant_doc.account_owner

    # Check for existing customer by email
    existing = frappe.db.get_value("Customer", {"email_id": owner_email}, "name")
    if existing:
        tenant_doc.db_set("erpnext_customer", existing, update_modified=False)
        return existing

    # Create new Customer
    customer = frappe.new_doc("Customer")
    customer.customer_name = tenant_doc.tenant_name
    customer.customer_type = "Individual"
    customer.customer_group = _default_customer_group()
    customer.territory = _default_territory()
    customer.email_id = owner_email
    customer.flags.ignore_permissions = True
    customer.insert(ignore_permissions=True)
    frappe.db.commit()

    tenant_doc.db_set("erpnext_customer", customer.name, update_modified=False)
    frappe.logger("frothiq_billing").info(
        "Created ERPNext Customer %s for tenant %s", customer.name, tenant_doc.name
    )
    return customer.name


def ensure_subscription(tenant_doc, new_plan: str | None = None) -> str | None:
    """
    Find or create/update an ERPNext Subscription for this tenant.

    Called on activation and on plan change. Returns the Subscription name.
    Safe to call repeatedly — idempotent.
    """
    if not _erpnext_available():
        return None

    if not tenant_doc.erpnext_customer:
        frappe.logger("frothiq_billing").warning(
            "Cannot create subscription — tenant %s has no ERPNext Customer yet", tenant_doc.name
        )
        return None

    plan = new_plan or tenant_doc.plan or "free"
    sub_plan_name = _SUBSCRIPTION_PLANS.get(plan)
    if not sub_plan_name:
        return None

    # Ensure the Subscription Plan exists
    _ensure_subscription_plan_exists(plan)

    # Look for existing active subscription
    existing_sub = tenant_doc.subscription
    if existing_sub and frappe.db.exists("Subscription", existing_sub):
        sub = frappe.get_doc("Subscription", existing_sub)
        # Update plan if changed
        if sub.plans and sub.plans[0].plan != sub_plan_name:
            sub.plans[0].plan = sub_plan_name
            sub.flags.ignore_permissions = True
            sub.save(ignore_permissions=True)
            frappe.db.commit()
            frappe.logger("frothiq_billing").info(
                "Updated subscription %s plan → %s for tenant %s",
                existing_sub, plan, tenant_doc.name,
            )
        return existing_sub

    # Create new subscription
    sub = frappe.new_doc("Subscription")
    sub.party_type = "Customer"
    sub.party = tenant_doc.erpnext_customer
    sub.start_date = today()
    sub.append("plans", {
        "plan": sub_plan_name,
        "qty": 1,
    })
    sub.flags.ignore_permissions = True
    sub.insert(ignore_permissions=True)
    frappe.db.commit()

    tenant_doc.db_set("subscription", sub.name, update_modified=False)
    frappe.logger("frothiq_billing").info(
        "Created subscription %s (plan=%s) for tenant %s", sub.name, plan, tenant_doc.name
    )
    return sub.name


@frappe.whitelist()
def setup_billing_items():
    """
    Ensure ERPNext Items and Subscription Plans exist for all plan tiers.

    Call manually once after installation, or run via bench console.
    Idempotent — safe to run multiple times.
    """
    if not _erpnext_available():
        frappe.msgprint("ERPNext not available — billing items skipped.")
        return

    for plan_key, item_name in _PLAN_ITEMS.items():
        limits = PLAN_LIMITS[plan_key]

        if not frappe.db.exists("Item", item_name):
            item = frappe.new_doc("Item")
            item.item_code = item_name
            item.item_name = item_name
            item.item_group = _default_item_group()
            item.is_stock_item = 0
            item.is_service_item = 1
            item.description = f"FrothIQ {plan_key.title()} Plan — monthly subscription"
            item.flags.ignore_permissions = True
            item.insert(ignore_permissions=True)
            frappe.logger("frothiq_billing").info("Created ERPNext Item: %s", item_name)

        _ensure_subscription_plan_exists(plan_key)

    frappe.db.commit()
    frappe.msgprint("FrothIQ billing items and subscription plans are ready.")


# ---------------------------------------------------------------------------
# Scheduled job — sync tenant configs to frothiq-core every 5 minutes
# ---------------------------------------------------------------------------

@frappe.whitelist()
def sync_tenants_to_core():
    """
    Scheduled task (every_5_minutes).

    Reads all active + trial FrothIQ Tenants, builds plan-limits payload,
    and POSTs to frothiq-core /api/v2/internal/sync-tenants.

    frothiq-core hot-reloads its in-memory registry without restart.
    """
    admin_key = _core_admin_key()
    if not admin_key:
        frappe.log_error(
            "frothiq_api_key not set in site_config — cannot sync tenants to core",
            "FrothIQ Billing Sync",
        )
        return

    tenants = frappe.get_all(
        "FrothIQ Tenant",
        filters={"status": ["in", ["active", "trial"]]},
        fields=["name", "plan", "status"],
    )

    payload_tenants = []
    for t in tenants:
        api_keys = frappe.db.get_list(
            "FrothIQ API Key",
            filters={"tenant": t.name, "revoked": 0},
            pluck="key",
        )
        if not api_keys:
            continue  # Don't sync tenants with no active keys — they can't authenticate

        limits = plan_limits(t.plan)
        payload_tenants.append({
            "tenant_id": t.name,
            "api_keys": api_keys,
            "plan": t.plan or "free",
            "status": t.status,
            "rate_limit_rpm": limits["rpm"],
            "max_sites": limits["max_sites"],
            "block_score": limits["block_score"],
            "features": limits["features"],
            "anomaly_thresholds": {},
        })

    if not payload_tenants:
        return

    try:
        resp = _requests.post(
            f"{_FROTHIQ_CORE_URL}/api/v2/internal/sync-tenants",
            headers={"X-FrothIQ-Key": admin_key, "Content-Type": "application/json"},
            json={"tenants": payload_tenants},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        result = resp.json()
        frappe.logger("frothiq_billing").info(
            "sync_tenants_to_core: pushed %d tenants, core confirmed %s synced",
            len(payload_tenants),
            result.get("synced", "?"),
        )
    except Exception as exc:
        frappe.log_error(
            f"sync_tenants_to_core failed: {exc}",
            "FrothIQ Billing Sync",
        )


# ---------------------------------------------------------------------------
# Scheduled job — sync security events from frothiq-core every minute
# ---------------------------------------------------------------------------

@frappe.whitelist()
def sync_events_from_core():
    """
    Scheduled task (every minute via cron).

    Pulls recent security events from /api/v2/internal/events, deduplicates
    using the 'since' cursor stored in Frappe cache, and inserts FrothIQ Event
    documents for each tenant.

    Global events (no tenant_id) are broadcast to all active tenants.
    Tenant-scoped events (tenant_id present) go only to that tenant.
    Suppression (dedup + per-IP hourly cap) is enforced in the DocType controller.
    """
    admin_key = _core_admin_key()
    if not admin_key:
        return

    # Read the last-sync cursor from cache (unix timestamp)
    since_key = "fq_events_since"
    since = frappe.cache().get(since_key)
    since = float(since) if since else 0.0

    try:
        resp = _requests.get(
            f"{_FROTHIQ_CORE_URL}/api/v2/internal/events",
            headers={"X-FrothIQ-Key": admin_key},
            params={"since": since, "limit": 500},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        frappe.log_error(f"sync_events_from_core fetch failed: {exc}", "FrothIQ Event Sync")
        return

    events = data.get("events") or []
    if not events:
        return

    # Build tenant list once (for broadcast events)
    active_tenants = frappe.get_all(
        "FrothIQ Tenant",
        filters={"status": ["in", ["active", "trial"]]},
        pluck="name",
    )

    inserted = 0
    newest_ts = since

    for ev in events:
        ev_ts = ev.get("timestamp") or 0.0
        if ev_ts > newest_ts:
            newest_ts = ev_ts

        # Determine target tenant(s)
        tenant_id = ev.get("tenant_id")
        if tenant_id:
            targets = [tenant_id] if frappe.db.exists("FrothIQ Tenant", tenant_id) else []
        else:
            targets = active_tenants

        for tid in targets:
            try:
                from frappe.utils import get_datetime
                ts_val = get_datetime(ev_ts) if ev_ts else frappe.utils.now_datetime()

                doc = frappe.new_doc("FrothIQ Event")
                doc.timestamp = ts_val
                doc.tenant = tid
                doc.site = ev.get("site") or None
                doc.event_type = ev.get("event_type", "attack")
                doc.severity = ev.get("severity", "low")
                doc.score = int(ev.get("score") or 0)
                doc.ip_address = ev.get("ip_address") or ""
                doc.campaign_id = ev.get("campaign_id") or ""
                doc.source = ev.get("source") or "core"
                doc.raw_payload = frappe.as_json(ev.get("metadata") or {})
                doc.flags.ignore_permissions = True
                doc.insert(ignore_permissions=True)
                inserted += 1
            except frappe.DuplicateEntryError:
                pass  # suppressed by dedup hash
            except frappe.ValidationError:
                pass  # suppressed by hourly cap
            except Exception as exc:
                frappe.logger("frothiq_billing").debug(
                    "sync_events: insert failed for tenant=%s: %s", tid, exc
                )

    frappe.db.commit()

    # Advance the cursor so next run fetches only new events
    if newest_ts > since:
        frappe.cache().set(since_key, str(newest_ts), expires_in_sec=86400)

    frappe.logger("frothiq_billing").info(
        "sync_events_from_core: fetched %d events, inserted %d FrothIQ Event docs",
        len(events), inserted,
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _erpnext_available() -> bool:
    """Return True if ERPNext is installed and the Subscription DocType exists."""
    try:
        return bool(frappe.db.exists("DocType", "Subscription") and
                    frappe.db.exists("DocType", "Customer"))
    except Exception:
        return False


def _core_admin_key() -> str:
    return frappe.conf.get("frothiq_api_key") or os.getenv("FROTHIQ_API_KEY", "")


def _default_customer_group() -> str:
    if frappe.db.exists("Customer Group", "FrothIQ"):
        return "FrothIQ"
    return frappe.db.get_value("Customer Group", {"is_group": 0}, "name") or "All Customer Groups"


def _default_territory() -> str:
    return frappe.db.get_value("Territory", {"is_group": 0}, "name") or "All Territories"


def _default_item_group() -> str:
    if frappe.db.exists("Item Group", "Services"):
        return "Services"
    return frappe.db.get_value("Item Group", {"is_group": 0}, "name") or "All Item Groups"


def _ensure_subscription_plan_exists(plan_key: str):
    """Create ERPNext Subscription Plan for the plan tier if it doesn't exist."""
    sub_plan_name = _SUBSCRIPTION_PLANS.get(plan_key)
    item_name = _PLAN_ITEMS.get(plan_key)
    if not sub_plan_name or not item_name:
        return
    if frappe.db.exists("Subscription Plan", sub_plan_name):
        return
    if not frappe.db.exists("Item", item_name):
        return  # Item must exist first

    limits = PLAN_LIMITS[plan_key]
    sp = frappe.new_doc("Subscription Plan")
    sp.plan_name = sub_plan_name
    sp.item = item_name
    sp.price_determination = "Fixed Rate"
    sp.cost = limits["monthly_price"]
    sp.billing_interval = "Month"
    sp.billing_interval_count = 1
    sp.currency = frappe.get_cached_value("Company",
        frappe.defaults.get_global_default("company"), "default_currency") or "USD"
    sp.flags.ignore_permissions = True
    sp.insert(ignore_permissions=True)
    frappe.logger("frothiq_billing").info("Created Subscription Plan: %s", sub_plan_name)
