# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ License Sync Hooks — ERPNext Subscription DocType Integration

Hooks into ERPNext Subscription document events to keep FrothIQ license
state in sync with billing reality in real time.

Hook registration (in hooks.py):
    doc_events = {
        "Subscription": {
            "on_update":  "orbweaver_frothiq.frothiq_portal.license_control.license_sync_hooks.on_subscription_update",
            "on_cancel":  "orbweaver_frothiq.frothiq_portal.license_control.license_sync_hooks.on_subscription_cancel",
            "on_submit":  "orbweaver_frothiq.frothiq_portal.license_control.license_sync_hooks.on_subscription_submit",
        }
    }

    # Custom payment-failed event (fired by ERPNext's payment reminder scheduler)
    scheduler_events = {
        "all": [
            "orbweaver_frothiq.frothiq_portal.license_control.license_sync_hooks.check_payment_failures"
        ]
    }

Safety contract
---------------
  All hooks are:
    - Idempotent:   safe to fire multiple times without side effects
    - Non-blocking: failures are logged, never raise to ERPNext
    - Deferred:     heavy work queued to background job (frappe.enqueue)
"""

from __future__ import annotations

import logging
import time

logger = logging.getLogger(__name__)

# Minimum seconds between sync calls for the same subscription (rate limit)
_SYNC_THROTTLE_SECONDS = 30
_last_sync: dict[str, float] = {}


def on_subscription_update(doc, method: str = "") -> None:
    """
    Called when an ERPNext Subscription document is saved/updated.

    Triggers a background license sync for the linked FrothIQ tenant.
    Throttled to once per 30s per subscription to avoid thundering herd.
    """
    try:
        sub_name = doc.name
        now      = time.time()
        if now - _last_sync.get(sub_name, 0) < _SYNC_THROTTLE_SECONDS:
            return
        _last_sync[sub_name] = now

        import frappe
        frappe.enqueue(
            "orbweaver_frothiq.frothiq_portal.license_control.license_sync_hooks._bg_sync_subscription",
            queue          = "short",
            subscription   = sub_name,
            is_async       = True,
            enqueue_after_commit = True,
        )
    except Exception as exc:
        logger.warning("license_sync_hooks.on_subscription_update: %s", exc)


def on_subscription_cancel(doc, method: str = "") -> None:
    """
    Called when an ERPNext Subscription is cancelled.

    Immediately revokes the linked tenant's license — no background queue
    because revocation must be instantaneous.
    """
    try:
        sub_name  = doc.name
        tenant_id = _find_tenant(sub_name)
        if not tenant_id:
            return

        from .billing_orchestrator import billing_orchestrator
        billing_orchestrator.on_subscription_cancelled(sub_name)
        logger.info("license_sync_hooks.on_cancel: revoked license for tenant=%s", tenant_id)
    except Exception as exc:
        logger.warning("license_sync_hooks.on_subscription_cancel: %s", exc)


def on_subscription_submit(doc, method: str = "") -> None:
    """
    Called when a new ERPNext Subscription is submitted (first activation).

    Issues a fresh license for the tenant, potentially upgrading from free.
    """
    try:
        import frappe
        frappe.enqueue(
            "orbweaver_frothiq.frothiq_portal.license_control.license_sync_hooks._bg_sync_subscription",
            queue        = "short",
            subscription = doc.name,
            is_async     = True,
            enqueue_after_commit = True,
        )
    except Exception as exc:
        logger.warning("license_sync_hooks.on_subscription_submit: %s", exc)


def check_payment_failures() -> None:
    """
    Scheduler hook (runs every 15 min) — find subscriptions with unpaid/past-due
    status and suspend the corresponding FrothIQ licenses.

    Idempotent: already-suspended licenses are not re-suspended.
    """
    try:
        import frappe
        unpaid_subs = frappe.db.get_all(
            "Subscription",
            filters={"status": ["in", ["Unpaid", "Past Due"]]},
            fields=["name"],
        )
        for row in unpaid_subs:
            try:
                tenant_id = _find_tenant(row.name)
                if not tenant_id:
                    continue
                # Check current license status — don't re-suspend what's already suspended
                import frappe
                current_status = frappe.db.get_value(
                    "FrothIQ License Record", {"tenant_id": tenant_id}, "status"
                )
                if current_status in ("suspended", "revoked"):
                    continue
                from .billing_orchestrator import billing_orchestrator
                billing_orchestrator.on_payment_failed(row.name)
            except Exception as exc:
                logger.warning("license_sync_hooks.check_payment_failures for %s: %s",
                               row.name, exc)
    except Exception as exc:
        logger.warning("license_sync_hooks.check_payment_failures: %s", exc)


# ---------------------------------------------------------------------------
# Background job helpers
# ---------------------------------------------------------------------------

def _bg_sync_subscription(subscription: str) -> None:
    """Background job: sync a single subscription to FrothIQ license state."""
    try:
        from .billing_orchestrator import billing_orchestrator
        billing_orchestrator.on_subscription_updated(subscription)
    except Exception as exc:
        logger.error("license_sync_hooks._bg_sync_subscription(%s): %s", subscription, exc)


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _find_tenant(subscription_name: str) -> str | None:
    try:
        import frappe
        return frappe.db.get_value(
            "FrothIQ Tenant", {"subscription": subscription_name}, "name"
        )
    except Exception:
        return None
