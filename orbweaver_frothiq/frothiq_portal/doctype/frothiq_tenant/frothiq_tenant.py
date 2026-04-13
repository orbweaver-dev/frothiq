# Copyright (c) 2026, OrbWeaver — Proprietary

import frappe
from frappe.model.document import Document


class FrothIQTenant(Document):

    # -------------------------------------------------------------------------
    # Frappe lifecycle hooks
    # -------------------------------------------------------------------------

    def before_insert(self):
        # Default account_owner to the session user if not set
        if not self.account_owner:
            self.account_owner = frappe.session.user

    def validate(self):
        # Enforce unique owner — one tenant per user (admins may bypass)
        if not frappe.flags.in_migrate and not frappe.flags.in_install:
            existing = frappe.db.get_value(
                "FrothIQ Tenant",
                {"account_owner": self.account_owner, "name": ["!=", self.name or ""]},
                "name",
            )
            if existing and not _is_frothiq_admin():
                frappe.throw(
                    f"User {self.account_owner} already has a FrothIQ Tenant ({existing}).",
                    frappe.DuplicateEntryError,
                )

    def after_insert(self):
        """Create ERPNext Customer on first save. Runs after row is committed."""
        if frappe.flags.in_migrate or frappe.flags.in_install:
            return
        _sync_erpnext(self, is_new=True)

    def on_update(self):
        """
        Sync ERPNext state when plan or status changes.
        Called after every save (including after_insert follow-up saves).
        """
        if frappe.flags.in_migrate or frappe.flags.in_install:
            return

        doc_before = self.get_doc_before_save()
        if not doc_before:
            return  # First-time save — after_insert already handled it

        plan_changed = doc_before.plan != self.plan
        became_active = doc_before.status != "active" and self.status == "active"

        if plan_changed or became_active:
            _sync_erpnext(self, is_new=False)

    def on_trash(self):
        """Cancel subscription when tenant is deleted."""
        if self.subscription and not frappe.flags.in_migrate:
            try:
                sub = frappe.get_doc("Subscription", self.subscription)
                if sub.status not in ("Cancelled",):
                    sub.cancel()
                    frappe.db.commit()
            except Exception as exc:
                frappe.log_error(
                    f"Could not cancel subscription {self.subscription} for tenant "
                    f"{self.name}: {exc}",
                    "FrothIQ Tenant",
                )


# ---------------------------------------------------------------------------
# Permission helpers (called from hooks.py permission_query_conditions)
# ---------------------------------------------------------------------------

def _is_frothiq_admin():
    return any(r in frappe.get_roles() for r in ("System Manager", "FrothIQ Admin"))


# ---------------------------------------------------------------------------
# ERPNext integration — called from lifecycle hooks
# ---------------------------------------------------------------------------

def _sync_erpnext(doc, is_new: bool):
    """
    Ensure Customer exists, then ensure Subscription is current.
    Silently skips if ERPNext isn't installed.
    """
    from orbweaver_frothiq.frothiq_portal.api.billing_api import (
        ensure_erpnext_customer,
        ensure_subscription,
    )

    try:
        customer_name = ensure_erpnext_customer(doc)
        if customer_name and doc.status == "active":
            ensure_subscription(doc)
        _refresh_subscription_status(doc)
    except Exception as exc:
        frappe.log_error(
            f"ERPNext sync failed for tenant {doc.name}: {exc}",
            "FrothIQ Tenant",
        )


def _refresh_subscription_status(doc):
    """Pull current subscription_status and next_billing_date from ERPNext."""
    if not doc.subscription:
        return
    try:
        sub = frappe.db.get_value(
            "Subscription",
            doc.subscription,
            ["status", "current_invoice_end"],
            as_dict=True,
        )
        if sub:
            doc.db_set("subscription_status", sub.status or "", update_modified=False)
            doc.db_set("next_billing_date", sub.current_invoice_end or None, update_modified=False)
    except Exception:
        pass  # ERPNext fields may vary by version — non-fatal
