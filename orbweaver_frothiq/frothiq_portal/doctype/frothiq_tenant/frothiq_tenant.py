# Copyright (c) 2026, OrbWeaver — Proprietary

import frappe
from frappe.model.document import Document


class FrothIQTenant(Document):
    def before_insert(self):
        # Default account_owner to the session user if not set
        if not self.account_owner:
            self.account_owner = frappe.session.user

    def validate(self):
        # Enforce unique owner — one tenant per user (unless admin bypasses)
        if not frappe.flags.in_migrate:
            existing = frappe.db.get_value(
                "FrothIQ Tenant",
                {"account_owner": self.account_owner, "name": ["!=", self.name or ""]},
                "name",
            )
            if existing and not frappe.has_permission("FrothIQ Tenant", ptype="write", user=frappe.session.user):
                # Allow admins to create multiple tenants for the same owner
                if not _is_frothiq_admin():
                    frappe.throw(
                        f"User {self.account_owner} already has a FrothIQ Tenant ({existing}).",
                        frappe.DuplicateEntryError,
                    )


def _is_frothiq_admin():
    return any(r in frappe.get_roles() for r in ("System Manager", "FrothIQ Admin"))
