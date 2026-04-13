# Copyright (c) 2026, OrbWeaver — Proprietary

import secrets

import frappe
from frappe.model.document import Document

_KEY_PREFIX = "fiq_"
_KEY_BYTES = 32   # 256-bit entropy → 43-char URL-safe base64


class FrothIQAPIKey(Document):
    def before_insert(self):
        if not self.key:
            self.key = _KEY_PREFIX + secrets.token_urlsafe(_KEY_BYTES)

    def validate(self):
        # Prevent editing the key value after creation
        if not self.is_new() and self.has_value_changed("key"):
            frappe.throw("API keys cannot be edited after creation. Revoke and create a new key.")

        # Ensure key belongs to a valid tenant
        if self.tenant:
            tenant_status = frappe.db.get_value("FrothIQ Tenant", self.tenant, "status")
            if tenant_status == "suspended":
                frappe.throw("Cannot create an API key for a suspended tenant.")
