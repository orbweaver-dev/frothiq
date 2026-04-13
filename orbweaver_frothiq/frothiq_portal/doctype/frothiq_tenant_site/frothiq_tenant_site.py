# Copyright (c) 2026, OrbWeaver — Proprietary

from datetime import datetime, timedelta, timezone

import frappe
from frappe.model.document import Document


class FrothIQTenantSite(Document):
    def validate(self):
        self._compute_status()
        self._validate_tenant_owns_key()

    def _compute_status(self):
        """Derive online/stale/offline from last_seen timestamp."""
        if not self.last_seen:
            self.status = "offline"
            return
        # last_seen may be a string; convert if needed
        if isinstance(self.last_seen, str):
            try:
                ls = datetime.fromisoformat(self.last_seen)
            except ValueError:
                self.status = "offline"
                return
        else:
            ls = self.last_seen

        # Ensure timezone-aware comparison
        now = datetime.now(timezone.utc)
        if ls.tzinfo is None:
            ls = ls.replace(tzinfo=timezone.utc)

        age = now - ls
        if age <= timedelta(minutes=5):
            self.status = "online"
        elif age <= timedelta(hours=1):
            self.status = "stale"
        else:
            self.status = "offline"

    def _validate_tenant_owns_key(self):
        """Ensure the linked API Key belongs to this site's tenant."""
        if not self.api_key or not self.tenant:
            return
        key_tenant = frappe.db.get_value("FrothIQ API Key", self.api_key, "tenant")
        if key_tenant and key_tenant != self.tenant:
            frappe.throw("The selected API Key does not belong to this site's tenant.")
