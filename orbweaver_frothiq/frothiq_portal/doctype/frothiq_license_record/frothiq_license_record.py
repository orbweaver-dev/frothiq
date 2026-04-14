# Copyright (c) 2026, OrbWeaver — Proprietary
import frappe
from frappe.model.document import Document


class FrothIQLicenseRecord(Document):
    def before_save(self):
        if not self.issued_at:
            import time
            self.issued_at = time.time()

    def on_update(self):
        """Keep the FrothIQ Tenant subscription_status in sync."""
        try:
            if self.tenant_id:
                frappe.db.set_value(
                    "FrothIQ Tenant", self.tenant_id,
                    "subscription_status", self.status,
                    update_modified=False,
                )
        except Exception:
            pass
