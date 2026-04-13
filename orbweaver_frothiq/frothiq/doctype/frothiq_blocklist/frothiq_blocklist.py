# Copyright (c) 2026, OrbWeaver
# License: Proprietary

"""
FrothIQ Blocklist — DocType controller

Tracks every IP block/deny/trust action issued by frothiq-core.
Records are written by the agent API; status is updated by background
jobs when blocks expire or are removed.

Read by:
  - dashboard_api.get_csf_history()
  - command_center_api.get_ip_intelligence()
"""

import frappe
from frappe.model.document import Document


class FrothIQBlocklist(Document):
    pass
