# Copyright (c) 2026, OrbWeaver
# License: Proprietary

"""
FrothIQ Log — DocType controller

Records every security event processed by frothiq-core agents.
Inserted by the FrothIQ agent API; never created manually.

Read by:
  - dashboard_api.py   (Security Dashboard live feed)
  - command_center_api.py  (Command Center live feed + IP intel)
"""

import frappe
from frappe.model.document import Document


class FrothIQLog(Document):
    # All inserts come from the agent API; no validate logic needed here.
    pass
