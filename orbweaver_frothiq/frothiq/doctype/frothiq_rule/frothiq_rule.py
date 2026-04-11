import re

import frappe
from frappe.model.document import Document


class FrothIQRule(Document):
	def validate(self):
		if self.rule_type == "regex" and self.pattern:
			try:
				re.compile(self.pattern)
			except re.error as e:
				frappe.throw(f"Invalid regex pattern: {e}")
