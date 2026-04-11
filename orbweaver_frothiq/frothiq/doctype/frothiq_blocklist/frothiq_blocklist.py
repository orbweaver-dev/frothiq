import frappe
from frappe.model.document import Document
from frappe.utils import nowdate


class FrothIQBlocklist(Document):
	def validate(self):
		import ipaddress
		try:
			ipaddress.ip_network(self.ip_address, strict=False)
		except ValueError:
			frappe.throw(f"Invalid IP address or CIDR: {self.ip_address}")

		if self.expires_on and self.expires_on < nowdate():
			self.status = "expired"

	def on_update(self):
		if self.status == "active" and not self.pushed_to_csf:
			self._push_to_agent()

	def _push_to_agent(self):
		agent_url = frappe.db.get_single_value("FrothIQ Settings", "agent_url") if frappe.db.exists("DocType", "FrothIQ Settings") else None
		if not agent_url:
			return

		import requests
		agent_key = frappe.db.get_single_value("FrothIQ Settings", "agent_key") or ""
		endpoint = f"{agent_url.rstrip('/')}/{'block' if self.list_type == 'deny' else 'allow'}"
		try:
			resp = requests.post(
				endpoint,
				json={"ip": self.ip_address, "comment": self.reason or f"FrothIQ {self.name}", "reload": True},
				headers={"X-FrothIQ-Agent-Key": agent_key},
				timeout=5,
			)
			if resp.ok:
				frappe.db.set_value("FrothIQ Blocklist", self.name, "pushed_to_csf", 1)
		except Exception as e:
			frappe.log_error(f"FrothIQ agent push failed: {e}", "FrothIQ Blocklist")
