import frappe
from frappe.model.document import Document


class FrothIQLog(Document):
	pass


@frappe.whitelist()
def create_log(ip_address, source="unknown", threat_score=0, blocked=0,
               request_method="", request_path="", event_type="other",
               severity="medium", reason="", raw_matches=None):
	doc = frappe.new_doc("FrothIQ Log")
	doc.ip_address = ip_address
	doc.source = source
	doc.threat_score = int(threat_score)
	doc.blocked = int(blocked)
	doc.request_method = request_method
	doc.request_path = request_path[:1000]
	doc.event_type = event_type
	doc.severity = severity
	doc.reason = reason
	doc.raw_matches = raw_matches or ""
	doc.insert(ignore_permissions=True)
	return doc.name
