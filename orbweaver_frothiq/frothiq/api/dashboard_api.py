# Copyright (c) 2026, OrbWeaver
# License: Proprietary

"""
FrothIQ Security Dashboard — backend API

All methods are whitelisted and called by the dashboard page JS via frappe.call().
Reads from FrothIQ Log, FrothIQ Blocklist, and FrothIQ Policy Decision DocTypes
(defined in orbweaver_frothiq_plugin; not redefined here).

Also provides the realtime notifier hook called on FrothIQ Log after_insert.
"""

import json
import os

import frappe
import requests as _requests
from frappe.utils import add_to_date, now_datetime

_FROTHIQ_CORE_URL = os.getenv("FROTHIQ_CORE_URL", "http://127.0.0.1:8001")
_REQUEST_TIMEOUT = 5  # seconds


def _get_admin_key():
	"""Return the FrothIQ admin API key from site config or environment."""
	return frappe.conf.get("frothiq_api_key") or os.getenv("FROTHIQ_API_KEY", "")


def _since(hours: int):
	"""Return a datetime string `hours` ago."""
	return add_to_date(now_datetime(), hours=-int(hours))


# ---------------------------------------------------------------------------
# Stat cards
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_dashboard_stats(hours=24):
	"""
	Returns the four summary stat cards:
	  total_requests, blocked_count, unique_ips, top_score
	"""
	hours = int(hours)
	since = _since(hours)

	total = frappe.db.count("FrothIQ Log", filters={"creation": [">=", since]})
	blocked = frappe.db.count("FrothIQ Log", filters={
		"creation": [">=", since], "blocked": 1
	})

	unique_ips = frappe.db.sql("""
		SELECT COUNT(DISTINCT ip_address) as c
		FROM `tabFrothIQ Log`
		WHERE creation >= %s
	""", since)[0][0] or 0

	top_score_row = frappe.db.sql("""
		SELECT ip_address, threat_score
		FROM `tabFrothIQ Log`
		WHERE creation >= %s
		ORDER BY threat_score DESC
		LIMIT 1
	""", since, as_dict=True)
	top_score = top_score_row[0] if top_score_row else {"ip_address": "—", "threat_score": 0}

	active_blocks = frappe.db.count("FrothIQ Blocklist", filters={"status": "active"})

	return {
		"total_requests": total,
		"blocked_count": blocked,
		"unique_ips": unique_ips,
		"top_score": top_score,
		"active_blocks": active_blocks,
		"hours": hours,
	}


# ---------------------------------------------------------------------------
# Live request feed
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_live_feed(limit=60, after_name=None):
	"""
	Return recent FrothIQ Log entries, newest first.
	If after_name is given, return only records created after that document
	(used for incremental poll updates).
	"""
	limit = min(int(limit), 200)
	filters = {}

	if after_name:
		# Get the creation time of the anchor record and fetch newer entries
		anchor_ts = frappe.db.get_value("FrothIQ Log", after_name, "creation")
		if anchor_ts:
			filters["creation"] = [">", anchor_ts]

	rows = frappe.get_all(
		"FrothIQ Log",
		filters=filters,
		fields=[
			"name", "creation", "ip_address", "source",
			"threat_score", "blocked", "event_type", "severity",
			"request_method", "request_path", "reason",
		],
		order_by="creation desc",
		limit=limit,
	)

	return rows


# ---------------------------------------------------------------------------
# Attack category breakdown
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_attack_breakdown(hours=24):
	"""
	Return event_type counts for blocked requests in the last N hours.
	Used by the attack category bar chart.
	"""
	since = _since(int(hours))
	rows = frappe.db.sql("""
		SELECT event_type, COUNT(*) as cnt
		FROM `tabFrothIQ Log`
		WHERE creation >= %s
		  AND event_type IS NOT NULL
		  AND event_type != ''
		  AND event_type != 'other'
		GROUP BY event_type
		ORDER BY cnt DESC
	""", since, as_dict=True)
	return rows


# ---------------------------------------------------------------------------
# IP tracking timeline — top offenders
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_top_ips(hours=24, limit=10):
	"""
	Return the top repeat-offending IPs with:
	  - request count
	  - blocked count
	  - max threat score
	  - distinct attack types
	  - first and last seen timestamps
	"""
	since = _since(int(hours))
	rows = frappe.db.sql("""
		SELECT
			ip_address,
			COUNT(*) AS request_count,
			SUM(blocked) AS blocked_count,
			MAX(threat_score) AS max_score,
			GROUP_CONCAT(DISTINCT event_type ORDER BY event_type SEPARATOR ', ') AS attack_types,
			MIN(creation) AS first_seen,
			MAX(creation) AS last_seen
		FROM `tabFrothIQ Log`
		WHERE creation >= %s
		GROUP BY ip_address
		ORDER BY blocked_count DESC, max_score DESC, request_count DESC
		LIMIT %s
	""", (since, int(limit)), as_dict=True)
	return rows


# ---------------------------------------------------------------------------
# CSF action history
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_csf_history(limit=20):
	"""
	Return recent FrothIQ Blocklist entries for the CSF action history panel.
	"""
	rows = frappe.get_all(
		"FrothIQ Blocklist",
		fields=[
			"name", "creation", "ip_address", "list_type",
			"status", "pushed_to_csf", "reason", "expires_on",
		],
		order_by="creation desc",
		limit=int(limit),
	)
	return rows


# ---------------------------------------------------------------------------
# Realtime — called by doc_events hook on FrothIQ Log after_insert
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Federation — node health, global offenders, peer status
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_node_health():
	"""
	Return health info for the local FrothIQ node.
	Calls GET /api/v2/federation/health (unauthenticated).
	"""
	try:
		resp = _requests.get(
			f"{_FROTHIQ_CORE_URL}/api/v2/federation/health",
			timeout=_REQUEST_TIMEOUT,
		)
		resp.raise_for_status()
		return resp.json()
	except Exception as exc:
		return {"status": "unreachable", "error": str(exc)}


@frappe.whitelist()
def get_federation_status():
	"""
	Return full federation summary: node identity, peer sync state, store stats.
	Calls GET /api/v2/federation/status (admin key required).
	"""
	key = _get_admin_key()
	try:
		resp = _requests.get(
			f"{_FROTHIQ_CORE_URL}/api/v2/federation/status",
			headers={"X-FrothIQ-Key": key},
			timeout=_REQUEST_TIMEOUT,
		)
		resp.raise_for_status()
		return resp.json()
	except Exception as exc:
		return {"error": str(exc), "local_node": None, "store": None}


@frappe.whitelist()
def get_global_offenders(limit=10):
	"""
	Return the top globally-observed threat IPs from the federation store.
	Calls GET /api/v2/federation/status and extracts top_global_offenders.
	"""
	key = _get_admin_key()
	try:
		resp = _requests.get(
			f"{_FROTHIQ_CORE_URL}/api/v2/federation/status",
			headers={"X-FrothIQ-Key": key},
			timeout=_REQUEST_TIMEOUT,
		)
		resp.raise_for_status()
		data = resp.json()
		return (data.get("top_global_offenders") or [])[:int(limit)]
	except Exception:
		return []


# ---------------------------------------------------------------------------
# Realtime — called by doc_events hook on FrothIQ Log after_insert
# ---------------------------------------------------------------------------

def notify_new_log(doc, method=None):
	"""
	Called after a FrothIQ Log record is inserted.
	Publishes a realtime event to all dashboard subscribers.
	"""
	try:
		frappe.publish_realtime(
			event="frothiq_new_log",
			message={
				"name": doc.name,
				"creation": str(doc.creation),
				"ip_address": doc.ip_address,
				"source": doc.source or "unknown",
				"threat_score": doc.threat_score or 0,
				"blocked": doc.blocked or 0,
				"event_type": doc.event_type or "other",
				"severity": doc.severity or "medium",
				"request_method": doc.request_method or "",
				"request_path": (doc.request_path or "")[:80],
				"reason": (doc.reason or "")[:120],
			},
			after_commit=True,
		)
	except Exception:
		pass  # realtime is best-effort — never block a log insert
