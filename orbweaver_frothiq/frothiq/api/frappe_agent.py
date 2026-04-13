# Copyright (c) 2026, OrbWeaver
# License: Proprietary

"""
FrothIQ Frappe Agent — transport layer for the FrothIQ Agent Protocol.

Implements the same 6-endpoint protocol as the WordPress plugin.
Only the transport differs (Python requests vs. PHP wp_remote_post).

This module is imported by doc_events hooks and the command center API.
It replaces direct calls to /api/v1/scan-request and /api/v1/report-threat
with the unified agent protocol at /api/v2/agents/*.
"""

from __future__ import annotations

import logging
import os
import time
from functools import lru_cache

import frappe
import requests as _requests

logger = logging.getLogger(__name__)

_CORE_URL = os.getenv("FROTHIQ_CORE_URL", "http://127.0.0.1:8001")
_TIMEOUT = 5
_AGENT_TYPE = "frappe"
_PROTOCOL_VERSION = "1.0"
_AGENT_ID_CONF_KEY = "frothiq_agent_id"


def _api_key() -> str:
    return frappe.conf.get("frothiq_api_key") or os.getenv("FROTHIQ_API_KEY", "")


def _tenant_id() -> str:
    return frappe.conf.get("frothiq_tenant_id") or os.getenv("FROTHIQ_TENANT_ID", "")


def _headers() -> dict:
    return {
        "Content-Type": "application/json",
        "X-FrothIQ-Key": _api_key(),
    }


def _capabilities() -> dict:
    return {
        "local_firewall":     False,
        "csf_integration":    True,   # Frappe app can invoke CSF via response engine
        "wp_hooks":           False,
        "frappe_hooks":       True,
        "nginx_integration":  False,
        "rate_limit_headers": False,
        "apply_actions":      True,
    }


# ---------------------------------------------------------------------------
# Agent ID persistence — stored in Frappe site_config
# ---------------------------------------------------------------------------

def get_or_register_agent_id() -> str:
    """
    Return the persisted agent_id, registering with core if not yet stored.
    Called lazily on first use.
    """
    stored = frappe.conf.get(_AGENT_ID_CONF_KEY)
    if stored:
        # Re-register to refresh last_seen (fire-and-forget)
        _register(stored)
        return stored

    new_id = _register(None)
    if new_id:
        frappe.conf[_AGENT_ID_CONF_KEY] = new_id
        # Persist to site_config.json
        try:
            from frappe.utils.data import set_conf
            set_conf({_AGENT_ID_CONF_KEY: new_id}, site=frappe.local.site)
        except Exception:
            pass
        return new_id

    # Fallback: generate locally
    import hashlib, uuid
    fallback = f"frappe-{frappe.local.site[:12]}-{uuid.uuid4().hex[:8]}"
    frappe.conf[_AGENT_ID_CONF_KEY] = fallback
    return fallback


def _register(existing_id: str | None) -> str | None:
    """POST /api/v2/agents/register → return agent_id or None."""
    try:
        from frothiq_core import __version__ as core_ver
    except ImportError:
        core_ver = "0.0.0"

    try:
        import orbweaver_frothiq
        agent_ver = orbweaver_frothiq.__version__
    except Exception:
        agent_ver = "0.0.0"

    payload: dict = {
        "agent_type":   _AGENT_TYPE,
        "tenant_id":    _tenant_id(),
        "version":      agent_ver,
        "hostname":     frappe.local.site if hasattr(frappe.local, "site") else "",
        "capabilities": _capabilities(),
    }
    if existing_id:
        payload["agent_id"] = existing_id

    try:
        resp = _requests.post(
            f"{_CORE_URL}/api/v2/agents/register",
            json=payload,
            headers=_headers(),
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json().get("agent_id")
    except Exception as exc:
        logger.warning("FrothIQ Agent: registration failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Protocol methods — identical interface to WordPress plugin
# ---------------------------------------------------------------------------

def send_event(ip: str, event_type: str, **context) -> dict | None:
    """
    Report a structured event to frothiq-core.

    Matches the WordPress FrothIQ_Agent::send_event() signature.
    All platforms use the same AgentEvent schema.

    Args:
        ip:         Client IP address.
        event_type: request | failed_login | block_applied | rate_limited | error
        **context:  path, method, severity, detail, metadata
    """
    agent_id = get_or_register_agent_id()
    payload = {
        "agent_id":   agent_id,
        "tenant_id":  _tenant_id(),
        "ip":         ip,
        "event_type": event_type,
        "severity":   context.get("severity", "medium"),
        "path":       context.get("path", "/"),
        "method":     context.get("method", "GET"),
        "detail":     context.get("detail", ""),
        "metadata":   context.get("metadata", {}),
        "ts":         time.time(),
    }
    return _post("/api/v2/agents/report-event", payload)


def scan_request(request_data: dict) -> dict | None:
    """
    Inspect a request via the agent protocol.
    Replaces direct /api/v1/scan-request calls.
    """
    agent_id = get_or_register_agent_id()
    payload = {
        "agent_id":           agent_id,
        "tenant_id":          _tenant_id(),
        "ip":                 request_data.get("ip", ""),
        "method":             request_data.get("method", "GET"),
        "path":               request_data.get("path", "/"),
        "query_params":       request_data.get("query_params", {}),
        "body":               request_data.get("body", ""),
        "headers":            request_data.get("headers", {}),
        "known_bad":          request_data.get("known_bad", False),
        "failed_login_count": request_data.get("failed_login_count", 0),
    }
    return _post("/api/v2/agents/scan-request", payload)


def fetch_decision(ip: str) -> dict | None:
    """Get the latest intelligence decision for an IP without triggering a scan."""
    agent_id = get_or_register_agent_id()
    try:
        resp = _requests.get(
            f"{_CORE_URL}/api/v2/agents/fetch-decision/{ip}",
            headers=_headers(),
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.debug("FrothIQ Agent: fetch-decision failed for %s: %s", ip, exc)
        return None


def apply_action(ip: str, action_type: str, reason: str = "", duration: int | None = None) -> dict | None:
    """Report that a local enforcement action has been applied."""
    agent_id = get_or_register_agent_id()
    payload = {
        "agent_id":         agent_id,
        "tenant_id":        _tenant_id(),
        "ip":               ip,
        "action_type":      action_type,
        "reason":           reason,
        "duration_seconds": duration,
    }
    return _post("/api/v2/agents/apply-action", payload)


def heartbeat(requests_1m: int = 0, blocks_1m: int = 0, errors_1m: int = 0) -> dict | None:
    """Send heartbeat with rolling 1-minute metrics."""
    agent_id = get_or_register_agent_id()
    payload = {
        "agent_id":    agent_id,
        "tenant_id":   _tenant_id(),
        "requests_1m": requests_1m,
        "blocks_1m":   blocks_1m,
        "errors_1m":   errors_1m,
    }
    return _post("/api/v2/agents/heartbeat", payload)


# ---------------------------------------------------------------------------
# Doc-event bridge — maps Frappe DocEvents to Agent Protocol events
# ---------------------------------------------------------------------------

def on_frothiq_log_insert(doc, method=None):
    """
    Called after a FrothIQ Log record is inserted.
    Maps the Frappe doc to the unified AgentEvent schema and reports it.
    This REPLACES the old notify_new_log approach for protocol compliance.
    """
    try:
        send_event(
            ip=doc.ip_address or "",
            event_type="request",
            path=doc.request_path or "/",
            method=doc.request_method or "GET",
            severity=doc.severity or "medium",
            detail=doc.reason or "",
            metadata={
                "threat_score": doc.threat_score or 0,
                "blocked":      bool(doc.blocked),
                "event_type":   doc.event_type or "other",
                "source":       doc.source or "frappe",
            },
        )
    except Exception as exc:
        logger.debug("FrothIQ Agent: on_frothiq_log_insert failed: %s", exc)


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------

def _post(path: str, payload: dict) -> dict | None:
    if not _api_key() or not _tenant_id():
        logger.debug("FrothIQ Agent: not configured (missing api_key or tenant_id)")
        return None
    try:
        resp = _requests.post(
            f"{_CORE_URL}{path}",
            json=payload,
            headers=_headers(),
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.debug("FrothIQ Agent: POST %s failed: %s", path, exc)
        return None
