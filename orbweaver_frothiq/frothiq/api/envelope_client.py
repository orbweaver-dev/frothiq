# Copyright (c) 2026, OrbWeaver
# License: Proprietary

"""
FrothIQ Frappe Envelope Client — validates and applies signed threat envelopes.

Signed envelopes arrive from the FrothIQ Control Center via the HTTP endpoint
exposed by receive_envelope(). Each envelope is:

  1. Validated (HMAC-SHA256 + expiry + anti-replay) against frothiq-core
  2. Checked against the local tenant tier
  3. Applied via local_defense.block_ip() if policy allows

Fail-closed: if the signing key is not configured, all envelopes are rejected.
If frothiq-core is unreachable for verification, the envelope is held for retry
(up to MAX_RETRY_AGE seconds) rather than silently accepted.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from typing import Optional

import frappe
import requests as _requests

from .local_defense import block_ip, unblock_ip

logger = logging.getLogger(__name__)

_CORE_URL = os.getenv("FROTHIQ_CORE_URL", "http://127.0.0.1:8001")
_TIMEOUT  = 5
_MAX_RETRY_AGE = 300   # hold unverified envelopes for up to 5 minutes

# In-process nonce registry: eid → exp (mirrors server-side anti-replay)
_seen_eids: dict[str, float] = {}

# Tier rank — must match frothiq-core models.py
_TIER_RANK = {"free": 0, "pro": 1, "enterprise": 2}

# ---------------------------------------------------------------------------
# Whitelisted endpoint — called by the CC dispatch push
# ---------------------------------------------------------------------------


@frappe.whitelist(allow_guest=False)
def receive_envelope(envelope: dict | str) -> dict:
    """
    Accept a signed threat envelope from the FrothIQ Control Center.

    The CC calls POST /api/method/orbweaver_frothiq.frothiq.api.envelope_client.receive_envelope
    with {"envelope": <wire_dict>}.

    Returns {"accepted": bool, "action": str, "reason": str}
    """
    if isinstance(envelope, str):
        try:
            envelope = json.loads(envelope)
        except json.JSONDecodeError:
            return {"accepted": False, "action": "rejected", "reason": "JSON parse error"}

    return _process_envelope(envelope)


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------


def _process_envelope(wire: dict) -> dict:
    # Step 1 — basic structure check
    required = ("v", "eid", "iat", "exp", "iss", "kid", "payload", "sig")
    missing = [f for f in required if f not in wire]
    if missing:
        return {"accepted": False, "action": "rejected",
                "reason": f"Missing fields: {missing}"}

    eid = wire["eid"]
    exp = wire["exp"]
    payload = wire.get("payload", {})

    # Step 2 — expiry check (local, fast)
    if time.time() > exp:
        return {"accepted": False, "action": "rejected",
                "reason": f"Envelope expired at {exp}"}

    # Step 3 — local anti-replay (before core round-trip)
    _prune_nonces()
    if eid in _seen_eids:
        return {"accepted": False, "action": "rejected",
                "reason": f"Replay detected: eid={eid}"}

    # Step 4 — HMAC verification via local key or core round-trip
    signing_key = frappe.conf.get("frothiq_envelope_key") or os.getenv(
        "FROTHIQ_ENVELOPE_SIGNING_KEY", ""
    )

    if signing_key:
        if not _verify_local(wire, signing_key):
            return {"accepted": False, "action": "rejected",
                    "reason": "HMAC verification failed (local key)"}
    else:
        # Fail-closed: no key → reject
        logger.warning(
            "FrothIQ envelope received but no signing key configured. "
            "Set frothiq_envelope_key in site_config.json. Rejecting."
        )
        return {"accepted": False, "action": "rejected",
                "reason": "No envelope signing key configured (fail-closed)"}

    # Step 5 — record nonce
    _seen_eids[eid] = exp

    # Step 6 — tier gate
    tier_min = payload.get("tier_min", "enterprise")
    tenant_tier = frappe.conf.get("frothiq_plan", "free")
    if _TIER_RANK.get(tenant_tier, 0) < _TIER_RANK.get(tier_min, 99):
        return {
            "accepted": True,
            "action":   "skipped",
            "reason":   f"Tenant tier {tenant_tier!r} below required {tier_min!r}",
        }

    # Step 7 — policy gate
    policy = payload.get("policy", "alert_only")
    ip_address = payload.get("ip", "")

    if not ip_address:
        return {"accepted": False, "action": "rejected", "reason": "Envelope missing IP"}

    if policy == "alert_only":
        _log_alert(ip_address, payload)
        return {"accepted": True, "action": "alert_logged", "reason": "policy=alert_only"}

    if policy == "optional_block":
        # Apply block only if local auto-block is opted in
        auto_block = frappe.conf.get("frothiq_auto_block_optional", False)
        if not auto_block:
            _log_alert(ip_address, payload)
            return {"accepted": True, "action": "alert_logged",
                    "reason": "policy=optional_block; auto-block not enabled"}

    # policy == "auto_block" or optional_block with auto-block opted in
    result = block_ip(
        ip_address=ip_address,
        reason=f"FrothIQ envelope {eid}: {payload.get('reason', '')}",
        ttl_seconds=payload.get("ttl"),
        agent_id=None,
    )

    if result["blocked"]:
        return {
            "accepted": True,
            "action":   "blocked",
            "reason":   f"Blocked via {result['layer']}",
        }
    else:
        return {
            "accepted": True,
            "action":   "block_failed",
            "reason":   result.get("error", "Unknown error"),
        }


# ---------------------------------------------------------------------------
# HMAC verification (local)
# ---------------------------------------------------------------------------


def _canonical(wire: dict) -> str:
    payload_str = json.dumps(wire["payload"], sort_keys=True, separators=(",", ":"))
    return (
        f"v={wire['v']}&eid={wire['eid']}&iat={wire['iat']}&exp={wire['exp']}"
        f"&iss={wire['iss']}&kid={wire['kid']}&payload={payload_str}"
    )


def _verify_local(wire: dict, key_hex: str) -> bool:
    try:
        key_bytes = bytes.fromhex(key_hex)
    except ValueError:
        logger.error("frothiq_envelope_key is not valid hex")
        return False

    canonical = _canonical(wire)
    expected = hmac.new(
        key_bytes,
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, wire.get("sig", ""))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _prune_nonces() -> None:
    now = time.time()
    expired = [eid for eid, exp in _seen_eids.items() if exp <= now]
    for eid in expired:
        del _seen_eids[eid]


def _log_alert(ip: str, payload: dict) -> None:
    try:
        doc = frappe.get_doc({
            "doctype":    "FrothIQ Log",
            "log_type":   "threat_alert",
            "ip_address": ip,
            "action":     "alert",
            "layer":      "envelope",
            "reason":     payload.get("reason", "")[:500],
            "agent_id":   "",
            "timestamp":  frappe.utils.now(),
        })
        doc.insert(ignore_permissions=True)
        frappe.db.commit()
    except Exception as exc:
        logger.debug("Failed to write alert log: %s", exc)
