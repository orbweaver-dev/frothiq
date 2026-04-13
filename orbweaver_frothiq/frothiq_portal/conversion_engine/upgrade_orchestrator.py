# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ Conversion Engine — Upgrade Orchestrator

Coordinates delivery of upgrade nudges to tenants who have triggered
ValueEvents. Manages:

  - Banner queue    : in-portal upgrade banners, de-duped and rate-limited
  - Email dispatch  : upgrade suggestion emails via Frappe's email system
  - Dismissal state : respects per-banner dismiss actions from the portal

Rate limits
-----------
  - Max 1 upgrade email per tenant per 7 days
  - Max 2 banners shown simultaneously (oldest dismissed first)
  - Email opt-out via FrothIQ Tenant.upgrade_emails_opt_out (Check field)

Banner format (stored in Redis as JSON)
---------------------------------------
  {
    "banner_id":   str,   — SHA-256 of (tenant_name + event_type)[:16]
    "event_type":  str,
    "title":       str,
    "body":        str,
    "cta_label":   str,
    "cta_plan":    str,
    "priority":    int,
    "created_at":  float,
    "dismissed":   bool,
  }
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Optional

import frappe

_BANNER_TTL           = 7 * 24 * 3600    # banners expire after 7 days
_EMAIL_COOLDOWN       = 7 * 24 * 3600    # one upgrade email per 7 days
_MAX_ACTIVE_BANNERS   = 2
_BANNER_KEY_PREFIX    = "ce:banner:"
_EMAIL_SENT_KEY       = "ce:email_sent:"


def _banner_id(tenant_name: str, event_type: str) -> str:
    raw = f"{tenant_name}:{event_type}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _banner_cache_key(tenant_name: str, banner_id: str) -> str:
    return f"{_BANNER_KEY_PREFIX}{tenant_name}:{banner_id}"


# ---------------------------------------------------------------------------
# Banner management
# ---------------------------------------------------------------------------

def push_banners(tenant, events: list) -> list[dict]:
    """
    Convert ValueEvents into banners and store them in Redis for the portal.

    Only stores banners that are not already present and not dismissed.
    Respects the MAX_ACTIVE_BANNERS limit.

    Parameters
    ----------
    tenant : FrothIQ Tenant doc
    events : list[ValueEvent] from value_event_detector.detect_events()

    Returns
    -------
    list[dict] — banners that were newly pushed
    """
    pushed = []
    for event in events:
        bid = _banner_id(tenant.name, event.event_type)
        key = _banner_cache_key(tenant.name, bid)

        existing = frappe.cache().get(key)
        if existing:
            continue  # already queued

        active = get_active_banners(tenant.name)
        if len(active) >= _MAX_ACTIVE_BANNERS:
            break  # don't exceed the visible limit

        banner = {
            "banner_id":  bid,
            "event_type": event.event_type,
            "title":      event.title,
            "body":       event.body,
            "cta_label":  event.cta_label,
            "cta_plan":   event.cta_plan,
            "priority":   event.priority,
            "created_at": time.time(),
            "dismissed":  False,
        }
        frappe.cache().set(key, json.dumps(banner), expires_in_sec=_BANNER_TTL)
        pushed.append(banner)
        frappe.logger("frothiq_conversion").info(
            "upgrade_orchestrator: pushed banner '%s' for tenant %s",
            event.event_type, tenant.name,
        )
    return pushed


def get_active_banners(tenant_name: str) -> list[dict]:
    """
    Return all non-dismissed banners for a tenant, sorted by priority.

    Banners are stored individually in Redis; this method scans the known
    event types to reconstruct the active set.
    """
    from .value_event_detector import ValueEvent

    # Scan all possible banner IDs for this tenant
    event_types = [
        "SITE_LIMIT_REACHED",
        "FEATURE_BLOCKED",
        "HIGH_THREAT_DETECTED",
        "INTEL_NEAR_LIMIT",
        "EVENTS_SPIKE",
        "CAMPAIGNS_ACTIVE",
        "TRIAL_NEARING_END",
    ]
    banners = []
    for etype in event_types:
        bid = _banner_id(tenant_name, etype)
        key = _banner_cache_key(tenant_name, bid)
        raw = frappe.cache().get(key)
        if raw:
            try:
                banner = json.loads(raw) if isinstance(raw, str) else raw
                if not banner.get("dismissed"):
                    banners.append(banner)
            except (json.JSONDecodeError, AttributeError):
                pass

    return sorted(banners, key=lambda b: b.get("priority", 5))


def dismiss_banner(tenant_name: str, banner_id: str) -> bool:
    """
    Mark a banner as dismissed (portal user clicked ×).

    The banner remains in Redis (so it doesn't re-fire within cooldown)
    but is excluded from active banner listings.

    Returns True if the banner was found and dismissed, False otherwise.
    """
    key = _banner_cache_key(tenant_name, banner_id)
    raw = frappe.cache().get(key)
    if not raw:
        return False

    try:
        banner = json.loads(raw) if isinstance(raw, str) else raw
    except (json.JSONDecodeError, AttributeError):
        return False

    banner["dismissed"] = True
    frappe.cache().set(key, json.dumps(banner), expires_in_sec=_BANNER_TTL)
    return True


# ---------------------------------------------------------------------------
# Email dispatch
# ---------------------------------------------------------------------------

def send_upgrade_email(tenant, event) -> bool:
    """
    Send an upgrade suggestion email to the tenant account owner.

    Respects:
      - upgrade_emails_opt_out flag on the tenant record
      - 7-day email cooldown per tenant (Redis key)

    Returns True if the email was sent, False if suppressed.
    """
    # Check opt-out flag
    if getattr(tenant, "upgrade_emails_opt_out", False):
        return False

    # Check cooldown
    cooldown_key = f"{_EMAIL_SENT_KEY}{tenant.name}"
    if frappe.cache().get(cooldown_key):
        return False

    try:
        owner_email = frappe.db.get_value("User", tenant.account_owner, "email")
        if not owner_email:
            return False

        subject = f"FrothIQ: {event.title}"
        message = _build_email_body(tenant, event)

        frappe.sendmail(
            recipients=[owner_email],
            subject=subject,
            message=message,
            now=True,
        )

        # Mark cooldown
        frappe.cache().set(cooldown_key, 1, expires_in_sec=_EMAIL_COOLDOWN)
        frappe.logger("frothiq_conversion").info(
            "upgrade_orchestrator: upgrade email sent to %s for event %s",
            owner_email, event.event_type,
        )
        return True

    except Exception as exc:
        frappe.logger("frothiq_conversion").warning(
            "upgrade_orchestrator: failed to send upgrade email for %s: %s",
            tenant.name, exc,
        )
        return False


def _build_email_body(tenant, event) -> str:
    """Build a simple HTML email body for the upgrade suggestion."""
    plan_url = frappe.utils.get_url("/portal/billing/upgrade")
    return f"""
<div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
  <h2 style="color: #0f1629;">{event.title}</h2>
  <p style="color: #333; line-height: 1.6;">{event.body}</p>
  <p>
    <a href="{plan_url}"
       style="display: inline-block; background: #4f8ef7; color: white;
              padding: 12px 24px; border-radius: 6px; text-decoration: none;
              font-weight: bold;">
      {event.cta_label}
    </a>
  </p>
  <p style="color: #666; font-size: 0.85em; margin-top: 32px;">
    You're receiving this because you have a FrothIQ account.
    <a href="{frappe.utils.get_url('/portal/notifications')}">Manage email preferences</a>
  </p>
</div>
"""


# ---------------------------------------------------------------------------
# Orchestrate: run detectors + push banners + optionally email
# ---------------------------------------------------------------------------

def orchestrate(tenant, send_email: bool = True) -> dict:
    """
    Full conversion orchestration for a tenant.

    Detects value events, pushes banners, optionally sends one upgrade email
    (the highest-priority event that qualifies).

    Parameters
    ----------
    tenant    : FrothIQ Tenant doc
    send_email: bool  — if False, skip email (useful for background jobs
                        that only want to refresh banners)

    Returns
    -------
    dict — {events: [...], banners_pushed: [...], email_sent: bool}
    """
    from .value_event_detector import detect_events

    events         = detect_events(tenant)
    banners_pushed = push_banners(tenant, events)
    email_sent     = False

    if send_email and events:
        # Send email for the highest-priority event
        top_event = events[0]
        email_sent = send_upgrade_email(tenant, top_event)

    return {
        "events":         [e.event_type for e in events],
        "banners_pushed": [b["event_type"] for b in banners_pushed],
        "email_sent":     email_sent,
    }
