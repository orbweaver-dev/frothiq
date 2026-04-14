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

# Phase 4: upgrade state machine
# States: observed → nudged → engaged → converted → retained
_UPGRADE_STATE_KEY    = "ce:upgrade_state:{tenant_name}"
_UPGRADE_STATE_TTL    = 90 * 24 * 3600   # 90 days

_VALID_STATES = ("observed", "nudged", "engaged", "converted", "retained")
# Allowed forward transitions only — no backward movement
_STATE_TRANSITIONS = {
    "observed":  {"nudged"},
    "nudged":    {"engaged", "converted"},
    "engaged":   {"converted"},
    "converted": {"retained"},
    "retained":  set(),
}

# Routing thresholds for contextual_upgrade_router
_INTENSITY_HIGH = 80
_INTENSITY_MID  = 50


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
        # Phase 1 additions
        "GLOBAL_INTEL_SPIKE",
        "CAMPAIGN_PROPAGATION_EVENT",
        "SIMULATION_INSIGHT_EVENT",
        "POLICY_UPGRADE_OPPORTUNITY",
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
# Phase 4: Upgrade state machine
# ---------------------------------------------------------------------------

def get_upgrade_state(tenant_name: str) -> str:
    """
    Return the current upgrade funnel state for a tenant.

    States: observed → nudged → engaged → converted → retained
    Default state is "observed" (everyone starts here).

    Parameters
    ----------
    tenant_name : str

    Returns
    -------
    str — current state name
    """
    key = _UPGRADE_STATE_KEY.format(tenant_name=tenant_name)
    try:
        raw = frappe.cache().get(key)
        state = raw.decode() if isinstance(raw, bytes) else str(raw or "")
        return state if state in _VALID_STATES else "observed"
    except Exception:
        return "observed"


def advance_upgrade_state(tenant_name: str, target_state: str) -> bool:
    """
    Advance the tenant's upgrade funnel state to target_state.

    Only valid forward transitions are allowed (no skipping, no going back).

    Parameters
    ----------
    tenant_name  : str
    target_state : str — must be a valid next state

    Returns
    -------
    bool — True if state was advanced, False if transition is invalid
    """
    if target_state not in _VALID_STATES:
        return False

    current = get_upgrade_state(tenant_name)
    if target_state not in _STATE_TRANSITIONS.get(current, set()):
        return False

    key = _UPGRADE_STATE_KEY.format(tenant_name=tenant_name)
    frappe.cache().set(key, target_state, expires_in_sec=_UPGRADE_STATE_TTL)
    frappe.logger("frothiq_conversion").info(
        "upgrade_orchestrator: state machine %s → %s for tenant %s",
        current, target_state, tenant_name,
    )
    return True


def contextual_upgrade_router(event, tenant) -> dict:
    """
    Route a ValueEvent to the appropriate upgrade action based on intensity.

    Routing rules:
    - intensity_score ≥ 80 → immediate upgrade modal + email trigger
    - intensity_score 50–79 → dashboard banner + delayed email
    - intensity_score < 50  → silent tracking only (advance to "nudged" quietly)

    Also advances the state machine based on what action is taken.

    Parameters
    ----------
    event  : ValueEvent (from value_event_detector)
    tenant : FrothIQ Tenant doc

    Returns
    -------
    dict — {action_taken, state_before, state_after, paywall_type, email_queued}
    """
    intensity = getattr(event, "intensity_score", 50)
    current_state = get_upgrade_state(tenant.name)
    result = {
        "action_taken": None,
        "state_before": current_state,
        "state_after":  current_state,
        "paywall_type": None,
        "email_queued": False,
    }

    from .paywall_injector import is_safe_to_show_paywall, select_paywall_type

    if intensity >= _INTENSITY_HIGH:
        # HIGH: modal upgrade prompt + email
        if is_safe_to_show_paywall(tenant.name, tenant.plan or "free"):
            paywall_type = "modal_upgrade_prompt"
            result["action_taken"] = "modal_and_email"
            result["paywall_type"] = paywall_type

            # Queue email immediately
            email_sent = send_upgrade_email(tenant, event)
            result["email_queued"] = email_sent

            # Advance state: observed→nudged or nudged→engaged
            if current_state == "observed":
                advance_upgrade_state(tenant.name, "nudged")
            elif current_state == "nudged":
                advance_upgrade_state(tenant.name, "engaged")

    elif intensity >= _INTENSITY_MID:
        # MID: dashboard banner + delayed email (next daily run)
        if is_safe_to_show_paywall(tenant.name, tenant.plan or "free"):
            paywall_type = select_paywall_type(
                feature=getattr(event, "cta_plan", ""),
                intensity_score=intensity,
                trigger_event_type=event.event_type,
            )
            result["action_taken"] = "banner_and_delayed_email"
            result["paywall_type"] = paywall_type

            # Email queued for next daily run (not sent immediately)
            result["email_queued"] = False

            if current_state == "observed":
                advance_upgrade_state(tenant.name, "nudged")

    else:
        # LOW: silent tracking only
        result["action_taken"] = "silent_track"
        if current_state == "observed":
            advance_upgrade_state(tenant.name, "nudged")

    result["state_after"] = get_upgrade_state(tenant.name)
    return result


def mark_tenant_converted(tenant_name: str) -> bool:
    """
    Mark a tenant as converted (they upgraded their plan).

    Called by billing_api when a plan upgrade is processed.
    """
    current = get_upgrade_state(tenant_name)
    if current in ("observed", "nudged", "engaged"):
        # Can jump to converted from any pre-converted state
        key = _UPGRADE_STATE_KEY.format(tenant_name=tenant_name)
        frappe.cache().set(key, "converted", expires_in_sec=_UPGRADE_STATE_TTL)
        frappe.logger("frothiq_conversion").info(
            "upgrade_orchestrator: CONVERTED — tenant %s", tenant_name
        )
        return True
    if current == "converted":
        return advance_upgrade_state(tenant_name, "retained")
    return False


def get_funnel_summary() -> dict:
    """
    Return aggregate counts across all tenant upgrade funnel states.

    Scans all active tenants and returns state distribution.
    Admin-only operation.
    """
    tenants = frappe.get_all("FrothIQ Tenant", filters={"is_active": 1}, fields=["name"])
    counts = {s: 0 for s in _VALID_STATES}
    for row in tenants:
        state = get_upgrade_state(row["name"])
        counts[state] = counts.get(state, 0) + 1
    return {
        "total":  len(tenants),
        "states": counts,
    }


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
    routed_actions = []

    for event in events:
        route = contextual_upgrade_router(event, tenant)
        routed_actions.append({
            "event_type":   event.event_type,
            "action_taken": route["action_taken"],
            "state_after":  route["state_after"],
            "paywall_type": route["paywall_type"],
        })
        if route.get("email_queued"):
            email_sent = True

    # Legacy fallback: if no contextual router sent email, try top event
    if send_email and events and not email_sent:
        top_event = events[0]
        if getattr(top_event, "intensity_score", 50) >= 70:
            email_sent = send_upgrade_email(tenant, top_event)

    result = {
        "events":         [e.event_type for e in events],
        "banners_pushed": [b["event_type"] for b in banners_pushed],
        "email_sent":     email_sent,
        "routed_actions": routed_actions,
        "funnel_state":   get_upgrade_state(tenant.name),
    }

    # Flywheel hook — non-breaking, fire-and-forget
    try:
        import sys
        if "/opt/frothiq-core" not in sys.path:
            sys.path.insert(0, "/opt/frothiq-core")
        from frothiq_core.flywheel import emit_signal, SignalType, OriginSystem
        if events:
            emit_signal(
                signal_type   = SignalType.UPGRADE_SHOWN,
                origin_system = OriginSystem.CONVERSION,
                severity      = "low",
                confidence    = 0.8,
                positive      = True,
                metadata      = {"event_count": len(events), "banners": len(banners_pushed)},
            )
        if email_sent:
            emit_signal(
                signal_type   = SignalType.CONVERSION_SUCCESS,
                origin_system = OriginSystem.CONVERSION,
                severity      = "medium",
                confidence    = 0.9,
                positive      = True,
                metadata      = {"funnel_state": result["funnel_state"]},
            )
    except Exception:
        pass  # flywheel must never break conversion engine

    return result
