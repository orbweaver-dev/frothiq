# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ Event — bridge between frothiq-core threat data and Frappe notifications.

Each document represents a single security event (attack, block, campaign,
anomaly, or system alert) for one tenant. The controller handles:

  1. Suppression   — hash-based deduplication; max 10 per IP per hour.
                     Duplicate events within a 5-minute window are silently dropped.
  2. Real-time     — frappe.publish_realtime() fires on every new event so the
                     customer portal dashboard updates without a page refresh.
  3. Webhook       — if the tenant has a webhook_url configured, a POST is sent
                     with the event JSON (respects webhook_events filter list).
"""

import hashlib
import json
import logging

import frappe
import requests as _requests
from frappe import _
from frappe.model.document import Document
from frappe.utils import now_datetime

logger = logging.getLogger(__name__)

# Alert suppression limits
_DEDUP_WINDOW_SECS = 300        # 5-minute dedup window
_MAX_EVENTS_PER_IP_PER_HOUR = 10
_CACHE_PREFIX = "fq_alert:"
_IP_HOUR_PREFIX = "fq_ip_hr:"

_WEBHOOK_TIMEOUT = 5


class FrothIQEvent(Document):
    # ------------------------------------------------------------------
    # Lifecycle hooks
    # ------------------------------------------------------------------

    def before_insert(self):
        """Set timestamp if not provided; compute dedup hash."""
        if not self.timestamp:
            self.timestamp = now_datetime()
        self._compute_dedup_hash()

    def validate(self):
        """
        Raise frappe.ValidationError to abort insert when this event is a duplicate
        or when the per-IP-per-hour cap has been reached.
        """
        if not self.dedup_hash:
            self._compute_dedup_hash()

        cache_key = f"{_CACHE_PREFIX}{self.dedup_hash}"

        # --- dedup check ---
        if frappe.cache().get(cache_key):
            frappe.throw(
                _("Duplicate alert suppressed (dedup_hash={0})").format(self.dedup_hash),
                frappe.DuplicateEntryError,
            )

        # --- per-IP hourly cap ---
        if self.ip_address:
            ip_key = f"{_IP_HOUR_PREFIX}{self.tenant}:{self.ip_address}"
            count = frappe.cache().get(ip_key)
            if count and int(count) >= _MAX_EVENTS_PER_IP_PER_HOUR:
                frappe.throw(
                    _("Alert suppressed: hourly cap reached for IP {0}").format(self.ip_address),
                    frappe.ValidationError,
                )

    def after_insert(self):
        """Mark dedup hash in cache, bump IP counter, fire realtime + webhook."""
        self._mark_dedup_cache()
        self._bump_ip_counter()
        self._publish_realtime()
        self._dispatch_webhook()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compute_dedup_hash(self):
        """
        SHA-256(tenant + ip_address + event_type + 5-min time bucket).

        Identical events within the same 5-minute window get the same hash
        and the second insertion is rejected by validate().
        """
        from frappe.utils import get_datetime
        import math

        ts = self.timestamp or now_datetime()
        if hasattr(ts, "timestamp"):
            unix_ts = ts.timestamp()
        else:
            unix_ts = get_datetime(str(ts)).timestamp()

        bucket = math.floor(unix_ts / _DEDUP_WINDOW_SECS)
        raw = f"{self.tenant}:{self.ip_address or ''}:{self.event_type}:{bucket}"
        self.dedup_hash = hashlib.sha256(raw.encode()).hexdigest()[:32]

    def _mark_dedup_cache(self):
        """Store dedup hash in Redis with a TTL of 2× the dedup window."""
        try:
            frappe.cache().set(
                f"{_CACHE_PREFIX}{self.dedup_hash}",
                "1",
                expires_in_sec=_DEDUP_WINDOW_SECS * 2,
            )
        except Exception:
            pass  # Cache miss is safe — worst case we get a duplicate event

    def _bump_ip_counter(self):
        """Increment the per-IP hourly event counter in Redis (TTL = 3600 s)."""
        if not self.ip_address:
            return
        try:
            ip_key = f"{_IP_HOUR_PREFIX}{self.tenant}:{self.ip_address}"
            cache = frappe.cache()
            val = cache.get(ip_key)
            if val is None:
                cache.set(ip_key, "1", expires_in_sec=3600)
            else:
                cache.set(ip_key, str(int(val) + 1), expires_in_sec=3600)
        except Exception:
            pass

    def _publish_realtime(self):
        """Push event to the tenant account owner via Socket.IO."""
        try:
            owner = frappe.db.get_value("FrothIQ Tenant", self.tenant, "account_owner")
            if not owner:
                return
            frappe.publish_realtime(
                event="frothiq_alert_event",
                message={
                    "name": self.name,
                    "tenant": self.tenant,
                    "event_type": self.event_type,
                    "severity": self.severity,
                    "score": self.score,
                    "ip_address": self.ip_address,
                    "timestamp": str(self.timestamp),
                    "campaign_id": self.campaign_id,
                    "source": self.source,
                },
                user=owner,
            )
        except Exception:
            logger.debug("publish_realtime failed for event %s", self.name, exc_info=True)

    def _dispatch_webhook(self):
        """POST event JSON to the tenant's configured webhook_url (if any)."""
        try:
            tenant_doc = frappe.get_cached_doc("FrothIQ Tenant", self.tenant)
            webhook_url = getattr(tenant_doc, "webhook_url", None)
            if not webhook_url:
                return

            # Respect event-type filter list
            webhook_events = getattr(tenant_doc, "webhook_events", "") or ""
            if webhook_events:
                allowed = [e.strip() for e in webhook_events.split(",") if e.strip()]
                if allowed and self.event_type not in allowed:
                    return

            payload = {
                "event": self.event_type,
                "severity": self.severity,
                "score": self.score,
                "ip_address": self.ip_address,
                "tenant": self.tenant,
                "site": self.site,
                "timestamp": str(self.timestamp),
                "campaign_id": self.campaign_id,
                "source": self.source,
                "name": self.name,
            }
            _requests.post(
                webhook_url,
                json=payload,
                timeout=_WEBHOOK_TIMEOUT,
                headers={"Content-Type": "application/json"},
            )
        except Exception:
            logger.debug("Webhook dispatch failed for event %s", self.name, exc_info=True)
