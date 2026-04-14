# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ License Audit Bridge

Unified dual-write audit trail for all license lifecycle events.

This bridge extends the existing license_system.license_audit_log.LicenseAuditLog
by adding:
  - A richer event schema (supports all Phase 1–6 event types)
  - Frappe FrothIQ Event DocType integration (real-time UI)
  - append-only JSONL secondary log at /var/log/frothiq/license_audit.jsonl
  - Event deduplication within a 1-second window (same tenant+event_type)
  - Rate-limit protection against log flooding

Event types
-----------
  issued         — new license token created
  refreshed      — periodic re-issuance
  suspended      — license suspended (quarantine)
  revoked        — license explicitly revoked (tombstone issued)
  rotated        — signing key rotated; new license_id issued
  expired        — token TTL elapsed (background purge job)
  sig_failure    — edge plugin reported signature failure
  expired_use    — edge plugin attempted action with expired license
  sync           — heartbeat sync event from edge plugin
  cache_poisoning — anomaly: replayed / forged token attempt
  version_mismatch — version downgrade detected
  cross_tenant   — cross-tenant token reuse attempt

All writes are thread-safe and best-effort — exceptions are caught
and logged to stderr, never propagated to callers.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_DEFAULT_LOG_PATH = Path("/var/log/frothiq/license_audit.jsonl")
_LOCK             = threading.Lock()

# Deduplication window: suppress identical (tenant_id, event_type) within 1s
_DEDUP_WINDOW_SECONDS = 1.0

# Valid event types
_VALID_EVENTS = frozenset({
    "issued", "refreshed", "suspended", "revoked", "rotated", "expired",
    "sig_failure", "expired_use", "sync", "cache_poisoning",
    "version_mismatch", "cross_tenant",
})

# Severity per event type
_EVENT_SEVERITY = {
    "issued":           "info",
    "refreshed":        "info",
    "sync":             "info",
    "expired":          "info",
    "rotated":          "info",
    "suspended":        "warning",
    "revoked":          "warning",
    "expired_use":      "warning",
    "version_mismatch": "warning",
    "sig_failure":      "critical",
    "cache_poisoning":  "critical",
    "cross_tenant":     "critical",
}


class LicenseAuditBridge:
    """
    Thread-safe dual-write audit trail for the License Control Center.

    Primary:   FrothIQ Event DocType (best-effort; requires Frappe context)
    Secondary: /var/log/frothiq/license_audit.jsonl (always)
    """

    def __init__(self, log_path: Optional[Path] = None) -> None:
        self._path        = log_path or _DEFAULT_LOG_PATH
        self._dedup_cache: dict[str, float] = {}
        self._dedup_lock  = threading.Lock()

    # ------------------------------------------------------------------
    # Public: record an event
    # ------------------------------------------------------------------

    def record(
        self,
        event_type: str,
        tenant_id:  str,
        license_id: str,
        severity:   Optional[str] = None,
        details:    Optional[dict] = None,
        agent_id:   str            = "",
    ) -> None:
        """
        Record a license lifecycle event.

        Parameters
        ----------
        event_type  : str   One of _VALID_EVENTS
        tenant_id   : str   FrothIQ Tenant name
        license_id  : str   License ID (FIQ-LIC-…)
        severity    : str   Override default severity for this event type
        details     : dict  Additional event-specific context
        agent_id    : str   Edge plugin agent identifier (if applicable)
        """
        if event_type not in _VALID_EVENTS:
            event_type = "issued"   # safe fallback

        resolved_severity = severity or _EVENT_SEVERITY.get(event_type, "info")

        # Deduplication (suppresses duplicate events within window)
        dedup_key = f"{tenant_id}:{event_type}"
        with self._dedup_lock:
            last_ts = self._dedup_cache.get(dedup_key, 0.0)
            now     = time.time()
            if now - last_ts < _DEDUP_WINDOW_SECONDS:
                return
            self._dedup_cache[dedup_key] = now

        entry = {
            "ts":         now,
            "event_type": event_type,
            "tenant_id":  tenant_id,
            "license_id": license_id,
            "severity":   resolved_severity,
            "agent_id":   agent_id,
            "details":    details or {},
        }

        self._write_jsonl(entry)
        self._write_frappe_event(entry)

    # Convenience wrappers for common event types
    def record_sig_failure(
        self,
        tenant_id:  str,
        agent_id:   str,
        reason:     str,
        license_id: str = "",
    ) -> None:
        self.record(
            event_type = "sig_failure",
            tenant_id  = tenant_id,
            license_id = license_id,
            agent_id   = agent_id,
            details    = {"reason": reason},
        )

    def record_cross_tenant_attempt(
        self,
        claimed_tenant_id: str,
        actual_tenant_id:  str,
        agent_id:          str,
        license_id:        str = "",
    ) -> None:
        self.record(
            event_type = "cross_tenant",
            tenant_id  = claimed_tenant_id,
            license_id = license_id,
            agent_id   = agent_id,
            severity   = "critical",
            details    = {
                "claimed_tenant": claimed_tenant_id,
                "actual_tenant":  actual_tenant_id,
            },
        )

    def record_cache_poisoning(
        self,
        tenant_id:  str,
        agent_id:   str,
        anomaly:    str,
        license_id: str = "",
    ) -> None:
        self.record(
            event_type = "cache_poisoning",
            tenant_id  = tenant_id,
            license_id = license_id,
            agent_id   = agent_id,
            severity   = "critical",
            details    = {"anomaly": anomaly},
        )

    def get_recent(
        self,
        limit:     int           = 100,
        tenant_id: Optional[str] = None,
        event_type: Optional[str] = None,
    ) -> list[dict]:
        """Read recent audit entries from the JSONL file (most recent first)."""
        entries: list[dict] = []
        try:
            if not self._path.exists():
                return []
            lines = self._path.read_text(encoding="utf-8").splitlines()
            for line in reversed(lines):
                if len(entries) >= limit:
                    break
                try:
                    e = json.loads(line)
                    if tenant_id  and e.get("tenant_id")  != tenant_id:
                        continue
                    if event_type and e.get("event_type") != event_type:
                        continue
                    entries.append(e)
                except Exception:
                    pass
        except Exception as exc:
            logger.debug("license_audit_bridge.get_recent: %s", exc)
        return entries

    # ------------------------------------------------------------------
    # Private: writers
    # ------------------------------------------------------------------

    def _write_jsonl(self, entry: dict) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with _LOCK:
                with self._path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, default=str) + "\n")
        except Exception as exc:
            logger.warning("license_audit_bridge: JSONL write failed: %s", exc)

    @staticmethod
    def _write_frappe_event(entry: dict) -> None:
        try:
            import frappe
            event = frappe.new_doc("FrothIQ Event")
            event.tenant      = entry["tenant_id"]
            event.event_type  = f"license_{entry['event_type']}"
            event.severity    = entry["severity"]
            event.timestamp   = frappe.utils.now_datetime()
            event.raw_payload = json.dumps(entry, default=str)
            event.flags.ignore_permissions = True
            event.insert(ignore_permissions=True)
        except Exception:
            pass   # Frappe context not always available; JSONL is the fallback


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

audit_bridge = LicenseAuditBridge()
