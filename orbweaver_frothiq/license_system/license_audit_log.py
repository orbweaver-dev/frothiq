# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ License Audit Log (Phase 6)

Immutable append-only audit trail for all license lifecycle events.

Events logged:
  issued       — new license token created
  refreshed    — periodic re-issuance from entitlement refresh
  revoked      — admin explicitly revoked license
  suspended    — license entered quarantine state
  sig_failure  — edge plugin reported signature verification failure
  expired_use  — edge plugin attempted action with expired license
  sync         — heartbeat sync event from edge plugin

Storage:
  Primary:   FrothIQ Event DocType (integrates with Frappe desk)
  Secondary: /var/lib/frothiq/license_audit.jsonl (line-delimited JSON)

Thread-safe. Writing to FrothIQ Event is best-effort — failures are caught
and written to the file-based fallback only.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_DEFAULT_AUDIT_PATH = Path("/var/lib/frothiq/license_audit.jsonl")
_LOCK               = threading.Lock()

_EVENT_TYPE_MAP = {
    "issued":      "license_issued",
    "refreshed":   "license_refreshed",
    "revoked":     "license_revoked",
    "suspended":   "license_suspended",
    "sig_failure": "license_sig_failure",
    "expired_use": "license_expired_use",
    "sync":        "license_sync",
}


class LicenseAuditLog:
    """
    Audit trail for all license lifecycle events.

    Writes to:
      1. FrothIQ Event DocType (best-effort; requires Frappe context)
      2. /var/lib/frothiq/license_audit.jsonl (always)
    """

    def __init__(self, audit_path: Optional[Path] = None) -> None:
        self._path = audit_path or _DEFAULT_AUDIT_PATH

    # ------------------------------------------------------------------
    # Public: specific event types
    # ------------------------------------------------------------------

    def record_issued(self, token: "LicenseToken", triggered_by: str = "system") -> None:
        self._write(
            event_type  = "issued",
            tenant_id   = token.tenant_id,
            license_id  = token.license_id,
            severity    = "info",
            details     = {
                "plan":       token.plan,
                "status":     token.status,
                "expires_at": token.expires_at,
                "triggered_by": triggered_by,
            },
        )

    def record_refreshed(self, token: "LicenseToken") -> None:
        self._write(
            event_type = "refreshed",
            tenant_id  = token.tenant_id,
            license_id = token.license_id,
            severity   = "info",
            details    = {"plan": token.plan, "status": token.status},
        )

    def record_revoked(self, token: "LicenseToken", revoked_by: str = "system") -> None:
        self._write(
            event_type = "revoked",
            tenant_id  = token.tenant_id,
            license_id = token.license_id,
            severity   = "warning",
            details    = {"revoked_by": revoked_by, "plan": token.plan},
        )

    def record_suspended(self, token: "LicenseToken", suspended_by: str = "system") -> None:
        self._write(
            event_type = "suspended",
            tenant_id  = token.tenant_id,
            license_id = token.license_id,
            severity   = "warning",
            details    = {"suspended_by": suspended_by},
        )

    def record_sig_failure(
        self,
        tenant_id:  str,
        agent_id:   str,
        reason:     str,
        license_id: str = "",
    ) -> None:
        self._write(
            event_type = "sig_failure",
            tenant_id  = tenant_id,
            license_id = license_id,
            severity   = "critical",
            details    = {"agent_id": agent_id, "reason": reason},
        )

    def record_expired_use(
        self,
        tenant_id:  str,
        agent_id:   str,
        license_id: str,
        action_attempted: str = "",
    ) -> None:
        self._write(
            event_type = "expired_use",
            tenant_id  = tenant_id,
            license_id = license_id,
            severity   = "warning",
            details    = {"agent_id": agent_id, "action_attempted": action_attempted},
        )

    def record_sync(
        self,
        tenant_id:   str,
        agent_id:    str,
        license_id:  str,
        reason:      str = "heartbeat",
        updated:     bool = False,
    ) -> None:
        self._write(
            event_type = "sync",
            tenant_id  = tenant_id,
            license_id = license_id,
            severity   = "info",
            details    = {"agent_id": agent_id, "reason": reason, "updated": updated},
        )

    def get_recent(self, limit: int = 100, tenant_id: Optional[str] = None) -> list[dict]:
        """Read recent audit entries from the JSONL file."""
        entries: list[dict] = []
        try:
            if not self._path.exists():
                return []
            lines = self._path.read_text().splitlines()
            for line in reversed(lines):
                if len(entries) >= limit:
                    break
                try:
                    entry = json.loads(line)
                    if tenant_id and entry.get("tenant_id") != tenant_id:
                        continue
                    entries.append(entry)
                except Exception:
                    pass
        except Exception as exc:
            logger.debug("license_audit_log.get_recent: %s", exc)
        return entries

    # ------------------------------------------------------------------
    # Private: write
    # ------------------------------------------------------------------

    def _write(
        self,
        event_type: str,
        tenant_id:  str,
        license_id: str,
        severity:   str,
        details:    dict,
    ) -> None:
        entry = {
            "ts":         time.time(),
            "event_type": event_type,
            "tenant_id":  tenant_id,
            "license_id": license_id,
            "severity":   severity,
            "details":    details,
        }
        # Write to JSONL file (always)
        self._write_jsonl(entry)
        # Write to FrothIQ Event DocType (best-effort)
        self._write_frappe_event(event_type, tenant_id, severity, details)

    def _write_jsonl(self, entry: dict) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with _LOCK:
                with self._path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, default=str) + "\n")
        except Exception as exc:
            logger.warning("license_audit_log: JSONL write failed: %s", exc)

    @staticmethod
    def _write_frappe_event(
        event_type: str,
        tenant_id:  str,
        severity:   str,
        details:    dict,
    ) -> None:
        try:
            import frappe
            event = frappe.new_doc("FrothIQ Event")
            event.tenant      = tenant_id
            event.event_type  = _EVENT_TYPE_MAP.get(event_type, event_type)
            event.severity    = severity
            event.timestamp   = frappe.utils.now_datetime()
            event.raw_payload = json.dumps(details, default=str)
            event.flags.ignore_permissions = True
            event.insert(ignore_permissions=True)
        except Exception:
            pass  # Frappe context not always available; JSONL is the fallback


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

audit_log = LicenseAuditLog()
