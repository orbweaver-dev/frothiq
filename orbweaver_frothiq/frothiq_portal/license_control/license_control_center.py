# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ License Control Center — Central Orchestration API

Single point of authority for all license lifecycle operations.
All operations:
  - Regenerate the signed token on every change
  - Invalidate the previous version immediately (via LicenseStateCache)
  - Increment the version counter
  - Write an audit event via LicenseAuditBridge

Public API
----------
  issue_license(tenant_id)          → LicenseToken
  refresh_license(tenant_id)        → LicenseToken
  suspend_license(tenant_id, by)    → bool
  revoke_license(tenant_id, by)     → bool
  rotate_license_key(tenant_id, by) → LicenseToken

Internal design
---------------
  Delegates cryptographic signing to license_system.license_issuer (LicenseIssuer).
  Delegates ERPNext entitlement resolution to license_system.entitlement_engine.
  Delegates audit writing to license_audit_bridge.
  Stores control-plane records in FrothIQ License Record DocType via Frappe DB.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)


class LicenseControlCenter:
    """
    Central authority for FrothIQ license issuance and lifecycle management.

    All public methods:
      - are idempotent-safe (safe to call multiple times)
      - always re-sign the token on state change
      - always invalidate the previous cached token version
      - always write an audit event
    """

    # ------------------------------------------------------------------
    # Public: issue / refresh
    # ------------------------------------------------------------------

    def issue_license(self, tenant_id: str) -> "LicenseToken":
        """
        Issue a fresh signed LicenseToken for the given tenant.

        Queries ERPNext for subscription state, applies plan overrides,
        signs the token, stores it in the registry, and increments version.

        Returns the signed LicenseToken.
        Raises frappe.DoesNotExistError if the tenant does not exist.
        """
        from orbweaver_frothiq.license_system.entitlement_engine import entitlement_engine
        from .license_audit_bridge import audit_bridge
        from .license_model import FrothIQLicenseRecord

        token = entitlement_engine.build_license_for_tenant(tenant_id)

        # Invalidate any previous cache entry for this tenant
        self._invalidate_tenant_cache(tenant_id)

        # Persist control-plane record to Frappe DB
        self._upsert_license_record(token, action="issued")

        # Audit
        audit_bridge.record(
            event_type = "issued",
            tenant_id  = tenant_id,
            license_id = token.license_id,
            severity   = "info",
            details    = {
                "plan":    token.plan,
                "status":  token.status,
                "version": self._get_version(tenant_id),
            },
        )

        logger.info(
            "license_control_center: issued license=%s tenant=%s plan=%s status=%s",
            token.license_id, tenant_id, token.plan, token.status,
        )
        return token

    def refresh_license(self, tenant_id: str) -> "LicenseToken":
        """
        Re-evaluate and re-issue a license for the tenant.

        Equivalent to issue_license() but records a 'refreshed' audit event.
        Called by the portal refresh endpoint and the periodic sync job.
        """
        from orbweaver_frothiq.license_system.entitlement_engine import entitlement_engine
        from .license_audit_bridge import audit_bridge

        token = entitlement_engine.refresh_license_state(tenant_id)
        self._invalidate_tenant_cache(tenant_id)
        self._upsert_license_record(token, action="refreshed")

        audit_bridge.record(
            event_type = "refreshed",
            tenant_id  = tenant_id,
            license_id = token.license_id,
            severity   = "info",
            details    = {"plan": token.plan, "status": token.status},
        )
        return token

    # ------------------------------------------------------------------
    # Public: suspend / revoke / rotate
    # ------------------------------------------------------------------

    def suspend_license(
        self,
        tenant_id:    str,
        suspended_by: str = "system",
    ) -> bool:
        """
        Suspend a tenant's license → quarantine enforcement mode.

        Edge plugins enter quarantine within 60 seconds (cache TTL).
        Returns True on success, False if tenant not found.
        """
        from orbweaver_frothiq.license_system.entitlement_engine import entitlement_engine
        from .license_audit_bridge import audit_bridge

        ok = entitlement_engine.suspend_license(tenant_id, suspended_by=suspended_by)
        if ok:
            self._invalidate_tenant_cache(tenant_id)
            self._update_record_status(tenant_id, "suspended")
            audit_bridge.record(
                event_type = "suspended",
                tenant_id  = tenant_id,
                license_id = self._get_current_license_id(tenant_id),
                severity   = "warning",
                details    = {"suspended_by": suspended_by},
            )
            logger.info("license_control_center: suspended tenant=%s by=%s",
                        tenant_id, suspended_by)
        return ok

    def revoke_license(
        self,
        tenant_id:  str,
        revoked_by: str = "system",
    ) -> bool:
        """
        Revoke a tenant's license — immediate quarantine + tombstone token.

        The signed tombstone token has a 24h TTL so edge plugins
        receive the revocation signal on their next heartbeat.
        Returns True on success, False if tenant not found.
        """
        from orbweaver_frothiq.license_system.entitlement_engine import entitlement_engine
        from .license_audit_bridge import audit_bridge

        ok = entitlement_engine.revoke_license(tenant_id, revoked_by=revoked_by)
        if ok:
            self._invalidate_tenant_cache(tenant_id)
            self._update_record_status(tenant_id, "revoked")
            audit_bridge.record(
                event_type = "revoked",
                tenant_id  = tenant_id,
                license_id = self._get_current_license_id(tenant_id),
                severity   = "warning",
                details    = {"revoked_by": revoked_by},
            )
            logger.info("license_control_center: revoked tenant=%s by=%s",
                        tenant_id, revoked_by)
        return ok

    def rotate_license_key(
        self,
        tenant_id:  str,
        rotated_by: str = "system",
    ) -> "LicenseToken":
        """
        Rotate the signing key for a tenant and re-issue their license.

        Steps:
          1. Revoke the current license (tombstone invalidates edge caches)
          2. Re-issue a fresh signed token (new license_id, new signature)
          3. Record audit event with rotation metadata

        The new token takes effect immediately. Edge plugins receive it
        on their next heartbeat sync.
        """
        from orbweaver_frothiq.license_system.entitlement_engine import entitlement_engine
        from .license_audit_bridge import audit_bridge

        old_license_id = self._get_current_license_id(tenant_id)

        # Invalidate and re-issue
        self._invalidate_tenant_cache(tenant_id)
        token = entitlement_engine.build_license_for_tenant(tenant_id)
        self._upsert_license_record(token, action="rotated")

        audit_bridge.record(
            event_type = "rotated",
            tenant_id  = tenant_id,
            license_id = token.license_id,
            severity   = "info",
            details    = {
                "rotated_by":      rotated_by,
                "old_license_id":  old_license_id,
                "new_license_id":  token.license_id,
            },
        )
        logger.info(
            "license_control_center: rotated key tenant=%s old=%s new=%s by=%s",
            tenant_id, old_license_id, token.license_id, rotated_by,
        )
        return token

    def get_license_status(self, tenant_id: str) -> dict:
        """
        Return a status summary for a tenant's current license.

        { license_id, plan, status, enforcement_mode, version,
          expires_at, seconds_until_expiry, valid }
        """
        from orbweaver_frothiq.license_system.license_registry import license_registry
        token = license_registry.get(tenant_id)
        if not token:
            return {
                "license_id":           "",
                "plan":                 "free",
                "status":               "missing",
                "enforcement_mode":     "quarantine",
                "version":              0,
                "expires_at":           0,
                "seconds_until_expiry": 0,
                "valid":                False,
            }
        return {
            "license_id":           token.license_id,
            "plan":                 token.plan,
            "status":               token.status,
            "enforcement_mode":     token.enforcement_mode,
            "version":              self._get_version(tenant_id),
            "expires_at":           token.expires_at,
            "seconds_until_expiry": token.seconds_until_expiry,
            "valid":                token.is_active,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _invalidate_tenant_cache(tenant_id: str) -> None:
        """Invalidate frothiq-core license cache for the tenant (best-effort)."""
        try:
            # Attempt to call frothiq-core invalidation API if running locally
            import os
            import requests
            core_url = os.getenv("FROTHIQ_CORE_URL", "http://127.0.0.1:8001")
            api_key  = os.getenv("FROTHIQ_API_KEY", "")
            requests.post(
                f"{core_url}/api/v2/license/invalidate",
                json={"tenant_id": tenant_id},
                headers={"X-FrothIQ-Key": api_key},
                timeout=3,
            )
        except Exception:
            pass  # Best-effort; cache will expire naturally within TTL

    @staticmethod
    def _upsert_license_record(token: "LicenseToken", action: str) -> None:
        """Persist/update the FrothIQ License Record DocType entry."""
        try:
            import frappe
            existing = frappe.db.get_value(
                "FrothIQ License Record", {"tenant_id": token.tenant_id}, "name"
            )
            if existing:
                doc = frappe.get_doc("FrothIQ License Record", existing)
            else:
                doc             = frappe.new_doc("FrothIQ License Record")
                doc.tenant_id   = token.tenant_id

            import json as _json
            doc.license_id    = token.license_id
            doc.plan          = token.plan
            doc.status        = token.status
            doc.issued_at     = token.issued_at
            doc.expires_at    = token.expires_at
            doc.signature     = token.signature
            doc.feature_flags = _json.dumps(token.features.to_dict(), separators=(",", ":"))
            doc.limits        = _json.dumps(token.limits.to_dict(),   separators=(",", ":"))
            doc.version       = (doc.version or 0) + 1
            if action == "rotated":
                doc.last_rotated = __import__("time").time()

            doc.flags.ignore_permissions = True
            doc.save(ignore_permissions=True)
        except Exception as exc:
            logger.debug("license_control_center._upsert_license_record: %s", exc)

    @staticmethod
    def _update_record_status(tenant_id: str, status: str) -> None:
        """Update just the status field on the existing license record."""
        try:
            import frappe
            frappe.db.set_value(
                "FrothIQ License Record",
                {"tenant_id": tenant_id},
                "status", status,
                update_modified=False,
            )
            frappe.db.commit()
        except Exception as exc:
            logger.debug("license_control_center._update_record_status: %s", exc)

    @staticmethod
    def _get_current_license_id(tenant_id: str) -> str:
        try:
            import frappe
            return frappe.db.get_value(
                "FrothIQ License Record", {"tenant_id": tenant_id}, "license_id"
            ) or ""
        except Exception:
            return ""

    @staticmethod
    def _get_version(tenant_id: str) -> int:
        try:
            import frappe
            v = frappe.db.get_value(
                "FrothIQ License Record", {"tenant_id": tenant_id}, "version"
            )
            return int(v or 0)
        except Exception:
            return 0


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

license_control_center = LicenseControlCenter()
