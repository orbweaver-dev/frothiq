# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ Billing Orchestrator

Bridges ERPNext Subscription state → FrothIQ License lifecycle.

Design contract
---------------
  ERPNext is the source of truth for:
    - Whether a subscription exists and is paid
    - The current plan tier (via Subscription Plan name)
    - Billing status (Active / Cancelled / Paused / Past Due / Unpaid)

  FrothIQ is the source of truth for:
    - Signed license tokens distributed to edge plugins
    - Feature flags and limits per plan
    - Enforcement state (full_enforcement / monitor_only / quarantine)

Idempotency
-----------
  Every sync computes a subscription_hash covering (tenant_id, plan, status,
  features).  If the hash matches the last issued record, the sync is a
  no-op and the cached record is returned unchanged.  This prevents
  redundant re-issuance on every scheduler tick.

ERPNext → FrothIQ status mapping
---------------------------------
  "Active"          → active
  "Trial"           → trial
  "Cancelled"       → revoked
  "Unpaid"          → suspended
  "Past Due"        → suspended
  "Paused"          → suspended
  (no subscription) → active (free plan default)
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Optional

from .license_model import (
    FrothIQLicenseRecord,
    PLAN_FEATURE_MATRIX,
    PLAN_LIMIT_MATRIX,
    LicensePlan,
    LicenseStatus,
)

logger = logging.getLogger(__name__)

# ERPNext Subscription status → FrothIQ license status
_ERPNEXT_STATUS_MAP: dict[str, str] = {
    "Active":    "active",
    "Trial":     "trial",
    "Cancelled": "revoked",
    "Unpaid":    "suspended",
    "Past Due":  "suspended",
    "Paused":    "suspended",
    "Expired":   "expired",
}

# Plan names from ERPNext Subscription Plan → FrothIQ plan tier
_PLAN_NAME_MAP: dict[str, str] = {
    "frothiq free":       "free",
    "frothiq pro":        "pro",
    "frothiq enterprise": "enterprise",
    "free":               "free",
    "pro":                "pro",
    "enterprise":         "enterprise",
}


class BillingOrchestrator:
    """
    Translates ERPNext Subscription state into FrothIQ LicenseRecord events.

    Called by:
      - Frappe scheduler (every 5 min) via sync_all_tenants()
      - ERPNext Subscription doc_event hooks (on_update, on_cancel)
      - Admin UI via LicenseControlCenter

    Never writes to ERPNext — read-only toward the billing source of truth.
    """

    # ------------------------------------------------------------------
    # Public: primary sync entry points
    # ------------------------------------------------------------------

    def sync_tenant(
        self,
        tenant_id:   str,
        force:       bool = False,
    ) -> Optional[FrothIQLicenseRecord]:
        """
        Sync one tenant's ERPNext subscription → FrothIQ license state.

        Returns the (possibly unchanged) FrothIQLicenseRecord, or None
        if the tenant does not exist or sync fails.

        Parameters
        ----------
        tenant_id : str   FrothIQ Tenant docname
        force     : bool  Skip idempotency hash check and always re-issue
        """
        try:
            import frappe
            tenant = frappe.get_doc("FrothIQ Tenant", tenant_id)
        except Exception as exc:
            logger.warning("billing_orchestrator.sync_tenant: tenant %s not found: %s",
                           tenant_id, exc)
            return None

        plan, status = self._resolve_subscription(tenant)
        features     = dict(PLAN_FEATURE_MATRIX.get(plan, PLAN_FEATURE_MATRIX["free"]))

        sub_hash = FrothIQLicenseRecord.compute_subscription_hash(
            tenant_id, plan, status, features
        )

        # Idempotency check — skip if nothing changed
        if not force:
            existing = self._load_existing_record(tenant_id)
            if existing and existing.subscription_hash == sub_hash:
                logger.debug(
                    "billing_orchestrator: tenant=%s unchanged (hash=%s) — skipping",
                    tenant_id, sub_hash[:8],
                )
                return existing

        # Resolve new version counter
        version = self._next_version(tenant_id)

        # Build the new record (unsigned at this layer)
        record = FrothIQLicenseRecord.create(
            tenant_id = tenant_id,
            plan      = plan,
            status    = status,
            version   = version,
        )
        record.subscription_hash = sub_hash

        # Delegate signing + storage to LicenseControlCenter
        from .license_control_center import license_control_center
        try:
            issued_token = license_control_center.issue_license(tenant_id)
            # Stamp the subscription_hash onto the stored record
            record.signature   = issued_token.signature
            record.license_id  = issued_token.license_id

            logger.info(
                "billing_orchestrator: synced tenant=%s plan=%s status=%s v=%d hash=%s",
                tenant_id, plan, status, version, sub_hash[:8],
            )
            return record
        except Exception as exc:
            logger.error(
                "billing_orchestrator: issue_license failed for tenant=%s: %s",
                tenant_id, exc,
            )
            return None

    def sync_all_tenants(self) -> dict:
        """
        Sync all FrothIQ Tenants. Called by the Frappe scheduler every 5 min.

        Returns { synced: N, skipped: N, failed: N }.
        """
        try:
            import frappe
            tenants = frappe.get_all("FrothIQ Tenant", fields=["name"])
        except Exception as exc:
            logger.error("billing_orchestrator.sync_all_tenants: %s", exc)
            return {"synced": 0, "skipped": 0, "failed": 0}

        synced = skipped = failed = 0
        for row in tenants:
            try:
                result = self.sync_tenant(row["name"])
                if result:
                    synced += 1
                else:
                    skipped += 1
            except Exception as exc:
                logger.warning("billing_orchestrator: sync failed for %s: %s", row["name"], exc)
                failed += 1

        logger.info("billing_orchestrator.sync_all: synced=%d skipped=%d failed=%d",
                    synced, skipped, failed)
        return {"synced": synced, "skipped": skipped, "failed": failed}

    def on_subscription_updated(self, subscription_name: str) -> None:
        """
        Hook triggered by ERPNext Subscription.on_update.

        Finds the FrothIQ Tenant linked to this subscription and syncs.
        """
        tenant_id = self._find_tenant_by_subscription(subscription_name)
        if tenant_id:
            self.sync_tenant(tenant_id, force=True)

    def on_subscription_cancelled(self, subscription_name: str) -> None:
        """
        Hook triggered by ERPNext Subscription.on_cancel.

        Immediately revokes the tenant's license.
        """
        tenant_id = self._find_tenant_by_subscription(subscription_name)
        if tenant_id:
            from .license_control_center import license_control_center
            license_control_center.revoke_license(tenant_id)
            logger.info(
                "billing_orchestrator: revoked license for tenant=%s "
                "(subscription %s cancelled)",
                tenant_id, subscription_name,
            )

    def on_payment_failed(self, subscription_name: str) -> None:
        """
        Hook triggered on payment failure.

        Immediately suspends the tenant's license → quarantine mode.
        """
        tenant_id = self._find_tenant_by_subscription(subscription_name)
        if tenant_id:
            from .license_control_center import license_control_center
            license_control_center.suspend_license(tenant_id)
            logger.info(
                "billing_orchestrator: suspended license for tenant=%s "
                "(payment failed on subscription %s)",
                tenant_id, subscription_name,
            )

    # ------------------------------------------------------------------
    # Private: ERPNext resolution
    # ------------------------------------------------------------------

    def _resolve_subscription(self, tenant) -> tuple[str, str]:
        """
        Determine (plan, status) from the tenant's ERPNext subscription.

        Falls back to (free, active) if no subscription is linked or
        ERPNext is unavailable.
        """
        try:
            import frappe
            tenant_plan   = (getattr(tenant, "plan",   None) or "free").lower()
            tenant_status = (getattr(tenant, "status", None) or "active").lower()

            # Map Frappe tenant status
            if tenant_status in ("inactive", "banned"):
                return tenant_plan, "suspended"
            if tenant_status == "suspended":
                return tenant_plan, "suspended"

            # Cross-check ERPNext Subscription if linked
            sub_name = getattr(tenant, "subscription", None)
            if sub_name and self._erpnext_available():
                sub = frappe.db.get_value(
                    "Subscription", sub_name, ["status"], as_dict=True
                )
                if sub:
                    frothiq_status = _ERPNEXT_STATUS_MAP.get(sub.status, "active")
                    # ERPNext plan from subscription plans table
                    plan_rows = frappe.db.get_all(
                        "Subscription Plan Detail",
                        filters={"parent": sub_name},
                        fields=["plan"],
                        limit=1,
                    )
                    if plan_rows:
                        erpnext_plan_name = (plan_rows[0].plan or "").lower()
                        mapped = _PLAN_NAME_MAP.get(erpnext_plan_name)
                        if mapped:
                            tenant_plan = mapped
                    return tenant_plan, frothiq_status

            # No ERPNext subscription — use tenant doc status
            status_map = {"trial": "trial", "active": "active", "suspended": "suspended"}
            return tenant_plan, status_map.get(tenant_status, "active")

        except Exception as exc:
            logger.warning(
                "billing_orchestrator._resolve_subscription: failed for %s: %s — "
                "defaulting to free/active",
                getattr(tenant, "name", "?"), exc,
            )
            return "free", "active"

    @staticmethod
    def _erpnext_available() -> bool:
        try:
            import frappe
            return bool(
                frappe.db.exists("DocType", "Subscription") and
                frappe.db.exists("DocType", "Customer")
            )
        except Exception:
            return False

    @staticmethod
    def _find_tenant_by_subscription(subscription_name: str) -> Optional[str]:
        try:
            import frappe
            return frappe.db.get_value(
                "FrothIQ Tenant", {"subscription": subscription_name}, "name"
            )
        except Exception:
            return None

    @staticmethod
    def _load_existing_record(tenant_id: str) -> Optional[FrothIQLicenseRecord]:
        """Load the most recent FrothIQLicenseRecord for a tenant from Frappe DB."""
        try:
            import frappe
            doc = frappe.db.get_value(
                "FrothIQ License Record",
                {"tenant_id": tenant_id},
                ["license_id", "tenant_id", "plan", "status", "issued_at",
                 "expires_at", "version", "subscription_hash", "signature",
                 "public_fingerprint"],
                as_dict=True,
                order_by="issued_at desc",
            )
            if not doc:
                return None
            return FrothIQLicenseRecord.from_dict(doc)
        except Exception:
            return None

    @staticmethod
    def _next_version(tenant_id: str) -> int:
        """Return the next version counter for a tenant."""
        try:
            import frappe
            rows = frappe.db.get_all(
                "FrothIQ License Record",
                filters={"tenant_id": tenant_id},
                fields=["version"],
                order_by="version desc",
                limit=1,
            )
            return (rows[0].version + 1) if rows else 1
        except Exception:
            return 1


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

billing_orchestrator = BillingOrchestrator()
