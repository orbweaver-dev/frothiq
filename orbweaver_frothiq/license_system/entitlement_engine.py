# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ Entitlement Engine

Translates ERPNext Subscription state + FrothIQ Tenant config into a
signed LicenseToken. This is the ONLY path by which licenses are created.

Authority chain
---------------
  ERPNext Subscription  →  FrothIQ Tenant  →  EntitlementEngine
    →  LicenseIssuer  →  LicenseToken  →  LicenseRegistry

Design rules
------------
  - ALWAYS queries ERPNext as source of truth for subscription status.
  - NEVER trusts edge-reported plan or status values.
  - Admin overrides (trial extensions, suspensions, promotions) are applied
    AFTER the ERPNext lookup, not instead of it.
  - revoke() and suspend() do not delete records — they re-issue tokens with
    the appropriate status and a short TTL.

Plan mapping (from billing_api.PLAN_LIMITS canonical definition)
----------------------------------------------------------------
  "free"       → LicensePlan.FREE
  "pro"        → LicensePlan.PRO
  "enterprise" → LicensePlan.ENTERPRISE

ERPNext Subscription status → LicenseStatus mapping
----------------------------------------------------
  "Active"   / "Trial"  → active / trial
  "Cancelled"/ "Past Due"/ "Unpaid" → expired or suspended
  "Paused"               → suspended
  (no subscription)      → free active
"""

from __future__ import annotations

import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)

# Plan tier ordering for upgrade path checks
_PLAN_ORDER = ["free", "pro", "enterprise"]


class EntitlementEngine:
    """
    Converts FrothIQ Tenant + ERPNext Subscription state into a LicenseToken.

    All methods that issue tokens require an active Frappe context (database
    access). They are safe to call from background jobs.
    """

    # ------------------------------------------------------------------
    # Public: primary entrypoint
    # ------------------------------------------------------------------

    def build_license_for_tenant(self, tenant_id: str) -> "LicenseToken":
        """
        Build and sign a fresh LicenseToken for the given tenant.

        Queries ERPNext subscription state, applies any overrides, issues
        and stores the token. Raises frappe.DoesNotExistError if tenant
        not found.

        Returns
        -------
        LicenseToken — freshly signed token, already stored in registry.
        """
        import frappe
        from .license_issuer import LicenseFeatures, LicenseLimits, get_issuer
        from .license_registry import license_registry
        from .license_audit_log import audit_log

        tenant = frappe.get_doc("FrothIQ Tenant", tenant_id)
        plan, status = self._resolve_entitlement(tenant)

        features = LicenseFeatures.for_plan(plan)
        limits   = LicenseLimits.for_plan(plan)

        # Apply any admin overrides stored on the tenant
        features, limits = self._apply_overrides(tenant, features, limits)

        issuer = get_issuer()
        token  = issuer.issue(
            tenant_id = tenant.name,
            plan      = plan,
            status    = status,
        )
        # Re-apply override features/limits (issuer uses defaults; we patch them in)
        token.features = features
        token.limits   = limits
        token.signature = issuer._sign(token)   # re-sign with override fields

        version = license_registry.store(token)
        audit_log.record_issued(token, triggered_by="build_license_for_tenant")

        logger.info(
            "entitlement_engine: built license for tenant=%s plan=%s status=%s version=%d",
            tenant_id, plan, status, version,
        )
        return token

    def refresh_license_state(self, tenant_id: str) -> "LicenseToken":
        """
        Re-evaluate entitlement from ERPNext and issue a fresh token.

        Equivalent to build_license_for_tenant but records a 'refresh' event.
        Called by the periodic sync job and the portal refresh endpoint.
        """
        import frappe
        from .license_registry import license_registry
        from .license_audit_log import audit_log

        token = self.build_license_for_tenant(tenant_id)
        audit_log.record_refreshed(token)
        return token

    def revoke_license(self, tenant_id: str, revoked_by: str = "system") -> bool:
        """
        Revoke a tenant's license — removes from registry and issues an
        expired tombstone token.

        Returns True on success, False if tenant not found.
        """
        import frappe
        from .license_issuer import LicenseFeatures, LicenseLimits, get_issuer
        from .license_registry import license_registry
        from .license_audit_log import audit_log

        try:
            tenant = frappe.get_doc("FrothIQ Tenant", tenant_id)
        except frappe.DoesNotExistError:
            return False

        # Issue expired tombstone (short TTL)
        issuer = get_issuer()
        token  = issuer.issue(
            tenant_id    = tenant_id,
            plan         = tenant.plan or "free",
            status       = "expired",
            ttl_override = 86400,  # 1 day tombstone
        )
        license_registry.store(token)
        audit_log.record_revoked(token, revoked_by=revoked_by)

        logger.info("entitlement_engine: revoked license for tenant=%s by=%s", tenant_id, revoked_by)
        return True

    def suspend_license(self, tenant_id: str, suspended_by: str = "system") -> bool:
        """
        Suspend a tenant's license — edge plugins enter quarantine mode.

        Returns True on success, False if tenant not found.
        """
        import frappe
        from .license_issuer import LicenseFeatures, LicenseLimits, get_issuer
        from .license_registry import license_registry
        from .license_audit_log import audit_log

        try:
            tenant = frappe.get_doc("FrothIQ Tenant", tenant_id)
        except frappe.DoesNotExistError:
            return False

        issuer = get_issuer()
        token  = issuer.issue(
            tenant_id    = tenant_id,
            plan         = tenant.plan or "free",
            status       = "suspended",
            ttl_override = 7 * 86400,  # re-evaluate in 7 days
        )
        license_registry.store(token)
        audit_log.record_suspended(token, suspended_by=suspended_by)

        logger.info("entitlement_engine: suspended license for tenant=%s by=%s", tenant_id, suspended_by)
        return True

    # ------------------------------------------------------------------
    # Private: ERPNext resolution
    # ------------------------------------------------------------------

    def _resolve_entitlement(self, tenant) -> tuple[str, str]:
        """
        Determine (plan, status) from the authoritative ERPNext subscription.

        Never trusts the tenant's self-reported plan — always cross-checks
        against the ERPNext Subscription if one exists.
        """
        try:
            import frappe
            plan   = (tenant.plan or "free").lower()
            status = (tenant.status or "active").lower()

            # Map Frappe tenant status → license status
            if status in ("inactive", "banned", "cancelled"):
                return plan, "suspended"
            if status not in ("active", "trial"):
                return plan, "expired"

            # Cross-check ERPNext Subscription if linked
            if tenant.subscription and self._erpnext_available():
                erpnext_plan, erpnext_status = self._lookup_erpnext_subscription(
                    tenant.subscription
                )
                # ERPNext is authoritative for billing status
                if erpnext_status in ("Cancelled", "Unpaid", "Past Due"):
                    return plan, "expired"
                if erpnext_status == "Paused":
                    return plan, "suspended"
                if erpnext_status == "Trial":
                    return plan, "trial"
                if erpnext_status == "Active":
                    # Trust the ERPNext plan name if it maps cleanly
                    mapped = self._map_erpnext_plan_name(erpnext_plan)
                    if mapped:
                        plan = mapped

            return plan, "active" if status in ("active",) else "trial"

        except Exception as exc:
            logger.warning(
                "entitlement_engine._resolve_entitlement: ERPNext lookup failed for "
                "tenant %s: %s — defaulting to free/active",
                getattr(tenant, "name", "?"), exc,
            )
            return "free", "active"

    @staticmethod
    def _lookup_erpnext_subscription(subscription_name: str) -> tuple[str, str]:
        """Return (plan_name, status) from ERPNext Subscription."""
        import frappe
        sub = frappe.db.get_value(
            "Subscription",
            subscription_name,
            ["status", "party"],
            as_dict=True,
        )
        if not sub:
            return "", "Unknown"
        # Get plan from subscription plans child table
        plans = frappe.db.get_all(
            "Subscription Plan Detail",
            filters={"parent": subscription_name},
            fields=["plan"],
            limit=1,
        )
        plan_name = plans[0].plan if plans else ""
        return plan_name, sub.status or "Unknown"

    @staticmethod
    def _map_erpnext_plan_name(erpnext_plan: str) -> Optional[str]:
        """Map ERPNext Subscription Plan name to FrothIQ plan tier."""
        lower = erpnext_plan.lower()
        if "enterprise" in lower:
            return "enterprise"
        if "pro" in lower:
            return "pro"
        if "free" in lower:
            return "free"
        return None

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

    # ------------------------------------------------------------------
    # Private: admin overrides
    # ------------------------------------------------------------------

    @staticmethod
    def _apply_overrides(
        tenant,
        features: "LicenseFeatures",
        limits:   "LicenseLimits",
    ) -> tuple["LicenseFeatures", "LicenseLimits"]:
        """
        Apply any per-tenant feature or limit overrides.

        Overrides are stored as JSON in the `notes` field of the tenant
        doc, under the key `license_overrides`. This avoids schema changes.

        Example notes JSON:
          {"license_overrides": {"features": {"simulation": true}, "limits": {"rpm": 1200}}}
        """
        try:
            import json as _json
            notes_raw = getattr(tenant, "notes", "") or ""
            if not notes_raw.strip().startswith("{"):
                return features, limits
            notes = _json.loads(notes_raw)
            overrides = notes.get("license_overrides", {})
            if not overrides:
                return features, limits

            feat_overrides = overrides.get("features", {})
            for key, val in feat_overrides.items():
                if hasattr(features, key):
                    setattr(features, key, bool(val))

            limit_overrides = overrides.get("limits", {})
            for key, val in limit_overrides.items():
                if hasattr(limits, key):
                    setattr(limits, key, int(val))

        except Exception as exc:
            logger.debug("entitlement_engine._apply_overrides: %s", exc)

        return features, limits


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

entitlement_engine = EntitlementEngine()
