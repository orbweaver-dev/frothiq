# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ Frappe Edge Enforcer

Wraps the frothiq-core edge SDK validation pipeline for Frappe/ERPNext
deployments.  Provides:

  FrappeEdgeEnforcer  — validates the current session's tenant license
  before_request()    — Frappe request hook; registers in hooks.py
  require_feature()   — decorator / guard for feature-gated endpoints

Token storage
-------------
  Primary:   Frappe Redis cache  (frappe.cache().get_value / set_value)
  Fallback:  FrothIQ License Record DocType (queried once on cold cache)

Tenant resolution
-----------------
  1. frappe.local.request.headers["X-FrothIQ-Tenant-ID"]  (edge API calls)
  2. frappe.db: FrothIQ Tenant.account_owner == frappe.session.user  (portal)
  3. frappe.conf.frothiq_tenant_id  (single-tenant server installs)

FAIL CLOSED
-----------
  Any validation failure (missing token, bad signature, expired beyond grace,
  suspended / revoked) → quarantine → frappe.PermissionError raised.

Audit
-----
  All quarantine and monitor_only events are written to the FrothIQ Event
  DocType via LicenseAuditBridge (best-effort; never raises).

Registration in hooks.py
------------------------
  before_request = [
      "orbweaver_frothiq.frothiq_portal.edge_enforcement.frappe_enforcer.before_request"
  ]
"""

from __future__ import annotations

import functools
import logging
import os
import time
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Redis cache key helpers
# ---------------------------------------------------------------------------

_CACHE_TOKEN_KEY     = "frothiq_edge_token:{tenant_id}"
_CACHE_TS_KEY        = "frothiq_edge_ts:{tenant_id}"
_CACHE_RESULT_KEY    = "frothiq_edge_result:{tenant_id}"
_CACHE_RESULT_TTL    = 60          # Re-validate result every 60 s
_TOKEN_CACHE_TTL     = 24 * 3600   # Keep raw token in Redis for 24 h

# ---------------------------------------------------------------------------
# Route prefixes that are EXEMPT from license enforcement
# ---------------------------------------------------------------------------

_EXEMPT_PREFIXES: tuple[str, ...] = (
    "/api/method/frappe.",
    "/api/method/login",
    "/api/method/logout",
    "/api/method/orbweaver_frothiq.license_system.license_api.",
    "/api/method/orbweaver_frothiq.frothiq_portal.api.portal_api.",
)


# ---------------------------------------------------------------------------
# FrappeEdgeEnforcer
# ---------------------------------------------------------------------------

class FrappeEdgeEnforcer:
    """
    Per-request Frappe license enforcer.

    Stateless: all state is in Redis cache or the Frappe DB.
    Instantiated once per request in before_request(); long-lived
    singleton use is also supported.

    Parameters
    ----------
    tenant_id   : str   Override auto-resolved tenant
    agent_id    : str   Agent identifier for audit trail
    """

    def __init__(
        self,
        tenant_id: Optional[str] = None,
        agent_id:  str = "",
    ) -> None:
        self._explicit_tenant_id = tenant_id
        self._agent_id           = agent_id or _default_agent_id()

    # ------------------------------------------------------------------
    # Primary API
    # ------------------------------------------------------------------

    def validate(self) -> "LicenseValidationResult":
        """
        Validate the current tenant's license.

        Returns LicenseValidationResult — NEVER raises.

        Result is cached in Redis for _CACHE_RESULT_TTL seconds to avoid
        repeated DB queries on high-traffic installations.
        """
        from frothiq_core.edge_sdk.validator import (
            LicenseValidationResult,
            validate_license_token,
        )

        tenant_id = self._resolve_tenant_id()
        if not tenant_id:
            logger.warning("frappe_enforcer.validate: no tenant_id resolved")
            from frothiq_core.edge_sdk.validator import _QUARANTINE
            from dataclasses import replace
            return replace(_QUARANTINE, reason="tenant_id_not_resolved")

        # --- Check short-lived result cache ---
        import frappe
        cache = frappe.cache()
        cached_result = cache.get_value(_CACHE_RESULT_KEY.format(tenant_id=tenant_id))
        if cached_result and isinstance(cached_result, dict):
            try:
                result = LicenseValidationResult(**cached_result)
                return result
            except Exception:
                pass  # stale cache format — fall through to re-validate

        # --- Load token from Redis (or DocType fallback) ---
        token_json    = self._load_token_json(tenant_id)
        last_valid_ts = self._load_last_valid_ts(tenant_id)
        signing_key   = self._load_signing_key()

        if not signing_key:
            logger.warning("frappe_enforcer: signing key not configured")
            from frothiq_core.edge_sdk.validator import _QUARANTINE
            from dataclasses import replace
            return replace(_QUARANTINE, reason="signing_key_not_configured")

        result = validate_license_token(
            token_json         = token_json,
            signing_key        = signing_key,
            expected_tenant_id = tenant_id,
            cached_token_json  = token_json,
            last_valid_ts      = last_valid_ts if last_valid_ts > 0 else None,
        )

        # --- Update last-valid timestamp on clean validation ---
        if result.valid and result.enforcement_mode == "full_enforcement":
            try:
                self._save_last_valid_ts(tenant_id, time.time())
            except Exception as exc:
                logger.debug("frappe_enforcer: ts update failed: %s", exc)

        # --- Cache result ---
        try:
            cache.set_value(
                _CACHE_RESULT_KEY.format(tenant_id=tenant_id),
                result.to_dict(),
                expires_in_sec=_CACHE_RESULT_TTL,
            )
        except Exception:
            pass

        # --- Emit audit event ---
        self._emit_audit(tenant_id, result)

        return result

    def require_feature(self, feature: str) -> None:
        """
        Raise frappe.PermissionError if the feature is not accessible.

        Decision logic:
          ALLOW          → returns silently
          SOFT_DEGRADE   → logs warning, returns silently (monitor_only)
          HARD_BLOCK     → raises frappe.PermissionError
          UPGRADE_PROMPT → raises frappe.PermissionError with upgrade hint
          FEATURE_LOCKED → raises frappe.PermissionError
        """
        import frappe
        from frothiq_core.edge_sdk.feature_gate import evaluate_feature, GateDecision

        result = self.validate()
        gate   = evaluate_feature(
            enforcement_mode = result.enforcement_mode,
            features         = result.features,
            plan             = result.plan,
            feature          = feature,
        )

        if gate.decision == GateDecision.ALLOW:
            return

        if gate.decision == GateDecision.SOFT_DEGRADE:
            logger.warning(
                "frappe_enforcer: soft degrade for feature=%s tenant=%s reason=%s",
                feature, result.tenant_id, gate.reason,
            )
            return  # Log-only; do not block in monitor_only

        # HARD_BLOCK / UPGRADE_PROMPT / FEATURE_LOCKED → block
        detail = gate.reason
        if gate.upgrade_target:
            detail = f"{gate.reason} (upgrade to {gate.upgrade_target})"

        _emit_feature_blocked(result.tenant_id or self._explicit_tenant_id or "",
                              feature, result.plan, self._agent_id)
        frappe.throw(
            f"License enforcement: {detail}",
            frappe.PermissionError,
            title="Feature Not Available",
        )

    def store_token(self, token_json: str, tenant_id: Optional[str] = None) -> bool:
        """
        Validate and persist a token received from the control center.

        Signature is checked before writing to cache.
        Returns True if stored; False if rejected.
        """
        from frothiq_core.edge_sdk.validator import validate_license_token

        tid = tenant_id or self._resolve_tenant_id()
        if not tid:
            logger.warning("frappe_enforcer.store_token: no tenant_id")
            return False

        signing_key = self._load_signing_key()
        if not signing_key:
            return False

        check = validate_license_token(
            token_json         = token_json,
            signing_key        = signing_key,
            expected_tenant_id = tid,
        )
        if check.enforcement_mode == "quarantine" and check.reason not in (
            "token_expired", "token_expired_offline_grace",
        ):
            logger.warning(
                "frappe_enforcer.store_token: rejected tenant=%s reason=%s",
                tid, check.reason,
            )
            return False

        self._save_token_json(tid, token_json)
        # Invalidate the short-lived result cache so next validate() re-runs
        try:
            import frappe
            frappe.cache().delete_key(_CACHE_RESULT_KEY.format(tenant_id=tid))
        except Exception:
            pass

        logger.info("frappe_enforcer.store_token: stored tenant=%s", tid)
        return True

    # ------------------------------------------------------------------
    # Tenant resolution
    # ------------------------------------------------------------------

    def _resolve_tenant_id(self) -> Optional[str]:
        if self._explicit_tenant_id:
            return self._explicit_tenant_id
        return _resolve_session_tenant_id()

    # ------------------------------------------------------------------
    # Storage helpers  (Redis primary, DocType fallback)
    # ------------------------------------------------------------------

    def _load_token_json(self, tenant_id: str) -> str:
        import frappe

        # 1. Redis
        try:
            val = frappe.cache().get_value(_CACHE_TOKEN_KEY.format(tenant_id=tenant_id))
            if val and isinstance(val, str):
                return val
        except Exception:
            pass

        # 2. FrothIQ License Record DocType fallback
        try:
            token_json = frappe.db.get_value(
                "FrothIQ License Record",
                {"tenant": tenant_id},
                "signed_token_json",
            )
            if token_json:
                # Warm the cache for next call
                try:
                    frappe.cache().set_value(
                        _CACHE_TOKEN_KEY.format(tenant_id=tenant_id),
                        token_json,
                        expires_in_sec=_TOKEN_CACHE_TTL,
                    )
                except Exception:
                    pass
                return token_json
        except Exception as exc:
            logger.debug("frappe_enforcer: doctype token lookup failed: %s", exc)

        return ""

    def _save_token_json(self, tenant_id: str, token_json: str) -> None:
        import frappe

        try:
            frappe.cache().set_value(
                _CACHE_TOKEN_KEY.format(tenant_id=tenant_id),
                token_json,
                expires_in_sec=_TOKEN_CACHE_TTL,
            )
        except Exception as exc:
            logger.warning("frappe_enforcer: cache write failed: %s", exc)

    def _load_last_valid_ts(self, tenant_id: str) -> float:
        import frappe
        try:
            val = frappe.cache().get_value(_CACHE_TS_KEY.format(tenant_id=tenant_id))
            if val is not None:
                return float(val)
        except Exception:
            pass
        return 0.0

    def _save_last_valid_ts(self, tenant_id: str, ts: float) -> None:
        import frappe
        try:
            frappe.cache().set_value(
                _CACHE_TS_KEY.format(tenant_id=tenant_id),
                ts,
                expires_in_sec=_TOKEN_CACHE_TTL,
            )
        except Exception:
            pass

    def _load_signing_key(self) -> Optional[bytes]:
        return _get_signing_key()

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    def _emit_audit(self, tenant_id: str, result: "LicenseValidationResult") -> None:
        if result.enforcement_mode == "quarantine":
            _emit_quarantine(tenant_id, result.reason, self._agent_id)
        elif result.enforcement_mode == "monitor_only":
            _emit_monitor_only(tenant_id, result.reason, self._agent_id)


# ---------------------------------------------------------------------------
# Frappe before_request hook
# ---------------------------------------------------------------------------

def before_request() -> None:
    """
    Frappe before_request hook — validates the current session's license.

    Register in hooks.py:
        before_request = [
            "orbweaver_frothiq.frothiq_portal.edge_enforcement.frappe_enforcer.before_request"
        ]

    Exempt routes (see _EXEMPT_PREFIXES) are skipped to avoid circular
    dependency issues during login, license sync, and framework boot.

    Decision:
      full_enforcement  → proceed normally
      monitor_only      → proceed; emit audit warning
      quarantine        → raise frappe.PermissionError (fail closed)
    """
    import frappe

    try:
        path = _current_request_path()
        if _is_exempt(path):
            return

        # Only enforce on whitelisted method calls and API endpoints
        if not _is_api_request(path):
            return

        tenant_id = _resolve_session_tenant_id()
        if not tenant_id:
            return  # No tenant binding for this session — skip (e.g. System Manager)

        enforcer = FrappeEdgeEnforcer(tenant_id=tenant_id)
        result   = enforcer.validate()

        if result.enforcement_mode == "quarantine":
            logger.warning(
                "before_request: quarantine tenant=%s reason=%s path=%s",
                tenant_id, result.reason, path,
            )
            frappe.throw(
                f"License enforcement: {result.reason}",
                frappe.PermissionError,
                title="License Invalid",
            )

        # monitor_only → logged in validate(); no block

    except frappe.PermissionError:
        raise
    except Exception as exc:
        # FAIL CLOSED — unexpected errors in the hook block the request
        logger.error("before_request: unexpected error: %s", exc)
        raise


# ---------------------------------------------------------------------------
# require_feature decorator
# ---------------------------------------------------------------------------

def require_feature(feature: str) -> Callable:
    """
    Decorator for @frappe.whitelist() methods that require a specific feature.

    Usage:
        @frappe.whitelist()
        @require_feature("defense_mesh")
        def run_defense_scan(...):
            ...

    Raises frappe.PermissionError if the feature gate blocks access.
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            tenant_id = _resolve_session_tenant_id()
            FrappeEdgeEnforcer(tenant_id=tenant_id).require_feature(feature)
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _resolve_session_tenant_id() -> Optional[str]:
    """
    Resolve tenant_id for the current Frappe session.

    Priority:
      1. Request header  X-FrothIQ-Tenant-ID  (edge API / plugin calls)
      2. FrothIQ Tenant record for the current user
      3. frappe.conf.frothiq_tenant_id  (single-tenant installations)
    """
    try:
        import frappe

        # 1. Header (edge plugin / API key auth)
        try:
            hdr = frappe.local.request.headers.get("X-FrothIQ-Tenant-ID", "")
            if hdr:
                return hdr.strip()
        except AttributeError:
            pass  # frappe.local.request may not exist (console / background)

        # 2. User → Tenant lookup
        user = frappe.session.user if frappe.session else None
        if user and user not in ("Guest", "Administrator"):
            tid = frappe.db.get_value(
                "FrothIQ Tenant",
                {"account_owner": user},
                "name",
            )
            if tid:
                return tid

        # 3. Instance-level config
        conf_tid = getattr(frappe.conf, "frothiq_tenant_id", None)
        if conf_tid:
            return conf_tid

    except Exception as exc:
        logger.debug("_resolve_session_tenant_id: %s", exc)

    return None


def _get_signing_key() -> Optional[bytes]:
    """
    Load the HMAC signing key for license verification.

    Source priority:
      1. FROTHIQ_LICENSE_SECRET  environment variable
      2. frappe.conf.frothiq_license_secret
    """
    try:
        secret = os.environ.get("FROTHIQ_LICENSE_SECRET", "")
        if secret:
            return secret.encode("utf-8")

        import frappe
        conf_secret = getattr(frappe.conf, "frothiq_license_secret", "")
        if conf_secret:
            return conf_secret.encode("utf-8")
    except Exception:
        pass
    return None


def _default_agent_id() -> str:
    try:
        import frappe
        return f"frappe:{frappe.conf.get('host_name', 'unknown')}"
    except Exception:
        return "frappe:unknown"


def _current_request_path() -> str:
    try:
        import frappe
        return frappe.local.request.path or ""
    except AttributeError:
        return ""


def _is_exempt(path: str) -> bool:
    if not path:
        return True
    return any(path.startswith(prefix) for prefix in _EXEMPT_PREFIXES)


def _is_api_request(path: str) -> bool:
    return path.startswith("/api/method/") or path.startswith("/api/resource/")


# ---------------------------------------------------------------------------
# Audit helpers  (best-effort; never raise)
# ---------------------------------------------------------------------------

def _emit_quarantine(tenant_id: str, reason: str, agent_id: str) -> None:
    try:
        from orbweaver_frothiq.frothiq_portal.license_control.license_audit_bridge import (
            LicenseAuditBridge,
        )
        LicenseAuditBridge().emit(
            event_type = "suspended",
            tenant_id  = tenant_id,
            license_id = "",
            severity   = "warning",
            details    = {"reason": reason, "enforcement_mode": "quarantine",
                          "agent_id": agent_id},
        )
    except Exception as exc:
        logger.debug("_emit_quarantine: %s", exc)


def _emit_monitor_only(tenant_id: str, reason: str, agent_id: str) -> None:
    try:
        from orbweaver_frothiq.frothiq_portal.license_control.license_audit_bridge import (
            LicenseAuditBridge,
        )
        LicenseAuditBridge().emit(
            event_type = "expired_use",
            tenant_id  = tenant_id,
            license_id = "",
            severity   = "warning",
            details    = {"reason": reason, "enforcement_mode": "monitor_only",
                          "agent_id": agent_id},
        )
    except Exception as exc:
        logger.debug("_emit_monitor_only: %s", exc)


def _emit_feature_blocked(
    tenant_id: str, feature: str, plan: str, agent_id: str
) -> None:
    try:
        from orbweaver_frothiq.frothiq_portal.license_control.license_audit_bridge import (
            LicenseAuditBridge,
        )
        LicenseAuditBridge().emit(
            event_type = "suspended",
            tenant_id  = tenant_id,
            license_id = "",
            severity   = "warning",
            details    = {"feature": feature, "plan": plan, "agent_id": agent_id,
                          "reason": "feature_blocked"},
        )
    except Exception as exc:
        logger.debug("_emit_feature_blocked: %s", exc)
