# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ License System — Frappe API Layer (Phase 1)

Whitelisted Frappe endpoints for license management.

Access control
--------------
  get_my_license()             — any authenticated FrothIQ tenant user
  get_license(tenant_id)       — FrothIQ Admin or System Manager only
  refresh_license()            — any authenticated FrothIQ tenant user
  revoke_license(tenant_id)    — System Manager only
  suspend_license(tenant_id)   — System Manager or FrothIQ Admin
  verify_license_signature()   — any (validates submitted token)
  sync_license(payload)        — edge agent HMAC-authenticated sync

Tenant isolation:
  Non-admin users can ONLY access their own tenant's license.
  Admin endpoints always require an explicit tenant_id argument.
  No method ever returns another tenant's data to a non-admin caller.
"""

from __future__ import annotations

import frappe

_ADMIN_ROLES  = {"System Manager", "FrothIQ Admin"}
_MANAGER_ROLE = "System Manager"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_admin() -> bool:
    return bool(_ADMIN_ROLES & set(frappe.get_roles()))


def _is_manager() -> bool:
    return _MANAGER_ROLE in frappe.get_roles()


def _require_admin() -> None:
    if not _is_admin():
        frappe.throw("Admin access required.", frappe.PermissionError)


def _require_manager() -> None:
    if not _is_manager():
        frappe.throw("System Manager role required.", frappe.PermissionError)


def _get_my_tenant_id() -> str:
    user = frappe.session.user
    name = frappe.db.get_value("FrothIQ Tenant", {"account_owner": user}, "name")
    if not name:
        frappe.throw(
            "No FrothIQ Tenant account found for your user.",
            frappe.DoesNotExistError,
        )
    return name


def _get_engine():
    from .entitlement_engine import entitlement_engine
    return entitlement_engine


def _get_registry():
    from .license_registry import license_registry
    return license_registry


def _get_issuer():
    from .license_issuer import get_issuer
    return get_issuer()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_my_license() -> dict:
    """
    Return the current license token for the calling tenant.

    Serves from registry cache; triggers a rebuild if stale or missing.

    Response: { license: <token dict>, cached: bool, stale: bool }
    """
    tenant_id = _get_my_tenant_id()
    return _fetch_license(tenant_id, allow_refresh=True)


@frappe.whitelist()
def get_license(tenant_id: str) -> dict:
    """
    Return the license for any tenant. Admin-only.
    """
    _require_admin()
    if not frappe.db.exists("FrothIQ Tenant", tenant_id):
        frappe.throw(f"Tenant {tenant_id!r} not found.", frappe.DoesNotExistError)
    return _fetch_license(tenant_id, allow_refresh=True)


@frappe.whitelist()
def refresh_license() -> dict:
    """
    Force a license refresh for the calling tenant from ERPNext.

    Re-evaluates subscription state and issues a new signed token.
    """
    tenant_id = _get_my_tenant_id()
    try:
        engine = _get_engine()
        token  = engine.refresh_license_state(tenant_id)
        return {
            "ok":      True,
            "license": token.to_public_dict(),
            "message": "License refreshed successfully.",
        }
    except Exception as exc:
        frappe.log_error(f"license_api.refresh_license: {exc}", "License System")
        frappe.throw(f"Failed to refresh license: {exc}")


@frappe.whitelist()
def revoke_license(tenant_id: str) -> dict:
    """
    Revoke a tenant's license. System Manager only.
    Issues an expired tombstone token — edge plugins enter monitor-only mode.
    """
    _require_manager()
    if not frappe.db.exists("FrothIQ Tenant", tenant_id):
        frappe.throw(f"Tenant {tenant_id!r} not found.", frappe.DoesNotExistError)

    engine  = _get_engine()
    success = engine.revoke_license(tenant_id, revoked_by=frappe.session.user)
    return {
        "ok":      success,
        "tenant":  tenant_id,
        "message": "License revoked." if success else "No license found for tenant.",
    }


@frappe.whitelist()
def suspend_license(tenant_id: str) -> dict:
    """
    Suspend a tenant's license. Admin or System Manager.
    Edge plugins enter quarantine mode immediately.
    """
    _require_admin()
    if not frappe.db.exists("FrothIQ Tenant", tenant_id):
        frappe.throw(f"Tenant {tenant_id!r} not found.", frappe.DoesNotExistError)

    engine  = _get_engine()
    success = engine.suspend_license(tenant_id, suspended_by=frappe.session.user)
    return {
        "ok":      success,
        "tenant":  tenant_id,
        "message": "License suspended." if success else "Suspension failed.",
    }


@frappe.whitelist(allow_guest=True)
def verify_license_signature(token_json: str) -> dict:
    """
    Verify the HMAC signature on a submitted LicenseToken JSON string.

    Available to all callers (including unauthenticated). Does NOT reveal
    whether the tenant exists — only confirms cryptographic validity.

    Returns: { valid: bool, reason: str, enforcement_mode: str | null }
    """
    import json as _json
    from .license_issuer import LicenseToken, get_issuer

    try:
        data    = _json.loads(token_json)
        token   = LicenseToken.from_dict(data)
        issuer  = get_issuer()
        valid, reason = issuer.verify_and_check(token)

        # Log signature failure for security monitoring
        if not valid and reason == "signature_invalid":
            from .license_audit_log import audit_log
            audit_log.record_sig_failure(
                tenant_id  = token.tenant_id,
                agent_id   = data.get("agent_id", "unknown"),
                reason     = reason,
                license_id = token.license_id,
            )

        return {
            "valid":            valid,
            "reason":           reason,
            "enforcement_mode": token.enforcement_mode if valid else None,
        }
    except Exception as exc:
        return {"valid": False, "reason": f"parse_error: {exc}", "enforcement_mode": None}


@frappe.whitelist(allow_guest=True)
def sync_license(payload: dict) -> dict:
    """
    Edge plugin heartbeat / license sync endpoint (Phase 4).

    Authenticates the agent by verifying the submitted license signature.
    Returns an updated token if the current registry version is newer.

    Payload:
      { agent_id, tenant_id, current_license_version, request_reason }

    Response:
      { license_token, updated, server_time }
    """
    import time as _time
    from .license_issuer import LicenseToken, get_issuer
    from .license_registry import license_registry
    from .license_audit_log import audit_log

    if isinstance(payload, str):
        import json as _json
        payload = _json.loads(payload)

    agent_id               = str(payload.get("agent_id", ""))
    tenant_id              = str(payload.get("tenant_id", ""))
    current_version        = int(payload.get("current_license_version", 0))
    reason                 = str(payload.get("request_reason", "heartbeat"))

    if not tenant_id:
        frappe.throw("tenant_id is required.", frappe.ValidationError)

    # Retrieve current registry token
    registry = license_registry
    token    = registry.get(tenant_id)

    # Build if not cached
    if token is None:
        try:
            engine = _get_engine()
            token  = engine.build_license_for_tenant(tenant_id)
        except Exception as exc:
            frappe.log_error(f"sync_license: build failed for {tenant_id}: {exc}", "License Sync")
            frappe.throw("License unavailable.", frappe.ValidationError)

    registry_version = registry.get_version(tenant_id)
    updated = registry_version > current_version

    audit_log.record_sync(
        tenant_id  = tenant_id,
        agent_id   = agent_id,
        license_id = token.license_id,
        reason     = reason,
        updated    = updated,
    )

    return {
        "license_token":  token.to_public_dict(),
        "updated":        updated,
        "server_time":    _time.time(),
    }


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _fetch_license(tenant_id: str, allow_refresh: bool = True) -> dict:
    """
    Fetch (and optionally refresh) a license from the registry.
    """
    registry = _get_registry()
    token    = registry.get(tenant_id)
    cached   = token is not None
    stale    = registry.is_stale(tenant_id)

    if (token is None or stale) and allow_refresh:
        try:
            engine = _get_engine()
            token  = engine.refresh_license_state(tenant_id)
            stale  = False
        except Exception as exc:
            frappe.log_error(f"_fetch_license refresh failed for {tenant_id}: {exc}", "License System")
            if token is None:
                frappe.throw(f"No license found for tenant {tenant_id!r}.")

    return {
        "license": token.to_public_dict() if token else None,
        "cached":  cached,
        "stale":   stale,
    }
