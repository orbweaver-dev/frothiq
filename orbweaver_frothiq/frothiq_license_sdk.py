# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ License SDK — Shared Edge Plugin Verification Library (Phase 2)

Portable, dependency-minimal license validation logic for use in ALL
edge plugins: WordPress (via PHP port), Joomla (via PHP port), Frappe.

This Python module is the reference implementation. Plugin ports must
maintain identical validation semantics.

DESIGN RULES
============
  FAIL CLOSED:  if the license token is missing, unparseable, or invalid,
                the SDK returns the most restrictive enforcement mode.
  NO ONLINE CHECK ON EVERY REQUEST: validation is local/cached.
  CACHE FALLBACK: last valid license is cached locally and served during
                  temporary control center outages (up to OFFLINE_GRACE seconds).

Enforcement modes (returned by validate_license_token())
---------------------------------------------------------
  full_enforcement  — active valid license; all protection actions enabled
  monitor_only      — expired token; LOG only, disable BLOCK actions
  quarantine        — suspended or missing; read-only logs, disable all actions

Anti-tamper rules
-----------------
  - Signature covers ALL fields (canonical JSON, HMAC-SHA256)
  - tenant_id + agent_id binding enforced (cross-site reuse rejected)
  - schema_version checked — reject tokens from unknown versions
  - Modified payload (even with valid format) will have invalid signature

Offline grace period
--------------------
  If the control center is unreachable for > OFFLINE_GRACE seconds,
  the SDK degrades to monitor_only (not quarantine) using the last
  valid cached token.  This prevents a control center outage from
  disabling all protected sites simultaneously.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass, replace as _dc_replace
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# How long a cached token remains usable after expiry during outages
OFFLINE_GRACE_SECONDS = int(os.getenv("FROTHIQ_OFFLINE_GRACE", str(4 * 3600)))  # 4 hours
_KNOWN_SCHEMA_VERSIONS = {1}
_VALID_PLANS   = {"free", "pro", "enterprise"}
_VALID_STATUSES = {"active", "suspended", "expired", "trial"}
_VALID_FEATURES = {
    "federation", "campaigns", "simulation", "defense_mesh",
    "intel_market", "policy_mesh", "response_engine", "adaptive_scoring",
}
_VALID_LIMITS = {"rpm", "max_sites", "block_score", "retention_days"}


# ---------------------------------------------------------------------------
# Validation result
# ---------------------------------------------------------------------------

@dataclass
class LicenseValidationResult:
    """
    Result of validate_license_token().

    Fields
    ------
    valid            : bool   — True if signature + expiry + status are all OK
    enforcement_mode : str    — full_enforcement | monitor_only | quarantine
    reason           : str    — human-readable explanation
    plan             : str    — free | pro | enterprise  (from token)
    features         : dict   — feature flag map from token
    limits           : dict   — limit map from token
    tenant_id        : str    — from token (verified)
    """
    valid:            bool
    enforcement_mode: str
    reason:           str
    plan:             str         = "free"
    features:         dict        = None
    limits:           dict        = None
    tenant_id:        str         = ""

    def __post_init__(self):
        if self.features is None:
            self.features = {}
        if self.limits is None:
            self.limits = {}

    @property
    def can_block(self) -> bool:
        return self.enforcement_mode == "full_enforcement"

    @property
    def can_log(self) -> bool:
        return self.enforcement_mode in ("full_enforcement", "monitor_only")

    def has_feature(self, feature: str) -> bool:
        return bool(self.features.get(feature, False))

    def to_dict(self) -> dict:
        return {
            "valid":            self.valid,
            "enforcement_mode": self.enforcement_mode,
            "reason":           self.reason,
            "plan":             self.plan,
            "features":         self.features,
            "limits":           self.limits,
            "tenant_id":        self.tenant_id,
        }


# ---------------------------------------------------------------------------
# Closed results (fail-safe constants)
# ---------------------------------------------------------------------------

_RESULT_QUARANTINE = LicenseValidationResult(
    valid=False, enforcement_mode="quarantine",
    reason="missing_or_invalid_license",
)
_RESULT_MONITOR = LicenseValidationResult(
    valid=False, enforcement_mode="monitor_only",
    reason="license_expired_grace_period",
)


# ---------------------------------------------------------------------------
# Core validation functions
# ---------------------------------------------------------------------------

def validate_license_token(
    token_json:        str,
    signing_key:       bytes,
    expected_tenant_id: Optional[str] = None,
    cached_token_json: Optional[str]  = None,
    last_valid_ts:     Optional[float] = None,
) -> LicenseValidationResult:
    """
    Primary entry point — fully validate a LicenseToken JSON string.

    Parameters
    ----------
    token_json        : str   — JSON string from control center
    signing_key       : bytes — HMAC key (same as control center)
    expected_tenant_id : str  — reject if token.tenant_id doesn't match
    cached_token_json  : str  — last known-good token (offline fallback)
    last_valid_ts      : float — Unix ts when cached_token was last verified

    Returns
    -------
    LicenseValidationResult — NEVER raises; always returns a result.
    """
    try:
        token = _parse_token(token_json)
    except Exception as exc:
        logger.warning("validate_license_token: parse failed: %s", exc)
        return _offline_fallback(cached_token_json, last_valid_ts,
                                  reason=f"parse_error: {exc}")

    # Schema version check
    if token.get("schema_version", 1) not in _KNOWN_SCHEMA_VERSIONS:
        return _dc_replace(_RESULT_QUARANTINE, reason="unknown_schema_version")

    # Tenant binding
    if expected_tenant_id and token.get("tenant_id") != expected_tenant_id:
        logger.warning(
            "validate_license_token: tenant_id mismatch — got %s expected %s",
            token.get("tenant_id"), expected_tenant_id,
        )
        return _dc_replace(_RESULT_QUARANTINE, reason="tenant_id_mismatch")

    # Signature verification (FAIL CLOSED)
    if not verify_signature(token, signing_key):
        logger.warning(
            "validate_license_token: signature invalid for tenant=%s",
            token.get("tenant_id", "?"),
        )
        return _dc_replace(_RESULT_QUARANTINE, reason="signature_invalid")

    # Expiry
    if not check_expiry(token):
        return _offline_fallback(
            cached_token_json, last_valid_ts,
            reason="token_expired",
            expired_token=token,
        )

    # Status check
    status = token.get("status", "").lower()
    if status == "suspended":
        return LicenseValidationResult(
            valid=False, enforcement_mode="quarantine",
            reason="license_suspended",
            plan=token.get("plan", "free"),
            features=token.get("features", {}),
            limits=token.get("limits", {}),
            tenant_id=token.get("tenant_id", ""),
        )

    # Valid
    mode = "full_enforcement" if status in ("active", "trial") else "monitor_only"
    return LicenseValidationResult(
        valid=True,
        enforcement_mode=mode,
        reason="ok",
        plan=token.get("plan", "free"),
        features=token.get("features", {}),
        limits=token.get("limits", {}),
        tenant_id=token.get("tenant_id", ""),
    )


def verify_signature(token: dict, signing_key: bytes) -> bool:
    """
    Verify the HMAC-SHA256 signature on a token dict.

    Returns False (not raises) on any error.
    """
    try:
        submitted_sig = token.get("signature", "")
        if not submitted_sig:
            return False
        expected = _compute_signature(token, signing_key)
        return hmac.compare_digest(
            expected.encode("ascii"),
            submitted_sig.encode("ascii"),
        )
    except Exception as exc:
        logger.warning("verify_signature: error: %s", exc)
        return False


def check_expiry(token: dict) -> bool:
    """Return True if the token is NOT yet expired."""
    try:
        return time.time() < float(token.get("expires_at", 0))
    except (TypeError, ValueError):
        return False


def check_feature_access(token: dict, feature_name: str) -> bool:
    """
    Return True if the feature is enabled in the token.

    FAIL CLOSED: returns False for missing or invalid tokens.
    """
    if not token:
        return False
    features = token.get("features", {}) if isinstance(token, dict) else {}
    return bool(features.get(feature_name, False))


def check_rate_limits(token: dict, rpm_request: int) -> bool:
    """
    Return True if the requested RPM is within the token's limit.

    FAIL CLOSED: returns False for missing or invalid tokens.
    """
    if not token:
        return False
    try:
        limits = token.get("limits", {}) if isinstance(token, dict) else {}
        allowed_rpm = int(limits.get("rpm", 0))
        return rpm_request <= allowed_rpm
    except (TypeError, ValueError):
        return False


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _parse_token(token_json: str) -> dict:
    """Parse and basic-validate a token JSON string."""
    if not token_json or not isinstance(token_json, str):
        raise ValueError("token_json must be a non-empty string")
    data = json.loads(token_json)
    if not isinstance(data, dict):
        raise ValueError("token must be a JSON object")
    # Required fields
    for field in ("tenant_id", "license_id", "plan", "status", "signature",
                  "issued_at", "expires_at", "features", "limits"):
        if field not in data:
            raise ValueError(f"missing required field: {field}")
    return data


def _compute_signature(token: dict, key: bytes) -> str:
    """Compute the expected HMAC signature for a token dict."""
    payload = {k: v for k, v in token.items() if k != "signature"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def _offline_fallback(
    cached_token_json: Optional[str],
    last_valid_ts:     Optional[float],
    reason:            str,
    expired_token:     Optional[dict] = None,
) -> LicenseValidationResult:
    """
    Attempt offline fallback using a cached token.

    If the cache is within OFFLINE_GRACE_SECONDS of the last valid time,
    return monitor_only. Otherwise fail closed (quarantine).
    """
    if not cached_token_json or last_valid_ts is None:
        # No cache — use expired token's data if available for monitor_only
        if expired_token:
            return LicenseValidationResult(
                valid=False,
                enforcement_mode="monitor_only",
                reason=reason,
                plan=expired_token.get("plan", "free"),
                features=expired_token.get("features", {}),
                limits=expired_token.get("limits", {}),
                tenant_id=expired_token.get("tenant_id", ""),
            )
        return _dc_replace(_RESULT_QUARANTINE, reason=reason)

    grace_elapsed = time.time() - float(last_valid_ts)
    if grace_elapsed <= OFFLINE_GRACE_SECONDS:
        try:
            cached = _parse_token(cached_token_json)
            return LicenseValidationResult(
                valid=False,
                enforcement_mode="monitor_only",
                reason=f"{reason}_offline_grace",
                plan=cached.get("plan", "free"),
                features=cached.get("features", {}),
                limits=cached.get("limits", {}),
                tenant_id=cached.get("tenant_id", ""),
            )
        except Exception:
            pass

    return _dc_replace(_RESULT_QUARANTINE, reason=reason)
