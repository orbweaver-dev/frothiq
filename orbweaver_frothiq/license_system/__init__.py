# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ License System — Control Center Authority Module

Root of trust for all FrothIQ edge plugin entitlements.

Import hierarchy:
  license_issuer     → LicenseToken dataclass + HMAC signing
  entitlement_engine → ERPNext → LicenseToken translation
  license_registry   → in-memory + on-disk store
  license_audit_log  → audit trail
  license_api        → Frappe whitelisted endpoints (imported via hooks)
"""

from .license_issuer import (
    LicenseToken,
    LicenseStatus,
    LicensePlan,
    LicenseFeatures,
    LicenseLimits,
    license_issuer,
)
from .license_registry import license_registry
from .entitlement_engine import entitlement_engine
from .license_audit_log import audit_log

__all__ = [
    "LicenseToken",
    "LicenseStatus",
    "LicensePlan",
    "LicenseFeatures",
    "LicenseLimits",
    "license_issuer",
    "license_registry",
    "entitlement_engine",
    "audit_log",
]
