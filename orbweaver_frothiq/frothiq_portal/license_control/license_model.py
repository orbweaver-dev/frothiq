# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ License Model — Control-Plane License Record

Defines the canonical FrothIQ License entity used by the control center.
This is the *control-plane* record stored in Frappe, distinct from the
LicenseToken (the signed JSON contract distributed to edge plugins).

Authority chain:
  ERPNext Subscription
    → BillingOrchestrator (billing status)
    → FrothIQLicenseRecord (control-plane state)
    → LicenseControlCenter.issue()
    → LicenseToken (edge-plugin artifact)

Field naming:  license_id uses FIQ-LIC-{YYYY}-{#####} series.
Fingerprint:   SHA-256(license_id + tenant_id + issued_at) — first 16 hex chars,
               included in all audit events for non-repudiation.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Plan / status enumerations
# ---------------------------------------------------------------------------

class LicensePlan(str, Enum):
    FREE       = "free"
    PRO        = "pro"
    ENTERPRISE = "enterprise"


class LicenseStatus(str, Enum):
    ACTIVE    = "active"
    SUSPENDED = "suspended"
    REVOKED   = "revoked"
    EXPIRED   = "expired"
    TRIAL     = "trial"


# ---------------------------------------------------------------------------
# Canonical plan → feature/limit matrices
# (single source of truth; license_issuer.py LicenseFeatures.for_plan() mirrors this)
# ---------------------------------------------------------------------------

PLAN_FEATURE_MATRIX: dict[str, dict[str, bool]] = {
    "free": {
        "federation":              False,
        "campaigns":               False,
        "simulation":              False,
        "defense_mesh":            False,
        "defense_mesh_auto_apply": False,
        "intel_market":            False,
        "policy_mesh":             False,
        "response_engine":         False,
        "adaptive_scoring":        True,
    },
    "pro": {
        "federation":              True,
        "campaigns":               True,
        "simulation":              False,
        "defense_mesh":            True,
        "defense_mesh_auto_apply": False,
        "intel_market":            True,
        "policy_mesh":             True,
        "response_engine":         False,
        "adaptive_scoring":        True,
    },
    "enterprise": {
        "federation":              True,
        "campaigns":               True,
        "simulation":              True,
        "defense_mesh":            True,
        "defense_mesh_auto_apply": True,
        "intel_market":            True,
        "policy_mesh":             True,
        "response_engine":         True,
        "adaptive_scoring":        True,
    },
}

PLAN_LIMIT_MATRIX: dict[str, dict[str, int]] = {
    "free":       {"rpm": 120,  "max_sites": 1,   "block_score": 100, "retention_days": 7},
    "pro":        {"rpm": 600,  "max_sites": 10,  "block_score": 80,  "retention_days": 30},
    "enterprise": {"rpm": 2000, "max_sites": 100, "block_score": 60,  "retention_days": 90},
}

# TTL values in seconds
LICENSE_TTL = {
    "active":    30 * 86400,   # 30 days
    "trial":     14 * 86400,   # 14 days
    "suspended":  7 * 86400,   # 7 days
    "expired":       86400,    # 1 day tombstone
    "revoked":       86400,    # 1 day tombstone
}


# ---------------------------------------------------------------------------
# FrothIQLicenseRecord — control-plane entity
# ---------------------------------------------------------------------------

@dataclass
class FrothIQLicenseRecord:
    """
    Control-plane record for a FrothIQ license.

    Stored in Frappe (FrothIQ License Record DocType).
    Serialised to/from dict for the audit bridge and API responses.

    Do NOT confuse with LicenseToken — the edge plugin artifact derived
    from this record by LicenseControlCenter.issue().
    """
    license_id:           str            # FIQ-LIC-YYYY-XXXXX
    tenant_id:            str            # FrothIQ Tenant name
    plan:                 str            # free | pro | enterprise
    status:               str            # active | suspended | revoked | expired | trial
    issued_at:            float          # Unix timestamp
    expires_at:           float          # Unix timestamp
    version:              int = 1        # monotonically incremented on each re-issue
    site_id:              Optional[str] = None   # optional — multi-site tenants
    last_rotated:         Optional[float] = None # Unix ts of last key rotation
    feature_flags:        dict = field(default_factory=dict)
    limits:               dict = field(default_factory=dict)
    signature:            str  = ""
    public_fingerprint:   str  = ""
    subscription_hash:    str  = ""      # idempotency key from ERPNext subscription state

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        tenant_id:         str,
        plan:              str,
        status:            str,
        site_id:           Optional[str] = None,
        ttl_override:      Optional[int] = None,
        feature_overrides: Optional[dict] = None,
        limit_overrides:   Optional[dict] = None,
        version:           int = 1,
    ) -> "FrothIQLicenseRecord":
        """Create a new unsigned FrothIQLicenseRecord."""
        plan   = plan.lower()
        status = status.lower()
        now    = time.time()
        ttl    = ttl_override or LICENSE_TTL.get(status, LICENSE_TTL["active"])

        features = dict(PLAN_FEATURE_MATRIX.get(plan, PLAN_FEATURE_MATRIX["free"]))
        limits   = dict(PLAN_LIMIT_MATRIX.get(plan, PLAN_LIMIT_MATRIX["free"]))

        if feature_overrides:
            features.update({k: bool(v) for k, v in feature_overrides.items()
                              if k in features})
        if limit_overrides:
            limits.update({k: int(v) for k, v in limit_overrides.items()
                           if k in limits})

        license_id = cls._generate_id()
        record = cls(
            license_id    = license_id,
            tenant_id     = tenant_id,
            plan          = plan,
            status        = status,
            issued_at     = now,
            expires_at    = now + ttl,
            version       = version,
            site_id       = site_id,
            feature_flags = features,
            limits        = limits,
        )
        record.public_fingerprint = record._compute_fingerprint()
        return record

    @classmethod
    def from_dict(cls, d: dict) -> "FrothIQLicenseRecord":
        return cls(
            license_id         = str(d["license_id"]),
            tenant_id          = str(d["tenant_id"]),
            plan               = str(d["plan"]),
            status             = str(d["status"]),
            issued_at          = float(d["issued_at"]),
            expires_at         = float(d["expires_at"]),
            version            = int(d.get("version", 1)),
            site_id            = d.get("site_id"),
            last_rotated       = d.get("last_rotated"),
            feature_flags      = dict(d.get("feature_flags", {})),
            limits             = dict(d.get("limits", {})),
            signature          = str(d.get("signature", "")),
            public_fingerprint = str(d.get("public_fingerprint", "")),
            subscription_hash  = str(d.get("subscription_hash", "")),
        )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_active(self) -> bool:
        return self.status in ("active", "trial") and not self.is_expired

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    @property
    def is_revoked(self) -> bool:
        return self.status == "revoked"

    @property
    def is_suspended(self) -> bool:
        return self.status == "suspended"

    @property
    def enforcement_mode(self) -> str:
        """Canonical enforcement mode for edge plugins."""
        if self.is_revoked:
            return "quarantine"
        if self.is_suspended:
            return "quarantine"
        if self.is_expired:
            return "monitor_only"
        if self.status in ("active", "trial"):
            return "full_enforcement"
        return "quarantine"

    def has_feature(self, feature: str) -> bool:
        return bool(self.feature_flags.get(feature, False))

    def seconds_until_expiry(self) -> float:
        return max(0.0, self.expires_at - time.time())

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "license_id":         self.license_id,
            "tenant_id":          self.tenant_id,
            "plan":               self.plan,
            "status":             self.status,
            "issued_at":          self.issued_at,
            "expires_at":         self.expires_at,
            "version":            self.version,
            "site_id":            self.site_id,
            "last_rotated":       self.last_rotated,
            "feature_flags":      self.feature_flags,
            "limits":             self.limits,
            "signature":          self.signature,
            "public_fingerprint": self.public_fingerprint,
            "subscription_hash":  self.subscription_hash,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_id() -> str:
        """Generate a FIQ-LIC-YYYY-XXXXX style license ID."""
        import datetime
        year   = datetime.datetime.now(datetime.timezone.utc).year
        suffix = uuid.uuid4().hex[:8].upper()
        return f"FIQ-LIC-{year}-{suffix}"

    def _compute_fingerprint(self) -> str:
        """Public fingerprint — first 16 hex chars of SHA-256."""
        raw = f"{self.license_id}:{self.tenant_id}:{self.issued_at:.0f}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def compute_subscription_hash(
        tenant_id: str,
        plan:      str,
        status:    str,
        features:  dict,
    ) -> str:
        """
        Compute a stable hash of the ERPNext subscription state.

        Used as an idempotency key: if the hash hasn't changed since the last
        issuance, we skip re-issuance and return the cached record.
        """
        payload = json.dumps({
            "tenant_id": tenant_id,
            "plan":      plan.lower(),
            "status":    status.lower(),
            "features":  features,
        }, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]
