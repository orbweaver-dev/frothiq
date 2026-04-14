# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ License Issuer — Cryptographic Token Authority

Generates, signs, and verifies HMAC-SHA256 signed LicenseTokens.

DESIGN CONTRACT
===============
  - Private signing key lives ONLY in the control center environment.
    It is NEVER serialized into a token, response, or edge plugin.
  - Signature covers every semantic field via JSON canonical form (sorted
    keys, no whitespace, UTF-8). Tampering any field invalidates the sig.
  - Offline verification: edge plugins receive the token + public key
    (HMAC symmetric — same key; enterprise RSA extension reserved).
  - Token TTL: 30 days for active, 14 days for trial.  Edge plugins
    MUST re-sync before expiry via the heartbeat endpoint.

Signing algorithm: HMAC-SHA256 (v1).
Key source (in priority order):
  1. FROTHIQ_LICENSE_SECRET environment variable
  2. frothiq_license_secret in site_config.json
  3. Derived fallback: HMAC(frothiq_api_key, b"frothiq-license-v1")
     (weaker — warn if used; production must set the dedicated key)

LicenseToken schema
-------------------
  tenant_id       : str   canonical tenant name
  license_id      : str   UUID, unique per issuance
  plan            : str   free | pro | enterprise
  status          : str   active | suspended | expired | trial
  features        : dict  {federation, campaigns, simulation, defense_mesh,
                            intel_market, policy_mesh, response_engine}
  limits          : dict  {rpm, max_sites, block_score, retention_days}
  issued_at       : float Unix timestamp
  expires_at      : float Unix timestamp
  schema_version  : int   token schema version (1)
  signature       : str   hex-encoded HMAC-SHA256

Wire format: JSON (dict) — use .to_dict() / .from_dict()
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Schema version — bump when adding fields to signing surface
# ---------------------------------------------------------------------------
_SCHEMA_VERSION = 1

# Token TTLs in seconds
_TTL_ACTIVE    = 30 * 86400   # 30 days
_TTL_TRIAL     = 14 * 86400   # 14 days
_TTL_SUSPENDED = 7  * 86400   # 7 days (short — re-validate often)
_TTL_EXPIRED   = 86400        # 1 day  (cached tombstone)

# Retention days per plan
_RETENTION_DAYS = {"free": 7, "pro": 30, "enterprise": 90}


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class LicensePlan(str, Enum):
    FREE       = "free"
    PRO        = "pro"
    ENTERPRISE = "enterprise"


class LicenseStatus(str, Enum):
    ACTIVE    = "active"
    SUSPENDED = "suspended"
    EXPIRED   = "expired"
    TRIAL     = "trial"


# ---------------------------------------------------------------------------
# Nested payload types
# ---------------------------------------------------------------------------

@dataclass
class LicenseFeatures:
    federation:          bool = False
    campaigns:           bool = False
    simulation:          bool = False
    defense_mesh:        bool = False
    intel_market:        bool = False
    policy_mesh:         bool = False
    response_engine:     bool = False
    adaptive_scoring:    bool = True   # always enabled; basic security signal

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "LicenseFeatures":
        known = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: bool(v) for k, v in d.items() if k in known})

    @classmethod
    def for_plan(cls, plan: str) -> "LicenseFeatures":
        """Return the canonical feature set for a given plan tier."""
        plan = plan.lower()
        if plan == "enterprise":
            return cls(
                federation=True, campaigns=True, simulation=True,
                defense_mesh=True, intel_market=True, policy_mesh=True,
                response_engine=True, adaptive_scoring=True,
            )
        if plan == "pro":
            return cls(
                federation=True, campaigns=True, simulation=False,
                defense_mesh=True, intel_market=True, policy_mesh=True,
                response_engine=False, adaptive_scoring=True,
            )
        # free
        return cls(
            federation=False, campaigns=False, simulation=False,
            defense_mesh=False, intel_market=False, policy_mesh=False,
            response_engine=False, adaptive_scoring=True,
        )


@dataclass
class LicenseLimits:
    rpm:             int = 120
    max_sites:       int = 1
    block_score:     int = 100
    retention_days:  int = 7

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "LicenseLimits":
        known = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: int(v) for k, v in d.items() if k in known})

    @classmethod
    def for_plan(cls, plan: str) -> "LicenseLimits":
        plan = plan.lower()
        if plan == "enterprise":
            return cls(rpm=2000, max_sites=100, block_score=60, retention_days=90)
        if plan == "pro":
            return cls(rpm=600,  max_sites=10,  block_score=80, retention_days=30)
        return cls(rpm=120,  max_sites=1,   block_score=100, retention_days=7)


# ---------------------------------------------------------------------------
# LicenseToken
# ---------------------------------------------------------------------------

@dataclass
class LicenseToken:
    """
    Cryptographically signed entitlement contract.

    Do NOT set signature directly — use LicenseIssuer.sign().
    Do NOT serialize until signed.
    """
    tenant_id:      str
    license_id:     str
    plan:           str
    status:         str
    features:       LicenseFeatures
    limits:         LicenseLimits
    issued_at:      float
    expires_at:     float
    schema_version: int   = _SCHEMA_VERSION
    signature:      str   = ""

    # ------------------------------------------------------------------
    # Convenience properties
    # ------------------------------------------------------------------

    @property
    def is_active(self) -> bool:
        return self.status == LicenseStatus.ACTIVE and not self.is_expired

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    @property
    def is_suspended(self) -> bool:
        return self.status == LicenseStatus.SUSPENDED

    @property
    def is_trial(self) -> bool:
        return self.status == LicenseStatus.TRIAL

    @property
    def seconds_until_expiry(self) -> float:
        return max(0.0, self.expires_at - time.time())

    def has_feature(self, feature: str) -> bool:
        return bool(getattr(self.features, feature, False))

    # ------------------------------------------------------------------
    # Enforcement state
    # ------------------------------------------------------------------

    @property
    def enforcement_mode(self) -> str:
        """
        Returns the effective enforcement mode for edge plugins:
          full_enforcement  — active + valid
          monitor_only      — expired (degrade gracefully)
          quarantine        — suspended or missing
        """
        if self.is_suspended:
            return "quarantine"
        if self.is_expired:
            return "monitor_only"
        if self.status in (LicenseStatus.ACTIVE, LicenseStatus.TRIAL):
            return "full_enforcement"
        return "quarantine"

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Full dict representation including signature (wire format)."""
        return {
            "tenant_id":      self.tenant_id,
            "license_id":     self.license_id,
            "plan":           self.plan,
            "status":         self.status,
            "features":       self.features.to_dict(),
            "limits":         self.limits.to_dict(),
            "issued_at":      self.issued_at,
            "expires_at":     self.expires_at,
            "schema_version": self.schema_version,
            "signature":      self.signature,
        }

    def to_public_dict(self) -> dict:
        """
        Public-facing representation — signature included for edge verification
        but the signing key is NOT exposed.
        """
        return self.to_dict()

    @classmethod
    def from_dict(cls, d: dict) -> "LicenseToken":
        return cls(
            tenant_id      = str(d["tenant_id"]),
            license_id     = str(d["license_id"]),
            plan           = str(d["plan"]),
            status         = str(d["status"]),
            features       = LicenseFeatures.from_dict(d.get("features", {})),
            limits         = LicenseLimits.from_dict(d.get("limits", {})),
            issued_at      = float(d["issued_at"]),
            expires_at     = float(d["expires_at"]),
            schema_version = int(d.get("schema_version", 1)),
            signature      = str(d.get("signature", "")),
        )

    def signing_payload(self) -> str:
        """
        Canonical signing string — deterministic, covers all semantic fields.
        Excludes 'signature' itself (obviously).
        """
        payload = {
            "tenant_id":      self.tenant_id,
            "license_id":     self.license_id,
            "plan":           self.plan,
            "status":         self.status,
            "features":       self.features.to_dict(),
            "limits":         self.limits.to_dict(),
            "issued_at":      self.issued_at,
            "expires_at":     self.expires_at,
            "schema_version": self.schema_version,
        }
        # Canonical JSON: sorted keys, no whitespace, UTF-8
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# ---------------------------------------------------------------------------
# LicenseIssuer
# ---------------------------------------------------------------------------

class LicenseIssuer:
    """
    Generates and signs LicenseTokens using HMAC-SHA256.

    The private signing key is loaded at instantiation from environment or
    Frappe site config. It is NEVER transmitted to edge plugins.
    """

    def __init__(self, secret_key: Optional[bytes] = None) -> None:
        self._key = secret_key or self._load_key()
        if not self._key:
            raise ValueError(
                "LicenseIssuer: no signing key available. "
                "Set FROTHIQ_LICENSE_SECRET env var or frothiq_license_secret in site_config."
            )

    # ------------------------------------------------------------------
    # Public: issue
    # ------------------------------------------------------------------

    def issue(
        self,
        tenant_id: str,
        plan: str,
        status: str,
        features: Optional[LicenseFeatures] = None,
        limits: Optional[LicenseLimits] = None,
        ttl_override: Optional[int] = None,
    ) -> LicenseToken:
        """
        Create and sign a new LicenseToken for the given tenant.

        Parameters
        ----------
        tenant_id : str       canonical FrothIQ Tenant name
        plan      : str       free | pro | enterprise
        status    : str       active | suspended | expired | trial
        features  : optional  override canonical plan features
        limits    : optional  override canonical plan limits
        ttl_override : optional  override default TTL in seconds

        Returns
        -------
        LicenseToken  — fully signed and ready for distribution
        """
        plan   = plan.lower()
        status = status.lower()

        now     = time.time()
        ttl     = ttl_override or self._default_ttl(status)
        expires = now + ttl

        token = LicenseToken(
            tenant_id   = tenant_id,
            license_id  = str(uuid.uuid4()),
            plan        = plan,
            status      = status,
            features    = features or LicenseFeatures.for_plan(plan),
            limits      = limits   or LicenseLimits.for_plan(plan),
            issued_at   = now,
            expires_at  = expires,
        )
        token.signature = self._sign(token)

        logger.info(
            "license_issuer: issued license=%s tenant=%s plan=%s status=%s expires_in=%dd",
            token.license_id, tenant_id, plan, status, int(ttl // 86400),
        )
        return token

    # ------------------------------------------------------------------
    # Public: verify
    # ------------------------------------------------------------------

    def verify_signature(self, token: LicenseToken) -> bool:
        """
        Return True if the token's signature is cryptographically valid.

        Does NOT check expiry — use token.is_expired for that.
        """
        if not token.signature:
            return False
        expected = self._sign(token)
        # Constant-time comparison to prevent timing attacks
        return hmac.compare_digest(
            expected.encode("ascii"),
            token.signature.encode("ascii"),
        )

    def verify_and_check(self, token: LicenseToken) -> tuple[bool, str]:
        """
        Full token health check: signature + expiry + suspension.

        Returns (is_valid: bool, reason: str).
        """
        if not self.verify_signature(token):
            return False, "signature_invalid"
        if token.is_expired:
            return False, "token_expired"
        if token.is_suspended:
            return False, "license_suspended"
        return True, "ok"

    # ------------------------------------------------------------------
    # Private: signing
    # ------------------------------------------------------------------

    def _sign(self, token: LicenseToken) -> str:
        """Compute HMAC-SHA256 hex digest over the canonical payload."""
        msg = token.signing_payload().encode("utf-8")
        return hmac.new(self._key, msg, hashlib.sha256).hexdigest()

    # ------------------------------------------------------------------
    # Private: key loading
    # ------------------------------------------------------------------

    @staticmethod
    def _load_key() -> Optional[bytes]:
        """
        Load the signing key from environment or Frappe site config.
        Prefers FROTHIQ_LICENSE_SECRET; falls back to a derived key.
        """
        # 1. Dedicated env var (production)
        raw = os.getenv("FROTHIQ_LICENSE_SECRET", "")
        if raw:
            return raw.encode("utf-8")

        # 2. Frappe site config (production alternative)
        try:
            import frappe
            site_secret = frappe.conf.get("frothiq_license_secret", "")
            if site_secret:
                return site_secret.encode("utf-8")
        except Exception:
            pass

        # 3. Derived fallback (not for production)
        try:
            import frappe
            api_key = frappe.conf.get("frothiq_api_key", "") or os.getenv("FROTHIQ_API_KEY", "")
            if api_key:
                logger.warning(
                    "license_issuer: using derived signing key from frothiq_api_key. "
                    "Set FROTHIQ_LICENSE_SECRET for production security."
                )
                # Derive a separate key so compromising the API key ≠ forging licenses
                return hmac.new(
                    api_key.encode("utf-8"),
                    b"frothiq-license-v1",
                    hashlib.sha256,
                ).digest()
        except Exception:
            pass

        return None

    @staticmethod
    def _default_ttl(status: str) -> int:
        return {
            "active":    _TTL_ACTIVE,
            "trial":     _TTL_TRIAL,
            "suspended": _TTL_SUSPENDED,
            "expired":   _TTL_EXPIRED,
        }.get(status.lower(), _TTL_ACTIVE)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

def _make_issuer() -> Optional[LicenseIssuer]:
    """Try to build the singleton; return None if no key is available yet."""
    try:
        return LicenseIssuer()
    except ValueError:
        logger.debug("license_issuer: singleton deferred — no key available at import time")
        return None


license_issuer: Optional[LicenseIssuer] = _make_issuer()


def get_issuer() -> LicenseIssuer:
    """
    Return the module-level issuer, (re-)initializing if needed.

    Call this instead of accessing license_issuer directly to handle
    lazy initialization when the Frappe context is available.
    """
    global license_issuer
    if license_issuer is None:
        license_issuer = LicenseIssuer()
    return license_issuer
