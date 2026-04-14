# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ License Registry

Thread-safe store for all active issued LicenseTokens.

Storage layers
--------------
  1. In-memory dict  — fast reads, keyed by tenant_id
  2. JSON on disk    — /var/lib/frothiq/licenses.json
     Written atomically (tmp → rename) after every mutation.

Cache TTL
---------
  Entries older than CACHE_TTL_SECONDS are considered stale and trigger
  a background refresh attempt. The stale entry is still served until a
  fresh one is available (graceful degradation).

  CACHE_TTL_SECONDS = 600  (10 minutes, configurable)

Versioning
----------
  Each stored record includes a `stored_at` timestamp and a `version`
  counter (monotonically incremented on each update). This allows callers
  to detect whether a cached entry predates a known event.

Tenant isolation
----------------
  get() NEVER returns another tenant's record even if called with
  an incorrect tenant_id — it simply returns None.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Optional

from .license_issuer import LicenseToken

logger = logging.getLogger(__name__)

_DEFAULT_STORE_PATH  = Path("/var/lib/frothiq/licenses.json")
_DEFAULT_AUDIT_PATH  = Path("/var/lib/frothiq/license_history.json")
CACHE_TTL_SECONDS    = int(os.getenv("FROTHIQ_LICENSE_TTL", "600"))   # 10 min
_MAX_HISTORY_PER_TENANT = 20   # keep last 20 issued tokens per tenant


class LicenseRegistry:
    """
    Thread-safe in-memory + on-disk registry for LicenseTokens.

    Stores:
      { tenant_id: { "token": dict, "stored_at": float, "version": int } }
    """

    def __init__(
        self,
        store_path: Optional[Path] = None,
        cache_ttl:  int             = CACHE_TTL_SECONDS,
    ) -> None:
        self._path    = store_path or _DEFAULT_STORE_PATH
        self._ttl     = cache_ttl
        self._lock    = threading.RLock()
        # Primary cache: tenant_id → { "token": dict, "stored_at": float, "version": int }
        self._cache:  dict[str, dict] = {}
        self._history: dict[str, list[dict]] = {}   # tenant_id → [last N token dicts]
        self._load()

    # ------------------------------------------------------------------
    # Public: reads
    # ------------------------------------------------------------------

    def get(self, tenant_id: str) -> Optional[LicenseToken]:
        """
        Return the cached LicenseToken for tenant_id, or None.

        Never returns another tenant's token.
        """
        with self._lock:
            entry = self._cache.get(tenant_id)
        if not entry:
            return None
        try:
            return LicenseToken.from_dict(entry["token"])
        except Exception as exc:
            logger.warning("license_registry.get: corrupt entry for %s: %s", tenant_id, exc)
            return None

    def is_stale(self, tenant_id: str) -> bool:
        """Return True if the cached entry is older than CACHE_TTL."""
        with self._lock:
            entry = self._cache.get(tenant_id)
        if not entry:
            return True
        return (time.time() - entry.get("stored_at", 0)) > self._ttl

    def all_tenants(self) -> list[str]:
        """Return list of all tenant_ids with a stored record."""
        with self._lock:
            return list(self._cache.keys())

    def get_version(self, tenant_id: str) -> int:
        """Return the version counter for a cached entry (0 if missing)."""
        with self._lock:
            return self._cache.get(tenant_id, {}).get("version", 0)

    def get_history(self, tenant_id: str) -> list[dict]:
        """Return version history for a tenant (most recent first)."""
        with self._lock:
            return list(reversed(self._history.get(tenant_id, [])))

    def count(self) -> int:
        """Return total number of tenants in the registry."""
        with self._lock:
            return len(self._cache)

    # ------------------------------------------------------------------
    # Public: writes
    # ------------------------------------------------------------------

    def store(self, token: LicenseToken) -> int:
        """
        Store a LicenseToken in the registry.

        Returns the new version counter for the tenant.
        """
        with self._lock:
            prev_version = self._cache.get(token.tenant_id, {}).get("version", 0)
            new_version  = prev_version + 1
            entry = {
                "token":     token.to_dict(),
                "stored_at": time.time(),
                "version":   new_version,
            }
            self._cache[token.tenant_id] = entry

            # Maintain version history
            hist = self._history.setdefault(token.tenant_id, [])
            hist.append(token.to_dict())
            if len(hist) > _MAX_HISTORY_PER_TENANT:
                self._history[token.tenant_id] = hist[-_MAX_HISTORY_PER_TENANT:]

        self._save()
        logger.debug(
            "license_registry: stored tenant=%s plan=%s status=%s version=%d",
            token.tenant_id, token.plan, token.status, new_version,
        )
        return new_version

    def revoke(self, tenant_id: str) -> bool:
        """
        Remove a tenant's license from the registry.

        Returns True if an entry was removed, False if not found.
        """
        with self._lock:
            existed = tenant_id in self._cache
            if existed:
                del self._cache[tenant_id]
        if existed:
            self._save()
            logger.info("license_registry: revoked tenant=%s", tenant_id)
        return existed

    def purge_expired(self) -> int:
        """Remove all entries whose token.expires_at is in the past. Returns count removed."""
        removed = 0
        with self._lock:
            expired_ids = []
            for tid, entry in self._cache.items():
                try:
                    expires = entry["token"].get("expires_at", 0)
                    if time.time() > float(expires):
                        expired_ids.append(tid)
                except Exception:
                    pass
            for tid in expired_ids:
                del self._cache[tid]
                removed += 1
        if removed:
            self._save()
            logger.info("license_registry: purged %d expired entries", removed)
        return removed

    # ------------------------------------------------------------------
    # Private: persistence
    # ------------------------------------------------------------------

    def _load(self) -> None:
        """Load state from disk on startup."""
        try:
            if self._path.exists():
                raw = json.loads(self._path.read_text())
                self._cache   = raw.get("cache", {})
                self._history = raw.get("history", {})
                logger.debug("license_registry: loaded %d entries from %s", len(self._cache), self._path)
        except Exception as exc:
            logger.warning("license_registry: failed to load from disk: %s", exc)
            self._cache   = {}
            self._history = {}

    def _save(self) -> None:
        """Atomically write state to disk."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".tmp")
            with self._lock:
                data = {
                    "cache":     self._cache,
                    "history":   self._history,
                    "saved_at":  time.time(),
                }
            tmp.write_text(json.dumps(data, indent=2, default=str))
            tmp.replace(self._path)
        except Exception as exc:
            logger.warning("license_registry: failed to save to disk: %s", exc)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

license_registry = LicenseRegistry()
