# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ Enforcement Health Monitor

Tracks real-time metrics for the license revocation mesh and exports them
to the FrothIQ Event system and the Control Center dashboard.

Metrics tracked
---------------
  revocation_propagation_latency_ms  — time from broadcast to last-node-ack
  sync_success_rate                  — fraction of broadcasts with ≥1 delivery
  node_drift_rate                    — drifted nodes / total nodes (per sweep)
  cache_mismatch_frequency           — sig failures per hour per tenant
  quarantine_triggers_per_hour       — quarantine events per hour (global)

Thread-safe: all counters are protected by a lock.
Singleton pattern: get_monitor() returns the process-level instance.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Optional

logger = logging.getLogger(__name__)

_WINDOW_SECONDS = 3600   # 1-hour rolling window for rate metrics


@dataclass
class HealthSnapshot:
    """Point-in-time health metrics snapshot."""
    ts:                               float
    active_nodes:                     int   = 0
    stale_nodes:                      int   = 0
    sync_success_rate:                float = 1.0   # 0.0 – 1.0
    node_drift_rate:                  float = 0.0
    quarantine_triggers_per_hour:     float = 0.0
    cache_mismatch_per_hour:          float = 0.0
    avg_propagation_latency_ms:       float = 0.0
    last_sweep_duration_seconds:      float = 0.0
    pending_broadcasts:               int   = 0

    def to_dict(self) -> dict:
        return {
            "ts":                           self.ts,
            "active_nodes":                 self.active_nodes,
            "stale_nodes":                  self.stale_nodes,
            "sync_success_rate":            round(self.sync_success_rate, 4),
            "node_drift_rate":              round(self.node_drift_rate, 4),
            "quarantine_triggers_per_hour": round(self.quarantine_triggers_per_hour, 2),
            "cache_mismatch_per_hour":      round(self.cache_mismatch_per_hour, 2),
            "avg_propagation_latency_ms":   round(self.avg_propagation_latency_ms, 2),
            "last_sweep_duration_seconds":  round(self.last_sweep_duration_seconds, 3),
            "pending_broadcasts":           self.pending_broadcasts,
        }


class EnforcementHealthMonitor:
    """
    Tracks key health metrics for the revocation mesh.

    Designed to be instantiated once (process singleton via get_monitor()).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()

        # Rolling event timestamp queues (for per-hour rates)
        self._quarantine_events:  Deque[float] = deque()
        self._cache_mismatches:   Deque[float] = deque()
        self._broadcast_results:  Deque[dict]  = deque(maxlen=1000)

        # Latest sweep metrics
        self._last_active_nodes:  int   = 0
        self._last_stale_nodes:   int   = 0
        self._last_drift_rate:    float = 0.0
        self._last_sweep_duration: float = 0.0
        self._pending_broadcasts: int   = 0

    # ------------------------------------------------------------------
    # Record methods (called by broadcast engine / reconciliation)
    # ------------------------------------------------------------------

    def record_broadcast(
        self,
        event_type:   str,
        license_id:   str,
        tenant_id:    str,
        redis_count:  int,
        http_count:   int,
        latency_ms:   float = 0.0,
    ) -> None:
        """Called by RevocationBroadcastEngine after each broadcast."""
        with self._lock:
            self._broadcast_results.append({
                "ts":          time.time(),
                "event_type":  event_type,
                "license_id":  license_id,
                "tenant_id":   tenant_id,
                "redis_count": redis_count,
                "http_count":  http_count,
                "latency_ms":  latency_ms,
                "success":     (redis_count + http_count) > 0,
            })

    def record_quarantine_trigger(self, tenant_id: str) -> None:
        """Called when an edge plugin enters quarantine mode."""
        with self._lock:
            self._quarantine_events.append(time.time())
            self._trim_window(self._quarantine_events)

    def record_cache_mismatch(self, tenant_id: str, drift_type: str) -> None:
        """Called by DriftDetector on sig_mismatch or version_mismatch."""
        with self._lock:
            self._cache_mismatches.append(time.time())
            self._trim_window(self._cache_mismatches)

    def record_sweep_result(
        self,
        active_nodes:    int,
        stale_nodes:     int,
        drifted_nodes:   int,
        total_nodes:     int,
        sweep_duration:  float,
        pending_count:   int,
    ) -> None:
        """Called by LicenseReconciliationEngine after each sweep."""
        with self._lock:
            self._last_active_nodes   = active_nodes
            self._last_stale_nodes    = stale_nodes
            self._last_drift_rate     = drifted_nodes / max(total_nodes, 1)
            self._last_sweep_duration = sweep_duration
            self._pending_broadcasts  = pending_count

    # ------------------------------------------------------------------
    # Snapshot
    # ------------------------------------------------------------------

    def snapshot(self) -> HealthSnapshot:
        """Return a current point-in-time metrics snapshot."""
        with self._lock:
            now = time.time()

            # Per-hour rates
            q_per_hr   = self._rate_per_hour(self._quarantine_events, now)
            cm_per_hr  = self._rate_per_hour(self._cache_mismatches, now)

            # Sync success rate (last 1000 broadcasts)
            broadcasts = list(self._broadcast_results)
            if broadcasts:
                success_count = sum(1 for b in broadcasts if b["success"])
                sync_rate     = success_count / len(broadcasts)
                latencies     = [b["latency_ms"] for b in broadcasts if b["latency_ms"] > 0]
                avg_latency   = sum(latencies) / len(latencies) if latencies else 0.0
            else:
                sync_rate   = 1.0
                avg_latency = 0.0

            return HealthSnapshot(
                ts                           = now,
                active_nodes                 = self._last_active_nodes,
                stale_nodes                  = self._last_stale_nodes,
                sync_success_rate            = sync_rate,
                node_drift_rate              = self._last_drift_rate,
                quarantine_triggers_per_hour = q_per_hr,
                cache_mismatch_per_hour      = cm_per_hr,
                avg_propagation_latency_ms   = avg_latency,
                last_sweep_duration_seconds  = self._last_sweep_duration,
                pending_broadcasts           = self._pending_broadcasts,
            )

    def export_to_frappe(self) -> None:
        """
        Export current metrics snapshot to Frappe (best-effort).
        Called by the reconciliation engine after each sweep.
        """
        snap = self.snapshot()
        try:
            import frappe
            frappe.publish_realtime(
                event   = "frothiq_mesh_health_update",
                message = snap.to_dict(),
            )
        except Exception:
            pass

        # Log to audit trail if thresholds breached
        if snap.node_drift_rate > 0.1:
            logger.warning(
                "health_monitor: HIGH DRIFT RATE %.1f%% — %d drifted nodes",
                snap.node_drift_rate * 100, snap.stale_nodes,
            )
        if snap.sync_success_rate < 0.9:
            logger.warning(
                "health_monitor: LOW SYNC SUCCESS RATE %.1f%%",
                snap.sync_success_rate * 100,
            )

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _trim_window(self, q: Deque[float]) -> None:
        """Remove events older than _WINDOW_SECONDS from the deque."""
        cutoff = time.time() - _WINDOW_SECONDS
        while q and q[0] < cutoff:
            q.popleft()

    def _rate_per_hour(self, q: Deque[float], now: float) -> float:
        """Count events in the last hour, return as float rate."""
        cutoff = now - _WINDOW_SECONDS
        count  = sum(1 for ts in q if ts >= cutoff)
        return float(count)


# ---------------------------------------------------------------------------
# Process-level singleton
# ---------------------------------------------------------------------------

_monitor: Optional[EnforcementHealthMonitor] = None
_monitor_lock = threading.Lock()


def get_monitor() -> EnforcementHealthMonitor:
    """Return the process-level singleton EnforcementHealthMonitor."""
    global _monitor
    if _monitor is None:
        with _monitor_lock:
            if _monitor is None:
                _monitor = EnforcementHealthMonitor()
    return _monitor
