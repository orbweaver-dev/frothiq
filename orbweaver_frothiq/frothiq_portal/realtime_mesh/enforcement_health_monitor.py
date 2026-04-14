# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ Enforcement Health Monitor — Frappe wrapper

Re-exports the core EnforcementHealthMonitor from frothiq_core and adds
Frappe-specific export_to_frappe() for publishing to the Control Center UI.

The pure-Python core lives in:
  frothiq_core.license_realtime_mesh.enforcement_health_monitor
"""

from __future__ import annotations

import logging

# Re-export core symbols so callers can import from either location.
from frothiq_core.license_realtime_mesh.enforcement_health_monitor import (  # noqa: F401
    EnforcementHealthMonitor as _CoreMonitor,
    HealthSnapshot,
    _WINDOW_SECONDS,
    _monitor_lock,
)
import frothiq_core.license_realtime_mesh.enforcement_health_monitor as _core_mod

logger = logging.getLogger(__name__)


class EnforcementHealthMonitor(_CoreMonitor):
    """
    Frappe-aware health monitor.

    Extends the core monitor with export_to_frappe() which publishes metrics
    to the FrothIQ Control Center dashboard via Frappe's realtime system.
    """

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


# ---------------------------------------------------------------------------
# Process-level singleton — override the core module's singleton factory
# so get_monitor() returns the Frappe-aware subclass when in Frappe context.
# ---------------------------------------------------------------------------

def get_monitor() -> EnforcementHealthMonitor:
    """Return the process-level singleton (Frappe-aware subclass)."""
    if _core_mod._monitor is None:
        with _monitor_lock:
            if _core_mod._monitor is None:
                _core_mod._monitor = EnforcementHealthMonitor()
    return _core_mod._monitor  # type: ignore[return-value]
