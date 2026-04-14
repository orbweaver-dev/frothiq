# Copyright (c) 2026, OrbWeaver
# License: Proprietary

"""
FrothIQ Command Center — DEPRECATED (Phase 5)

Admin dashboard functionality has been migrated to the standalone
FrothIQ Control Center service (port 8002).

Only realtime notifier functions are preserved here — they are called
by Frappe doc_events and scheduler hooks and must remain in this module.
"""

import frappe


# ---------------------------------------------------------------------------
# Realtime publishers — still called by Frappe event hooks
# ---------------------------------------------------------------------------

def notify_block_action(ip: str, strategy: str, reason: str):
    """Publish a realtime event when a block or unblock occurs."""
    try:
        frappe.publish_realtime(
            event="frothiq_block_action",
            message={
                "ip": ip,
                "strategy": strategy,
                "reason": reason,
            },
            after_commit=True,
        )
    except Exception:
        pass


def notify_campaign_update(campaign_id: str, campaign_type: str, confidence: int):
    """Publish a realtime event when a campaign is detected or updated."""
    try:
        frappe.publish_realtime(
            event="frothiq_campaign_update",
            message={
                "campaign_id": campaign_id,
                "campaign_type": campaign_type,
                "confidence_score": confidence,
            },
            after_commit=True,
        )
    except Exception:
        pass


def notify_agent_update(agent_id: str, agent_type: str, status: str):
    """Publish a realtime event when an agent comes online or goes offline."""
    try:
        frappe.publish_realtime(
            event="frothiq_agent_update",
            message={
                "agent_id":   agent_id,
                "agent_type": agent_type,
                "status":     status,
            },
            after_commit=True,
        )
    except Exception:
        pass
