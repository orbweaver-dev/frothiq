# Copyright (c) 2026, OrbWeaver — Proprietary
"""
FrothIQ Conversion Engine

Detects high-value moments (upgrade triggers) and orchestrates promotional
nudges, paywall metadata, and plan recommendation logic.

Architecture
------------
  value_event_detector  — watches tenant activity for upgrade-moment signals
  upgrade_orchestrator  — schedules upgrade banners and email notifications
  plan_optimizer        — scores plans against tenant usage and recommends best fit
  paywall_injector      — generates soft-paywall metadata for API responses
  conversion_api        — whitelisted Frappe API methods for portal + admin use

Design principles
-----------------
  - No hard paywalls: blocked features return metadata, not 403 errors
  - Upgrade suggestions are advisory, time-boxed, and rate-limited
  - Email notifications respect opt-out; banners respect dismissal state
  - All logic is tenant-scoped; no cross-tenant comparison
"""
