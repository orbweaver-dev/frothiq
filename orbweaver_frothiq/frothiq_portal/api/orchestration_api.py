"""
Hybrid Orchestration Intelligence Layer — Frappe API  (Phase 3)

All orchestration endpoints have been migrated to the FrothIQ Control Center
standalone service (port 8002) or removed as part of Phase 5 boundary enforcement.

The Frappe app is a customer SaaS portal only — it must not contain any
policy evaluation, license verification, or orchestration decision logic.

This module is retained as a stub to avoid ImportError in legacy code.
"""
