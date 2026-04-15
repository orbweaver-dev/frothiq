# Copyright (c) 2026, OrbWeaver
# License: Proprietary

"""
FrothIQ Frappe Local Defense — autonomous IP blocking cascade.

block_ip() attempts each firewall layer in order, stopping at the first
success. If all system-level layers fail, it falls back to the Frappe DB
blocklist (FrothIQ Blocklist DocType). This is always available.

Blocking layers (in priority order):
  1. CSF (ConfigServer Firewall)   — Linux/cPanel environments
  2. UFW                           — Ubuntu/Debian
  3. FirewallD                     — RHEL/CentOS/Fedora
  4. iptables                      — universal Linux
  5. nftables                      — modern Linux
  6. Apache .htaccess               — web-layer block
  7. Frappe DB blocklist           — application-level always-available fallback

unblock_ip() reverses a block applied by any layer.

All block/unblock actions are recorded in the FrothIQ Log DocType for
audit purposes, regardless of which layer handled the request.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import subprocess
from typing import Optional

import frappe

logger = logging.getLogger(__name__)

# Path to the Frappe site's public directory .htaccess (adjust if needed)
_HTACCESS_PATH = os.path.join(
    frappe.get_site_path("public"), ".htaccess"
)

_DENY_MARKER_FMT = "# frothiq-block: {ip}"
_HTACCESS_DENY_FMT = (
    "\n# frothiq-block: {ip}\n"
    "<RequireAll>\n"
    "    Require not ip {ip}\n"
    "</RequireAll>\n"
)

_MAX_CMD_TIMEOUT = 5  # seconds


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def block_ip(
    ip_address: str,
    reason: str = "FrothIQ threat propagation",
    ttl_seconds: Optional[int] = None,
    agent_id: Optional[str] = None,
) -> dict:
    """
    Block *ip_address* using the best available local method.

    Returns a dict with:
      - blocked (bool)
      - layer (str) — which mechanism was used
      - ip (str)
      - reason (str)
      - error (str | None) — error from failed layers, if any
    """
    if not _validate_ip(ip_address):
        return {"blocked": False, "layer": None, "ip": ip_address,
                "reason": reason, "error": "Invalid IP address"}

    layers = [
        ("csf",      _block_csf),
        ("ufw",      _block_ufw),
        ("firewalld",_block_firewalld),
        ("iptables", _block_iptables),
        ("nftables", _block_nftables),
        ("htaccess", _block_htaccess),
        ("frappe_db",_block_frappe_db),
    ]

    last_error: Optional[str] = None
    for layer_name, layer_fn in layers:
        try:
            ok = layer_fn(ip_address, ttl_seconds)
            if ok:
                _audit_block(ip_address, reason, layer_name, agent_id)
                logger.info(
                    "FrothIQ local block: ip=%s layer=%s reason=%s",
                    ip_address, layer_name, reason,
                )
                return {
                    "blocked":  True,
                    "layer":    layer_name,
                    "ip":       ip_address,
                    "reason":   reason,
                    "error":    None,
                }
        except Exception as exc:
            last_error = str(exc)
            logger.debug("Layer %s failed for %s: %s", layer_name, ip_address, exc)

    # Should never reach here — frappe_db is always available
    logger.error("All block layers failed for %s: %s", ip_address, last_error)
    return {
        "blocked": False,
        "layer":   None,
        "ip":      ip_address,
        "reason":  reason,
        "error":   last_error,
    }


def unblock_ip(ip_address: str, agent_id: Optional[str] = None) -> dict:
    """
    Attempt to remove a block from all possible layers.
    Returns dict with per-layer results.
    """
    if not _validate_ip(ip_address):
        return {"unblocked": False, "ip": ip_address, "error": "Invalid IP"}

    results: dict[str, bool] = {}

    for name, fn in [
        ("csf",       _unblock_csf),
        ("ufw",       _unblock_ufw),
        ("firewalld", _unblock_firewalld),
        ("iptables",  _unblock_iptables),
        ("nftables",  _unblock_nftables),
        ("htaccess",  _unblock_htaccess),
        ("frappe_db", _unblock_frappe_db),
    ]:
        try:
            results[name] = fn(ip_address)
        except Exception as exc:
            logger.debug("Unblock layer %s failed for %s: %s", name, ip_address, exc)
            results[name] = False

    any_success = any(results.values())
    if any_success:
        _audit_block(ip_address, "unblock", "multi", agent_id, action="unblock")
    return {"unblocked": any_success, "ip": ip_address, "layers": results}


def is_blocked(ip_address: str) -> bool:
    """Return True if the IP is in the Frappe DB blocklist (fastest check)."""
    if not _validate_ip(ip_address):
        return False
    return bool(frappe.db.exists("FrothIQ Blocklist", {"ip_address": ip_address}))


# ---------------------------------------------------------------------------
# Layer implementations — block
# ---------------------------------------------------------------------------


def _block_csf(ip: str, ttl: Optional[int]) -> bool:
    if not _cmd_exists("csf"):
        return False
    args = ["csf", "-d", ip, "FrothIQ:auto-block"]
    if ttl:
        args = ["csf", "--tempdeny", ip, str(ttl), "FrothIQ:auto-block"]
    return _run(args)


def _block_ufw(ip: str, ttl: Optional[int]) -> bool:
    if not _cmd_exists("ufw"):
        return False
    return _run(["ufw", "deny", "from", ip, "to", "any"])


def _block_firewalld(ip: str, ttl: Optional[int]) -> bool:
    if not _cmd_exists("firewall-cmd"):
        return False
    return _run(["firewall-cmd", "--add-rich-rule",
                 f'rule family="ipv4" source address="{ip}" reject'])


def _block_iptables(ip: str, ttl: Optional[int]) -> bool:
    if not _cmd_exists("iptables"):
        return False
    return _run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])


def _block_nftables(ip: str, ttl: Optional[int]) -> bool:
    if not _cmd_exists("nft"):
        return False
    # Add to a pre-existing set "frothiq_blocked" in the "filter" table.
    # Falls back silently if the set doesn't exist.
    return _run([
        "nft", "add", "element", "inet", "filter", "frothiq_blocked",
        "{", ip, "}"
    ])


def _block_htaccess(ip: str, ttl: Optional[int]) -> bool:
    marker = _DENY_MARKER_FMT.format(ip=ip)
    try:
        if os.path.exists(_HTACCESS_PATH):
            with open(_HTACCESS_PATH, "r") as f:
                content = f.read()
            if marker in content:
                return True  # already blocked
            with open(_HTACCESS_PATH, "a") as f:
                f.write(_HTACCESS_DENY_FMT.format(ip=ip))
        else:
            with open(_HTACCESS_PATH, "w") as f:
                f.write(_HTACCESS_DENY_FMT.format(ip=ip))
        return True
    except OSError as exc:
        logger.debug(".htaccess block failed: %s", exc)
        return False


def _block_frappe_db(ip: str, ttl: Optional[int]) -> bool:
    """Always-available fallback — insert into FrothIQ Blocklist DocType."""
    try:
        if frappe.db.exists("FrothIQ Blocklist", {"ip_address": ip}):
            return True
        doc = frappe.get_doc({
            "doctype":    "FrothIQ Blocklist",
            "ip_address": ip,
            "reason":     "FrothIQ threat propagation",
            "blocked_at": frappe.utils.now(),
        })
        doc.insert(ignore_permissions=True)
        frappe.db.commit()
        return True
    except Exception as exc:
        logger.error("frappe_db block failed for %s: %s", ip, exc)
        return False


# ---------------------------------------------------------------------------
# Layer implementations — unblock
# ---------------------------------------------------------------------------


def _unblock_csf(ip: str) -> bool:
    if not _cmd_exists("csf"):
        return False
    return _run(["csf", "-dr", ip])


def _unblock_ufw(ip: str) -> bool:
    if not _cmd_exists("ufw"):
        return False
    return _run(["ufw", "delete", "deny", "from", ip, "to", "any"])


def _unblock_firewalld(ip: str) -> bool:
    if not _cmd_exists("firewall-cmd"):
        return False
    return _run(["firewall-cmd", "--remove-rich-rule",
                 f'rule family="ipv4" source address="{ip}" reject'])


def _unblock_iptables(ip: str) -> bool:
    if not _cmd_exists("iptables"):
        return False
    return _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])


def _unblock_nftables(ip: str) -> bool:
    if not _cmd_exists("nft"):
        return False
    return _run([
        "nft", "delete", "element", "inet", "filter", "frothiq_blocked",
        "{", ip, "}"
    ])


def _unblock_htaccess(ip: str) -> bool:
    marker = _DENY_MARKER_FMT.format(ip=ip)
    try:
        if not os.path.exists(_HTACCESS_PATH):
            return False
        with open(_HTACCESS_PATH, "r") as f:
            content = f.read()
        if marker not in content:
            return False
        # Remove the deny block from marker to the closing </RequireAll>
        pattern = (
            r"\n# frothiq-block: " + re.escape(ip) +
            r"\n<RequireAll>\n    Require not ip " + re.escape(ip) +
            r"\n</RequireAll>\n"
        )
        new_content = re.sub(pattern, "", content)
        with open(_HTACCESS_PATH, "w") as f:
            f.write(new_content)
        return True
    except OSError as exc:
        logger.debug(".htaccess unblock failed: %s", exc)
        return False


def _unblock_frappe_db(ip: str) -> bool:
    try:
        docs = frappe.db.get_all(
            "FrothIQ Blocklist", filters={"ip_address": ip}, pluck="name"
        )
        if not docs:
            return False
        for name in docs:
            frappe.delete_doc("FrothIQ Blocklist", name, ignore_permissions=True)
        frappe.db.commit()
        return True
    except Exception as exc:
        logger.error("frappe_db unblock failed for %s: %s", ip, exc)
        return False


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _cmd_exists(cmd: str) -> bool:
    """Return True if *cmd* is on PATH and executable."""
    import shutil
    return shutil.which(cmd) is not None


def _run(args: list[str]) -> bool:
    """
    Run a shell command with a short timeout.
    Returns True on rc=0, False otherwise.
    Does NOT raise — callers interpret False as layer unavailable.
    """
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            timeout=_MAX_CMD_TIMEOUT,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return False


def _audit_block(
    ip: str,
    reason: str,
    layer: str,
    agent_id: Optional[str],
    action: str = "block",
) -> None:
    """Write a FrothIQ Log record for the block/unblock action."""
    try:
        doc = frappe.get_doc({
            "doctype":    "FrothIQ Log",
            "log_type":   "threat_propagation",
            "ip_address": ip,
            "action":     action,
            "layer":      layer,
            "reason":     reason[:500],
            "agent_id":   agent_id or "",
            "timestamp":  frappe.utils.now(),
        })
        doc.insert(ignore_permissions=True)
        frappe.db.commit()
    except Exception as exc:
        logger.debug("Failed to write audit log for %s: %s", ip, exc)
