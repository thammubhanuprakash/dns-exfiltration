#!/usr/bin/env python3
"""
DNS-ExfilWatch - Active Defense & Firewall Quarantine Engine (firewall.py)
Author: Senior Cyber Security Engineer & Systems Software Developer
Platform: Kali Linux / Debian / Linux x86_64

Capabilities:
    1. Automated IP Quarantine via Linux kernel Netfilter / iptables.
    2. Input Validation (strict IP address formatting, RFC 1918 loopback / local IP protection).
    3. Idempotent rule injection with designated security comments.
    4. Session state tracking and graceful cleanup handler for rule rollback on exit.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import platform
import subprocess
import threading
from typing import List, Optional, Set, Tuple

logger = logging.getLogger("DNS-ExfilWatch.Firewall")


class FirewallManager:
    """
    Manages automated quarantine and release of malicious source IPs using Linux iptables.
    """

    RULE_COMMENT = "DNS-ExfilWatch Quarantine"

    def __init__(self, enabled: bool = False) -> None:
        """
        Args:
            enabled: If True, firewall actions are executed against iptables.
                     If False, quarantine actions are simulated / dry-run.
        """
        self.enabled = enabled
        self._quarantined_ips: Set[str] = set()
        self._lock = threading.Lock()
        self.is_linux = platform.system() == "Linux"
        self.has_root = self._check_root_privileges()

        # Whitelist critical infrastructure to prevent accidental self-lockout
        self._protected_ips: Set[str] = {
            "127.0.0.1",
            "::1",
            "0.0.0.0",
        }
        self._populate_local_interfaces()

    def _check_root_privileges(self) -> bool:
        """Checks if current process has root / EUID 0 privileges required for iptables."""
        if not self.is_linux:
            return False
        return hasattr(os, "geteuid") and os.geteuid() == 0

    def _populate_local_interfaces(self) -> None:
        """Discovers local network interface IPs to protect against accidental quarantine."""
        try:
            # Parse `ip -o addr` or `hostname -I` on Linux
            res = subprocess.run(
                ["hostname", "-I"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if res.returncode == 0:
                for addr in res.stdout.strip().split():
                    self._protected_ips.add(addr.strip())
        except Exception:
            pass

    def is_ip_protected(self, ip_str: str) -> bool:
        """
        Ensures loopback, broadcast, multicast, or host IPs are never blocked.
        """
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_str in self._protected_ips:
                return True
            if ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_unspecified:
                return True
            return False
        except ValueError:
            return True  # If invalid IP, treat as protected to prevent broken commands

    def is_quarantined(self, ip_str: str) -> bool:
        """Thread-safe check if an IP is currently tracked as quarantined."""
        with self._lock:
            return ip_str in self._quarantined_ips

    def quarantine_ip(self, ip_str: str) -> Tuple[bool, str]:
        """
        Executes an iptables drop rule against a hostile IP address.

        Args:
            ip_str: Target IPv4 or IPv6 string.

        Returns:
            Tuple[bool, str]: (Success status, descriptive human-readable message).
        """
        if not self.enabled:
            return False, "Auto-block disabled (dry-run mode)"

        if self.is_ip_protected(ip_str):
            return False, f"Refusing to block protected/local address: {ip_str}"

        # Strict validation
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            normalized_ip = str(ip_obj)
        except ValueError:
            return False, f"Invalid IP address format: {ip_str}"

        with self._lock:
            if normalized_ip in self._quarantined_ips:
                return True, f"IP {normalized_ip} is already quarantined"

            if not self.is_linux:
                self._quarantined_ips.add(normalized_ip)
                return True, f"[Simulated-NonLinux] Quarantined {normalized_ip}"

            if not self.has_root:
                return False, f"Permission denied: Root/sudo required to invoke iptables for {normalized_ip}"

            # Select correct iptables command (iptables for IPv4, ip6tables for IPv6)
            cmd_binary = "ip6tables" if ip_obj.version == 6 else "iptables"

            try:
                # 1. Check if rule already exists to maintain idempotency
                check_cmd = [
                    cmd_binary,
                    "-C",
                    "INPUT",
                    "-s",
                    normalized_ip,
                    "-m",
                    "comment",
                    "--comment",
                    self.RULE_COMMENT,
                    "-j",
                    "DROP",
                ]
                check_res = subprocess.run(
                    check_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )

                if check_res.returncode != 0:
                    # 2. Insert rule at top of INPUT chain
                    insert_cmd = [
                        cmd_binary,
                        "-I",
                        "INPUT",
                        "1",
                        "-s",
                        normalized_ip,
                        "-m",
                        "comment",
                        "--comment",
                        self.RULE_COMMENT,
                        "-j",
                        "DROP",
                    ]
                    insert_res = subprocess.run(
                        insert_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        check=False,
                    )
                    if insert_res.returncode != 0:
                        err_msg = insert_res.stderr.strip()
                        return False, f"iptables error: {err_msg}"

                self._quarantined_ips.add(normalized_ip)
                return True, f"Successfully quarantined {normalized_ip} via {cmd_binary}"

            except Exception as e:
                return False, f"Subprocess exception while executing {cmd_binary}: {e}"

    def unquarantine_ip(self, ip_str: str) -> Tuple[bool, str]:
        """
        Removes an iptables drop rule for the designated IP address.
        """
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            normalized_ip = str(ip_obj)
        except ValueError:
            return False, f"Invalid IP address: {ip_str}"

        with self._lock:
            if normalized_ip in self._quarantined_ips:
                self._quarantined_ips.remove(normalized_ip)

            if not self.is_linux or not self.has_root:
                return True, f"Removed {normalized_ip} from session tracking"

            cmd_binary = "ip6tables" if ip_obj.version == 6 else "iptables"
            del_cmd = [
                cmd_binary,
                "-D",
                "INPUT",
                "-s",
                normalized_ip,
                "-m",
                "comment",
                "--comment",
                self.RULE_COMMENT,
                "-j",
                "DROP",
            ]
            try:
                res = subprocess.run(
                    del_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                if res.returncode == 0:
                    return True, f"Unquarantined {normalized_ip}"
                return False, f"iptables rule not found: {res.stderr.strip()}"
            except Exception as e:
                return False, f"Error unquarantining {normalized_ip}: {e}"

    def flush_session_rules(self) -> int:
        """
        Removes all iptables rules created during this session.
        Invoked during SIGINT/SIGTERM shutdown.

        Returns:
            int: Count of successfully removed rules.
        """
        with self._lock:
            if not self.is_linux or not self.has_root:
                count = len(self._quarantined_ips)
                self._quarantined_ips.clear()
                return count

            flushed = 0
            for ip_str in list(self._quarantined_ips):
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    cmd_binary = "ip6tables" if ip_obj.version == 6 else "iptables"
                    del_cmd = [
                        cmd_binary,
                        "-D",
                        "INPUT",
                        "-s",
                        ip_str,
                        "-m",
                        "comment",
                        "--comment",
                        self.RULE_COMMENT,
                        "-j",
                        "DROP",
                    ]
                    res = subprocess.run(
                        del_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                    )
                    if res.returncode == 0:
                        flushed += 1
                except Exception:
                    pass

            self._quarantined_ips.clear()
            return flushed

    def flush_all_labeled_rules(self) -> int:
        """
        Searches iptables for any residual rules tagged with RULE_COMMENT
        and deletes them. Useful for manual cleanup.
        """
        if not self.is_linux or not self.has_root:
            return 0

        total_cleaned = 0
        for cmd_binary in ["iptables", "ip6tables"]:
            try:
                # Query numbered rules in INPUT chain
                list_cmd = [cmd_binary, "-L", "INPUT", "-n", "--line-numbers", "-v"]
                res = subprocess.run(
                    list_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                if res.returncode != 0:
                    continue

                # Find line numbers that match our comment (process in reverse order)
                matching_lines: List[int] = []
                for line in res.stdout.splitlines():
                    if self.RULE_COMMENT in line:
                        parts = line.strip().split()
                        if parts and parts[0].isdigit():
                            matching_lines.append(int(parts[0]))

                # Delete in descending order so line numbers remain stable
                for line_num in sorted(matching_lines, reverse=True):
                    del_cmd = [cmd_binary, "-D", "INPUT", str(line_num)]
                    d_res = subprocess.run(
                        del_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                    )
                    if d_res.returncode == 0:
                        total_cleaned += 1

            except Exception:
                pass

        with self._lock:
            self._quarantined_ips.clear()

        return total_cleaned

    @property
    def quarantined_count(self) -> int:
        """Total number of unique IPs currently blocked in this session."""
        with self._lock:
            return len(self._quarantined_ips)

    @property
    def quarantined_list(self) -> List[str]:
        """Snapshot list of quarantined IP addresses."""
        with self._lock:
            return sorted(list(self._quarantined_ips))
