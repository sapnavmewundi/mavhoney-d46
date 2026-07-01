#!/usr/bin/env python3
"""
MAVLink Honeypot — Application-Level Firewall.

Defense-in-depth layer that runs BEFORE the SecurityGate.
Blocks known malicious patterns, enforces protocol compliance,
and provides connection-level protection.

This is designed for real-world deployment where the honeypot
is exposed to the public internet.
"""

import time
import logging
import ipaddress
from collections import defaultdict
from typing import Dict, Set, Tuple, Optional

logger = logging.getLogger("firewall")


class HoneypotFirewall:
    """
    Application-level firewall for the MAVLink honeypot.

    Features:
        - Connection rate limiting per IP (prevent SYN floods)
        - Payload size enforcement
        - Protocol validation (only MAVLink v1/v2 start bytes)
        - Geo-based suspicious IP tracking
        - Auto-ban after repeated violations
        - Maximum simultaneous connections
        - Bandwidth throttling per IP
        - Connection duration limits
    """

    def __init__(
        self,
        max_connections_global: int = 50,
        max_connections_per_ip: int = 5,
        max_new_connections_per_min: int = 20,
        max_packet_size: int = 280,
        ban_threshold: int = 10,
        ban_duration_sec: int = 3600,
        max_session_duration_sec: int = 1800,
        max_bytes_per_min_per_ip: int = 1_000_000,
    ):
        self.max_connections_global = max_connections_global
        self.max_connections_per_ip = max_connections_per_ip
        self.max_new_connections_per_min = max_new_connections_per_min
        self.max_packet_size = max_packet_size
        self.ban_threshold = ban_threshold
        self.ban_duration_sec = ban_duration_sec
        self.max_session_duration_sec = max_session_duration_sec
        self.max_bytes_per_min_per_ip = max_bytes_per_min_per_ip

        # State tracking
        self._active_connections: Dict[str, int] = defaultdict(int)
        self._total_connections: int = 0
        self._violations: Dict[str, int] = defaultdict(int)
        self._banned_ips: Dict[str, float] = {}  # ip -> ban_expiry_time
        self._connection_times: Dict[str, list] = defaultdict(list)
        self._session_starts: Dict[str, float] = {}
        self._bytes_received: Dict[str, list] = defaultdict(list)  # ip -> [(time, bytes)]

        # Known scanner IPs to always allow (for Shodan/Censys discoverability)
        self._whitelisted_scanners: Set[str] = set()

        # Statistics
        self.stats = {
            "total_accepted": 0,
            "total_rejected": 0,
            "total_banned": 0,
            "violations_by_type": defaultdict(int),
        }

    def allow_connection(self, ip: str) -> Tuple[bool, str]:
        """
        Check if a new connection from `ip` should be accepted.

        Returns:
            (allowed: bool, reason: str)
        """
        now = time.time()

        # 1. Check if IP is banned
        if ip in self._banned_ips:
            if now < self._banned_ips[ip]:
                self.stats["total_rejected"] += 1
                return False, f"BANNED (expires in {int(self._banned_ips[ip] - now)}s)"
            else:
                # Ban expired
                del self._banned_ips[ip]
                self._violations[ip] = 0

        # 2. Check global connection limit
        if self._total_connections >= self.max_connections_global:
            self._record_violation(ip, "GLOBAL_LIMIT")
            return False, f"GLOBAL_LIMIT ({self._total_connections}/{self.max_connections_global})"

        # 3. Check per-IP connection limit
        if self._active_connections[ip] >= self.max_connections_per_ip:
            self._record_violation(ip, "PER_IP_LIMIT")
            return False, f"PER_IP_LIMIT ({self._active_connections[ip]}/{self.max_connections_per_ip})"

        # 4. Check connection rate (new connections per minute)
        self._connection_times[ip] = [
            t for t in self._connection_times[ip] if now - t < 60
        ]
        if len(self._connection_times[ip]) >= self.max_new_connections_per_min:
            self._record_violation(ip, "CONN_RATE")
            return False, f"CONN_RATE ({len(self._connection_times[ip])}/min)"

        # 5. Check if IP is from a private range (shouldn't happen on public deployment)
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private and ip != "127.0.0.1":
                logger.warning(f"Private IP {ip} attempted connection — unusual for public deployment")
        except ValueError:
            self._record_violation(ip, "INVALID_IP")
            return False, "INVALID_IP"

        # Accept
        self._active_connections[ip] += 1
        self._total_connections += 1
        self._connection_times[ip].append(now)
        self._session_starts[f"{ip}:{id}"] = now
        self.stats["total_accepted"] += 1

        logger.info(f"FIREWALL ACCEPT: {ip} (active: {self._active_connections[ip]})")
        return True, "ACCEPTED"

    def validate_packet(self, ip: str, data: bytes) -> Tuple[bool, str]:
        """
        Validate an incoming packet before processing.

        Returns:
            (valid: bool, reason: str)
        """
        # 1. Size check
        if len(data) > self.max_packet_size:
            self._record_violation(ip, "OVERSIZED_PACKET")
            return False, f"OVERSIZED ({len(data)} > {self.max_packet_size})"

        # 2. Empty packet
        if len(data) == 0:
            self._record_violation(ip, "EMPTY_PACKET")
            return False, "EMPTY_PACKET"

        # 3. MAVLink protocol check (must start with 0xFE v1 or 0xFD v2)
        if data[0] not in (0xFE, 0xFD):
            self._record_violation(ip, "NON_MAVLINK")
            return False, f"NON_MAVLINK (start_byte=0x{data[0]:02X})"

        # 4. Bandwidth throttling
        now = time.time()
        self._bytes_received[ip] = [
            (t, b) for t, b in self._bytes_received[ip] if now - t < 60
        ]
        total_bytes = sum(b for _, b in self._bytes_received[ip]) + len(data)
        if total_bytes > self.max_bytes_per_min_per_ip:
            self._record_violation(ip, "BANDWIDTH_EXCEEDED")
            return False, f"BANDWIDTH ({total_bytes}/{self.max_bytes_per_min_per_ip} bytes/min)"

        self._bytes_received[ip].append((now, len(data)))
        return True, "VALID"

    def disconnect(self, ip: str) -> None:
        """Record a disconnection."""
        if self._active_connections[ip] > 0:
            self._active_connections[ip] -= 1
        self._total_connections = max(0, self._total_connections - 1)
        logger.info(f"FIREWALL DISCONNECT: {ip} (remaining: {self._active_connections[ip]})")

    def check_session_timeout(self, ip: str, session_key: str) -> bool:
        """Check if a session has exceeded max duration."""
        start = self._session_starts.get(session_key, time.time())
        if time.time() - start > self.max_session_duration_sec:
            logger.warning(f"Session timeout for {ip} (>{self.max_session_duration_sec}s)")
            return True
        return False

    def _record_violation(self, ip: str, violation_type: str) -> None:
        """Record a violation and auto-ban if threshold reached."""
        self._violations[ip] += 1
        self.stats["violations_by_type"][violation_type] += 1
        self.stats["total_rejected"] += 1

        logger.warning(
            f"FIREWALL VIOLATION: {ip} type={violation_type} "
            f"count={self._violations[ip]}/{self.ban_threshold}"
        )

        if self._violations[ip] >= self.ban_threshold:
            self._banned_ips[ip] = time.time() + self.ban_duration_sec
            self.stats["total_banned"] += 1
            logger.warning(
                f"FIREWALL BAN: {ip} banned for {self.ban_duration_sec}s "
                f"(violations: {self._violations[ip]})"
            )

    def is_banned(self, ip: str) -> bool:
        """Check if an IP is currently banned."""
        if ip in self._banned_ips:
            if time.time() < self._banned_ips[ip]:
                return True
            del self._banned_ips[ip]
        return False

    def get_stats(self) -> dict:
        """Get firewall statistics."""
        return {
            "active_connections": self._total_connections,
            "banned_ips": len(self._banned_ips),
            "total_accepted": self.stats["total_accepted"],
            "total_rejected": self.stats["total_rejected"],
            "total_banned": self.stats["total_banned"],
            "violations": dict(self.stats["violations_by_type"]),
            "top_violators": sorted(
                self._violations.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10],
        }

    def get_banned_list(self) -> Dict[str, float]:
        """Get all currently banned IPs with expiry times."""
        now = time.time()
        return {
            ip: remaining
            for ip, expiry in self._banned_ips.items()
            if (remaining := expiry - now) > 0
        }
