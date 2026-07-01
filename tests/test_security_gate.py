#!/usr/bin/env python3
"""
Tests for SecurityGate: rate limiting, blocklisting, connection limits, packet validation.
"""

import os
import sys
import time
import struct
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, 'honeypot'))


class TestSecurityGateBlocking:
    """Test IP blocking and blocklist management."""

    def setup_method(self):
        from mavlink_honeypot import SecurityGate
        self.gate = SecurityGate()

    def test_new_ip_not_blocked(self):
        """Fresh IPs should not be blocked."""
        assert not self.gate.is_blocked("10.0.0.1")

    def test_manual_block(self):
        """Manually added blocklist entries should be enforced."""
        self.gate.blocklist["10.0.0.99"] = time.time() + 3600
        assert self.gate.is_blocked("10.0.0.99")

    def test_expired_block_is_removed(self):
        """Expired blocklist entries should no longer block."""
        self.gate.blocklist["10.0.0.50"] = time.time() - 1  # expired
        assert not self.gate.is_blocked("10.0.0.50")


class TestSecurityGateConnections:
    """Test connection limit enforcement."""

    def setup_method(self):
        from mavlink_honeypot import SecurityGate
        self.gate = SecurityGate()

    def test_first_connection_allowed(self):
        """First connection from an IP should be allowed."""
        assert self.gate.can_connect("10.0.0.1")

    def test_connection_count_tracks(self):
        """Registering connections should increment counter."""
        ip = "10.0.0.1"
        self.gate.register_connection(ip)
        self.gate.register_connection(ip)
        assert self.gate.active_connections[ip] == 2

    def test_unregister_decrements(self):
        """Unregistering should decrement connection counter."""
        ip = "10.0.0.1"
        self.gate.register_connection(ip)
        self.gate.register_connection(ip)
        self.gate.unregister_connection(ip)
        assert self.gate.active_connections[ip] == 1

    def test_max_connections_enforced(self):
        """Exceeding MAX_CONNECTIONS_PER_IP should reject."""
        ip = "10.0.0.1"
        for _ in range(self.gate.MAX_CONNECTIONS_PER_IP):
            self.gate.register_connection(ip)
        assert not self.gate.can_connect(ip)


class TestSecurityGateRateLimit:
    """Test packet rate limiting."""

    def setup_method(self):
        from mavlink_honeypot import SecurityGate
        self.gate = SecurityGate()

    def test_first_packet_allowed(self):
        """First packet from an IP should pass rate check."""
        assert self.gate.check_rate("10.0.0.1")

    def test_under_limit_passes(self):
        """Packets under the threshold should all pass."""
        ip = "10.0.0.2"
        for _ in range(self.gate.MAX_PACKETS_PER_WINDOW - 1):
            assert self.gate.check_rate(ip)

    def test_over_limit_fails(self):
        """Exceeding MAX_PACKETS_PER_WINDOW should fail."""
        ip = "10.0.0.3"
        for _ in range(self.gate.MAX_PACKETS_PER_WINDOW):
            self.gate.check_rate(ip)
        assert not self.gate.check_rate(ip)


class TestSecurityGatePacketValidation:
    """Test packet structure validation."""

    def setup_method(self):
        from mavlink_honeypot import SecurityGate
        self.gate = SecurityGate()

    def test_valid_mavlink_v1(self, heartbeat_packet):
        """A properly formed MAVLink v1 packet should pass validation."""
        assert self.gate.validate_packet(heartbeat_packet)

    def test_oversized_packet_rejected(self):
        """Packets exceeding MAX_PAYLOAD_BYTES should be rejected."""
        oversized = b'\xfe' + b'\x00' * 500
        assert not self.gate.validate_packet(oversized)

    def test_empty_packet_rejected(self):
        """Empty data should be rejected."""
        assert not self.gate.validate_packet(b'')

    def test_wrong_start_byte_rejected(self):
        """Non-MAVLink packets should be rejected."""
        fake = b'\x00\x09\x00\x01\x01\x00' + b'\x00' * 9 + b'\x00\x00'
        assert not self.gate.validate_packet(fake)


class TestConnectionSandbox:
    """Test per-connection sandbox isolation."""

    def setup_method(self):
        from mavlink_honeypot import ConnectionSandbox
        self.Sandbox = ConnectionSandbox

    def test_create_returns_instance(self):
        """Factory method should return a valid sandbox."""
        sb = self.Sandbox.create()
        assert sb is not None
        assert sb.current_state == "NORMAL"

    def test_sandboxes_isolated(self):
        """Two sandboxes should have independent state."""
        sb1 = self.Sandbox.create()
        sb2 = self.Sandbox.create()
        sb1.decoy_lat = 99.0
        sb1.current_state = "CRASHED"
        assert sb2.decoy_lat != 99.0
        assert sb2.current_state == "NORMAL"

    def test_default_values(self):
        """Sandbox defaults should be sensible."""
        sb = self.Sandbox.create()
        assert sb.decoy_battery == 100.0
        assert sb.packets_received == 0
