#!/usr/bin/env python3
"""
Tests for the MAVLink protocol parser and packet crafter.
"""

import os
import sys
import struct
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "honeypot"))

from honeypot.core.protocol import MAVLinkProtocol


class TestParsePacket:
    """Test MAVLinkProtocol.parse_packet()."""

    def test_parse_v1_heartbeat(self, heartbeat_packet):
        """Valid v1 HEARTBEAT should parse correctly."""
        result = MAVLinkProtocol.parse_packet(heartbeat_packet)
        assert result is not None
        assert result["version"] == 1
        assert result["msg_id"] == 0
        assert result["sys_id"] == 1
        assert result["comp_id"] == 1

    def test_parse_v1_set_mode(self, set_mode_packet):
        """SET_MODE (msg_id=11) should be parsed."""
        result = MAVLinkProtocol.parse_packet(set_mode_packet)
        assert result is not None
        assert result["msg_id"] == 11

    def test_parse_v2_packet(self):
        """MAVLink v2 (0xFD) should be parsed."""
        # Construct a minimal v2 packet: 0xFD, len, incompat, compat, seq,
        # sysid, compid, msgid_low, msgid_mid, msgid_high, payload, crc
        payload = b"\x00" * 5
        msg_id_bytes = struct.pack("<I", 42)[:3]  # 24-bit msg_id
        header = bytes([0xFD, len(payload), 0, 0, 0, 1, 1]) + msg_id_bytes
        packet = header + payload + b"\x00\x00"
        result = MAVLinkProtocol.parse_packet(packet)
        assert result is not None
        assert result["version"] == 2
        assert result["msg_id"] == 42

    def test_parse_empty_returns_none(self):
        assert MAVLinkProtocol.parse_packet(b"") is None

    def test_parse_too_short_returns_none(self):
        assert MAVLinkProtocol.parse_packet(b"\xfe\x00\x01") is None

    def test_parse_wrong_stx_returns_none(self):
        assert MAVLinkProtocol.parse_packet(b"\x00" * 20) is None

    def test_parse_v2_too_short_returns_none(self):
        """v2 packets need at least 10 bytes header."""
        assert MAVLinkProtocol.parse_packet(b"\xfd\x00\x00\x00\x00\x00") is None

    def test_parse_payload_truncation(self):
        """When data is shorter than payload_len, payload should be empty bytes."""
        packet = bytes([0xFE, 20, 0, 1, 1, 0]) + b"\x00" * 5  # only 5 payload bytes, claimed 20
        result = MAVLinkProtocol.parse_packet(packet)
        assert result is not None
        assert result["payload"] == b""

    def test_parse_preserves_sequence(self, craft_mavlink_packet):
        """Sequence number should be accurately extracted."""
        pkt = craft_mavlink_packet(msg_id=0, seq=42)
        result = MAVLinkProtocol.parse_packet(pkt)
        assert result["seq"] == 42


class TestCraftHeartbeat:
    """Test MAVLinkProtocol.craft_heartbeat()."""

    def setup_method(self):
        self.proto = MAVLinkProtocol(sys_id=1, comp_id=1)

    def test_starts_with_stx(self):
        hb = self.proto.craft_heartbeat()
        assert hb[0] == 0xFE

    def test_msg_id_is_zero(self):
        hb = self.proto.craft_heartbeat()
        assert hb[5] == 0  # msg_id for HEARTBEAT

    def test_sys_id_embedded(self):
        hb = self.proto.craft_heartbeat()
        assert hb[3] == 1

    def test_custom_mode_encoded(self):
        hb = self.proto.craft_heartbeat(base_mode=209, custom_mode=5)
        # base_mode is at payload offset 4 (struct '<IBBBB B')
        # payload starts at byte 6
        payload = hb[6:-2]
        custom, mav_type, autopilot, base, status, version = struct.unpack("<IBBBBB", payload)
        assert custom == 5
        assert base == 209

    def test_roundtrip_parse(self):
        """Crafted packet should be parseable."""
        hb = self.proto.craft_heartbeat()
        parsed = MAVLinkProtocol.parse_packet(hb)
        assert parsed is not None
        assert parsed["msg_id"] == 0
        assert parsed["sys_id"] == 1


class TestCraftGPS:
    """Test MAVLinkProtocol.craft_gps_raw()."""

    def setup_method(self):
        self.proto = MAVLinkProtocol(sys_id=1, comp_id=1)

    def test_msg_id_is_24(self):
        pkt = self.proto.craft_gps_raw(lat=37.0, lon=-122.0, alt=100, speed=5, heading=90)
        assert pkt[5] == 24  # GPS_RAW_INT

    def test_roundtrip_parse(self):
        pkt = self.proto.craft_gps_raw(lat=37.0, lon=-122.0, alt=100, speed=5, heading=90)
        parsed = MAVLinkProtocol.parse_packet(pkt)
        assert parsed is not None
        assert parsed["msg_id"] == 24

    def test_lat_lon_encoded(self):
        pkt = self.proto.craft_gps_raw(lat=37.7749, lon=-122.4194, alt=100, speed=0, heading=0)
        payload = pkt[6:-2]
        # Skip 8-byte timestamp, then lat(i), lon(i)
        lat_raw, lon_raw = struct.unpack_from("<ii", payload, 8)
        assert abs(lat_raw - int(37.7749 * 1e7)) < 2
        assert abs(lon_raw - int(-122.4194 * 1e7)) < 2


class TestCraftBattery:
    """Test MAVLinkProtocol.craft_battery_status()."""

    def setup_method(self):
        self.proto = MAVLinkProtocol(sys_id=1, comp_id=1)

    def test_msg_id_is_147(self):
        pkt = self.proto.craft_battery_status(battery_pct=85.0)
        assert pkt[5] == 147  # BATTERY_STATUS

    def test_roundtrip_parse(self):
        pkt = self.proto.craft_battery_status(battery_pct=50.0)
        parsed = MAVLinkProtocol.parse_packet(pkt)
        assert parsed is not None
        assert parsed["msg_id"] == 147

    def test_battery_remaining_encoded(self):
        """battery_remaining is the last byte of the payload."""
        pkt = self.proto.craft_battery_status(battery_pct=75.0)
        payload = pkt[6:-2]
        remaining = struct.unpack_from("<b", payload, len(payload) - 1)[0]
        assert remaining == 75
