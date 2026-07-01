#!/usr/bin/env python3
"""
Pytest configuration and shared fixtures for MAVLink honeypot tests.
"""

import os
import sys
import json
import struct
import pytest
import tempfile
import shutil

# Ensure project root is on path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, 'honeypot'))


@pytest.fixture
def project_root():
    """Return the project root directory."""
    return PROJECT_ROOT


@pytest.fixture
def temp_dir():
    """Provide a temporary directory, cleaned up after test."""
    d = tempfile.mkdtemp(prefix="mavhoney_test_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def temp_logs_dir(temp_dir):
    """Provide a temporary logs directory."""
    logs = os.path.join(temp_dir, "logs")
    os.makedirs(logs)
    return logs


def _mavlink_checksum(data: bytes) -> int:
    """Calculate MAVLink CRC (X.25/CCITT checksum)."""
    crc = 0xFFFF
    for byte in data:
        tmp = byte ^ (crc & 0xFF)
        tmp ^= (tmp << 4) & 0xFF
        crc = (crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)
        crc &= 0xFFFF
    return crc


@pytest.fixture
def craft_mavlink_packet():
    """
    Factory fixture to craft valid MAVLink v1.0 packets.

    Usage:
        packet = craft_mavlink_packet(msg_id=0, payload=b'\\x00' * 9)
    """
    def _craft(msg_id: int = 0, payload: bytes = b'\x00' * 9,
               sys_id: int = 1, comp_id: int = 1, seq: int = 0) -> bytes:
        header = struct.pack('<BBBBB',
            len(payload),  # payload length
            seq & 0xFF,    # sequence
            sys_id,        # system ID
            comp_id,       # component ID
            msg_id & 0xFF  # message ID
        )
        packet = b'\xfe' + header + payload  # 0xFE = MAVLink v1 start
        crc = _mavlink_checksum(header + payload)
        packet += struct.pack('<H', crc)
        return packet
    return _craft


@pytest.fixture
def heartbeat_packet(craft_mavlink_packet):
    """A valid MAVLink HEARTBEAT packet (msg_id=0)."""
    # HEARTBEAT: type, autopilot, base_mode, custom_mode(4B), sys_status
    payload = struct.pack('<BBBIB', 6, 3, 81, 0, 4)  # MAV_TYPE_GCS, MAV_AUTOPILOT_ARDUPILOTMEGA
    return craft_mavlink_packet(msg_id=0, payload=payload)


@pytest.fixture
def set_mode_packet(craft_mavlink_packet):
    """A MAVLink SET_MODE packet (msg_id=11)."""
    payload = struct.pack('<IBB', 0, 1, 81)  # custom_mode, target_system, base_mode
    return craft_mavlink_packet(msg_id=11, payload=payload)


@pytest.fixture
def command_long_packet(craft_mavlink_packet):
    """A MAVLink COMMAND_LONG packet (msg_id=76)."""
    payload = struct.pack('<7fHBB', 0, 0, 0, 0, 0, 0, 0, 400, 1, 0)
    return craft_mavlink_packet(msg_id=76, payload=payload)


@pytest.fixture
def sample_attack_event():
    """A sample AttackEvent dict for testing."""
    return {
        "timestamp": "2024-01-01T12:00:00",
        "attacker_ip": "192.168.1.100",
        "attacker_port": 54321,
        "msg_id": 76,
        "msg_name": "COMMAND_LONG",
        "intent": "CONTROL",
        "severity": 6,
        "payload_hex": "00" * 33,
        "session_id": "abc12345",
        "fake_response_type": "HEARTBEAT",
        "fake_gps_lat": 37.7749,
        "fake_gps_lon": -122.4194,
        "fake_altitude": 100.0,
        "fake_battery": 85.0,
        "fake_heading": 270,
        "fake_speed": 5.0,
        "honeypot_state": "NORMAL",
    }


@pytest.fixture
def sample_events_file(temp_dir, sample_attack_event):
    """Write sample events to a JSON log file."""
    events = [sample_attack_event for _ in range(5)]
    filepath = os.path.join(temp_dir, "events.json")
    with open(filepath, 'w') as f:
        json.dump(events, f)
    return filepath
