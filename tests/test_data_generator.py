#!/usr/bin/env python3
"""
Synthetic MAVLink attack data generator for testing and demos.
Generates realistic attack sequences for all intents.
"""

import os
import sys
import json
import csv
import struct
import random
import time
from datetime import datetime, timedelta

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, 'honeypot'))


# Attack intent profiles with realistic timing and message sequences
ATTACK_PROFILES = {
    "recon_scan": {
        "description": "Network reconnaissance scan",
        "msg_ids": [0, 1, 20, 21, 24, 245, 252, 253],
        "duration_range": (5, 30),
        "packet_rate_range": (1, 5),
        "severity_max": 2,
    },
    "gps_spoof": {
        "description": "GPS spoofing attack",
        "msg_ids": [113, 132, 0],
        "duration_range": (10, 60),
        "packet_rate_range": (5, 20),
        "severity_max": 8,
    },
    "hijack_attempt": {
        "description": "Full drone hijack sequence",
        "msg_ids": [400, 76, 84, 86, 11],
        "duration_range": (30, 120),
        "packet_rate_range": (2, 10),
        "severity_max": 9,
    },
    "dos_flood": {
        "description": "Denial of service flood",
        "msg_ids": [0, 1, 76],
        "duration_range": (10, 60),
        "packet_rate_range": (50, 200),
        "severity_max": 7,
    },
    "mission_inject": {
        "description": "Malicious mission upload",
        "msg_ids": [510, 511, 512, 513, 514],
        "duration_range": (20, 90),
        "packet_rate_range": (1, 5),
        "severity_max": 9,
    },
    "mixed_advanced": {
        "description": "Advanced attacker with mixed techniques",
        "msg_ids": [0, 20, 76, 11, 113, 510, 400],
        "duration_range": (60, 300),
        "packet_rate_range": (1, 15),
        "severity_max": 10,
    },
}

FAKE_IPS = [
    "45.33.32.156", "185.220.101.35", "103.235.47.18",
    "192.168.1.100", "10.0.0.50", "172.16.0.15",
    "209.141.59.40", "77.247.181.163", "116.6.57.211",
    "91.219.237.244", "198.51.100.23", "203.0.113.42",
]


def generate_events(
    num_events: int = 100,
    profile: str = "mixed_advanced",
    start_time: datetime = None,
) -> list:
    """
    Generate synthetic attack events.

    Args:
        num_events: Number of events to generate
        profile: Attack profile name from ATTACK_PROFILES
        start_time: Start timestamp (default: now)

    Returns:
        List of event dicts
    """
    from mavlink_honeypot import MAVLINK_SEMANTICS

    prof = ATTACK_PROFILES.get(profile, ATTACK_PROFILES["mixed_advanced"])
    if start_time is None:
        start_time = datetime.now() - timedelta(hours=1)

    events = []
    current_time = start_time
    attacker_ip = random.choice(FAKE_IPS)
    session_id = f"sim_{random.randint(1000, 9999)}"

    for i in range(num_events):
        msg_id = random.choice(prof["msg_ids"])
        semantics = MAVLINK_SEMANTICS.get(msg_id, {
            "name": f"MSG_{msg_id}", "intent": "UNKNOWN", "severity": 3
        })

        # Realistic timing
        delay = random.uniform(
            1.0 / prof["packet_rate_range"][1],
            1.0 / prof["packet_rate_range"][0]
        )
        current_time += timedelta(seconds=delay)

        # Random payload (hex)
        payload_len = random.randint(4, 32)
        payload_hex = os.urandom(payload_len).hex()

        # Fake telemetry
        lat = 37.7749 + random.uniform(-0.01, 0.01)
        lon = -122.4194 + random.uniform(-0.01, 0.01)

        event = {
            "timestamp": current_time.isoformat(),
            "attacker_ip": attacker_ip,
            "attacker_port": random.randint(30000, 65000),
            "msg_id": msg_id,
            "msg_name": semantics["name"],
            "intent": semantics["intent"],
            "severity": semantics["severity"],
            "payload_hex": payload_hex,
            "session_id": session_id,
            "fake_response_type": random.choice(["HEARTBEAT", "GPS_RAW_INT", "BATTERY_STATUS"]),
            "fake_gps_lat": round(lat, 6),
            "fake_gps_lon": round(lon, 6),
            "fake_altitude": round(random.uniform(50, 500), 1),
            "fake_battery": round(random.uniform(20, 100), 1),
            "fake_heading": random.randint(0, 359),
            "fake_speed": round(random.uniform(0, 30), 1),
            "honeypot_state": random.choice(["NORMAL", "WEAK", "CONFUSED"]),
        }
        events.append(event)

        # Occasional IP rotation (simulates multi-source attack)
        if random.random() < 0.1:
            attacker_ip = random.choice(FAKE_IPS)

    return events


def generate_dataset_csv(output_path: str, num_events: int = 500):
    """Generate a CSV dataset for ML training."""
    events = generate_events(num_events)

    fieldnames = list(events[0].keys())
    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(events)

    return output_path


def generate_log_json(output_path: str, num_events: int = 200):
    """Generate a JSON log file."""
    events = generate_events(num_events)
    with open(output_path, 'w') as f:
        json.dump(events, f, indent=2)
    return output_path


# ── Tests ──

class TestDataGenerator:
    """Test the data generator itself."""

    def test_generate_events_count(self):
        """Should generate the requested number of events."""
        events = generate_events(50, "recon_scan")
        assert len(events) == 50

    def test_event_structure(self):
        """Events should have all required fields."""
        events = generate_events(1)
        event = events[0]
        required = ["timestamp", "attacker_ip", "msg_id", "msg_name",
                     "intent", "severity", "session_id"]
        for field in required:
            assert field in event, f"Missing field: {field}"

    def test_all_profiles(self):
        """All attack profiles should generate valid events."""
        for profile_name in ATTACK_PROFILES:
            events = generate_events(10, profile_name)
            assert len(events) == 10
            assert all("msg_id" in e for e in events)

    def test_csv_generation(self, temp_dir):
        """Should write a valid CSV file."""
        path = os.path.join(temp_dir, "test_dataset.csv")
        generate_dataset_csv(path, 20)
        assert os.path.exists(path)
        with open(path) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 20

    def test_json_generation(self, temp_dir):
        """Should write a valid JSON file."""
        path = os.path.join(temp_dir, "test_log.json")
        generate_log_json(path, 15)
        assert os.path.exists(path)
        with open(path) as f:
            data = json.load(f)
        assert len(data) == 15

    def test_timestamps_ordered(self):
        """Events should have monotonically increasing timestamps."""
        events = generate_events(50)
        timestamps = [e["timestamp"] for e in events]
        assert timestamps == sorted(timestamps)

    def test_severity_in_range(self):
        """Severity should always be 1-10."""
        events = generate_events(100, "mixed_advanced")
        for e in events:
            assert 1 <= e["severity"] <= 10
