#!/usr/bin/env python3
"""
Tests for MAVLink semantic analysis and intent classification.
"""

import os
import sys
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, 'honeypot'))


class TestMAVLinkSemantics:
    """Test the MAVLINK_SEMANTICS dictionary and intent classification."""

    def setup_method(self):
        from mavlink_honeypot import MAVLINK_SEMANTICS, ATTACK_PATTERNS
        self.semantics = MAVLINK_SEMANTICS
        self.patterns = ATTACK_PATTERNS

    def test_heartbeat_is_recon(self):
        """HEARTBEAT (0) should be classified as RECON with severity 1."""
        assert 0 in self.semantics
        assert self.semantics[0]["intent"] == "RECON"
        assert self.semantics[0]["severity"] == 1

    def test_set_mode_is_control(self):
        """SET_MODE (11) should be classified as CONTROL."""
        assert 11 in self.semantics
        assert self.semantics[11]["intent"] == "CONTROL"

    def test_command_long_is_control(self):
        """COMMAND_LONG (76) should be classified as CONTROL."""
        assert 76 in self.semantics
        assert self.semantics[76]["intent"] == "CONTROL"

    def test_gps_messages_identified(self):
        """GPS-related messages should be mapped."""
        gps_ids = [113, 132]  # GPS_SPOOF pattern
        for mid in gps_ids:
            if mid in self.semantics:
                assert self.semantics[mid]["severity"] >= 3

    def test_mission_inject_severity(self):
        """Mission inject messages should have high severity."""
        mission_msgs = [k for k, v in self.semantics.items()
                        if v.get("intent") == "MISSION_INJECT"]
        for mid in mission_msgs:
            assert self.semantics[mid]["severity"] >= 5, (
                f"msg_id {mid} ({self.semantics[mid]['name']}) has severity "
                f"{self.semantics[mid]['severity']}, expected >= 5"
            )

    def test_all_entries_have_required_fields(self):
        """Every entry should have name, intent, and severity."""
        for msg_id, entry in self.semantics.items():
            assert "name" in entry, f"msg_id {msg_id} missing 'name'"
            assert "intent" in entry, f"msg_id {msg_id} missing 'intent'"
            assert "severity" in entry, f"msg_id {msg_id} missing 'severity'"

    def test_severity_range(self):
        """All severity values should be 1-10."""
        for msg_id, entry in self.semantics.items():
            assert 1 <= entry["severity"] <= 10, (
                f"msg_id {msg_id} severity {entry['severity']} out of range"
            )

    def test_valid_intent_values(self):
        """All intents should be from the known set."""
        valid_intents = {
            "RECON", "CONTROL", "FIRMWARE", "GPS_SPOOF",
            "MISSION_INJECT", "SENSOR_SPOOF", "CONFIG_ATTACK",
            "HIJACK", "UNKNOWN"
        }
        for msg_id, entry in self.semantics.items():
            assert entry["intent"] in valid_intents, (
                f"msg_id {msg_id} has unknown intent '{entry['intent']}'"
            )

    def test_attack_patterns_defined(self):
        """Attack patterns should be defined."""
        assert "DOS" in self.patterns
        assert "GPS_SPOOF" in self.patterns
        assert "HIJACK_SEQUENCE" in self.patterns

    def test_dos_pattern_has_threshold(self):
        """DoS pattern should have threshold and window."""
        dos = self.patterns["DOS"]
        assert "threshold" in dos
        assert "window" in dos
        assert dos["threshold"] > 0


class TestIntentAnalysis:
    """Test the analyze_intent method of AdaptiveHoneypot."""

    def setup_method(self):
        from mavlink_honeypot import AdaptiveHoneypot
        from honeypot.core.semantic_analyzer import SemanticAnalyzer
        self.hp = AdaptiveHoneypot.__new__(AdaptiveHoneypot)
        # Minimal init for analyze_intent
        self.hp.analyzer = SemanticAnalyzer()
        self.hp.session_data = self.hp.analyzer.session_data
        self.hp.msg_timestamps = self.hp.analyzer.msg_timestamps
        self.hp.events = []
        self.hp.attacker_profiles = {}

    def test_known_message_returns_semantics(self):
        """analyze_intent should return correct dict for known msg_id."""
        from mavlink_honeypot import MAVLINK_SEMANTICS
        result = self.hp.analyze_intent(0, ("127.0.0.1", 12345))
        assert result["name"] == "HEARTBEAT"
        assert result["intent"] == "RECON"

    def test_unknown_message_returns_unknown(self):
        """analyze_intent should handle unknown msg_id gracefully."""
        result = self.hp.analyze_intent(999, ("127.0.0.1", 12345))
        assert result["intent"] == "UNKNOWN"


class TestPacketParsing:
    """Test MAVLink packet parsing."""

    def setup_method(self):
        from mavlink_honeypot import AdaptiveHoneypot
        from honeypot.core.protocol import MAVLinkProtocol
        self.hp = AdaptiveHoneypot.__new__(AdaptiveHoneypot)
        self.hp.protocol = MAVLinkProtocol()

    def test_parse_valid_v1_packet(self, heartbeat_packet):
        """Should parse a valid MAVLink v1 HEARTBEAT."""
        result = self.hp.parse_mavlink_packet(heartbeat_packet)
        assert result is not None
        assert result["msg_id"] == 0

    def test_parse_too_short_returns_none(self):
        """Packets shorter than 8 bytes should return None."""
        result = self.hp.parse_mavlink_packet(b'\xfe\x00')
        assert result is None

    def test_parse_wrong_start_byte(self):
        """Non-MAVLink data should return None."""
        result = self.hp.parse_mavlink_packet(b'\x00' * 20)
        assert result is None

    def test_parse_empty_returns_none(self):
        """Empty data should return None."""
        result = self.hp.parse_mavlink_packet(b'')
        assert result is None
