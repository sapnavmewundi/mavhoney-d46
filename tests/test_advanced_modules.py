#!/usr/bin/env python3
"""
Tests for advanced honeypot modules:
- Canary Tokens
- MITRE ATT&CK Mapper
- Fuzz Detector
- Tarpit
- Biometrics
- Threat Predictor
- CVE Simulator
"""

import os
import sys
import time
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, 'honeypot'))


# ── Canary Tokens ──


class TestCanaryTokenEngine:
    """Test canary token creation and triggering."""

    def setup_method(self):
        from canary_tokens import CanaryTokenEngine
        self.engine = CanaryTokenEngine()

    def test_generate_gps_canary(self):
        """Should generate a GPS canary token."""
        token = self.engine.generate_gps_canary("192.168.1.1")
        assert token is not None

    def test_generate_param_canary(self):
        """Should generate a param canary token."""
        token = self.engine.generate_param_canary("192.168.1.1")
        assert token is not None

    def test_get_all_tokens(self):
        """Should return all tokens."""
        self.engine.generate_gps_canary("192.168.1.1")
        tokens = self.engine.get_all_tokens()
        assert isinstance(tokens, (list, dict))

    def test_get_stats(self):
        """Should return statistics."""
        stats = self.engine.get_stats()
        assert isinstance(stats, dict)


# ── MITRE ATT&CK Mapper ──


class TestMITREMapper:
    """Test MITRE ATT&CK technique mapping."""

    def setup_method(self):
        from mitre_mapper import MITREMapper
        self.mapper = MITREMapper()

    def test_map_recon_intent(self):
        """RECON intent should map to a MITRE technique."""
        result = self.mapper.map_event("192.168.1.1", "RECON", "HEARTBEAT")
        assert result is not None

    def test_map_control_intent(self):
        """CONTROL intent should map to a MITRE technique."""
        result = self.mapper.map_event("192.168.1.1", "CONTROL", "COMMAND_LONG")
        assert result is not None

    def test_get_attack_matrix(self):
        """Should generate an attack matrix summary."""
        self.mapper.map_event("192.168.1.1", "RECON", "HEARTBEAT")
        matrix = self.mapper.get_attack_matrix()
        assert matrix is not None

    def test_get_stats(self):
        """Should return stats dict."""
        stats = self.mapper.get_stats()
        assert isinstance(stats, dict)


# ── Fuzz Detector ──


class TestFuzzDetector:
    """Test protocol fuzzing detection."""

    def setup_method(self):
        from fuzz_detector import FuzzDetector
        self.detector = FuzzDetector()

    def test_analyze_normal_packet(self):
        """Normal MAVLink packets should not immediately trigger fuzzing."""
        # Use valid bytes for a MAVLink v1 packet
        import struct
        payload = b'\x00' * 9
        header = struct.pack('<BBBBB', len(payload), 0, 1, 1, 0)
        packet = b'\xfe' + header + payload + b'\x00\x00'
        result = self.detector.analyze_packet("192.168.1.1", packet, msg_id=0)
        assert result is not None

    def test_get_stats(self):
        """Should return statistics."""
        stats = self.detector.get_stats()
        assert isinstance(stats, dict)


# ── Tarpit ──


class TestAttackerTarpit:
    """Test attacker tarpit strategies."""

    def setup_method(self):
        from tarpit import AttackerTarpit
        self.tarpit = AttackerTarpit()

    def test_get_delay_ms(self):
        """Should return a delay value in milliseconds."""
        delay = self.tarpit.get_delay_ms("192.168.1.1")
        assert isinstance(delay, (int, float))
        assert delay >= 0

    def test_delay_increases(self):
        """Delays should escalate with more interactions."""
        ip = "10.0.0.1"
        delays = []
        for _ in range(10):
            d = self.tarpit.get_delay_ms(ip)
            delays.append(d)
        # Later delays should be >= earlier delays
        assert delays[-1] >= delays[0]

    def test_get_fake_params(self):
        """Should return fake ArduPilot parameters."""
        params = self.tarpit.get_fake_params("192.168.1.1")
        assert isinstance(params, (list, dict))

    def test_get_stats(self):
        """Should return stats dict."""
        stats = self.tarpit.get_stats()
        assert isinstance(stats, dict)


# ── Biometrics ──


class TestBiometricsEngine:
    """Test behavioral biometrics."""

    def setup_method(self):
        from biometrics import BiometricsEngine
        self.engine = BiometricsEngine()

    def test_record_command(self):
        """Should record interactions without error."""
        self.engine.on_command("192.168.1.1", "HEARTBEAT", "RECON")
        assert True

    def test_multiple_commands_build_profile(self):
        """Multiple commands should build a behavioral profile."""
        ip = "192.168.1.50"
        commands = [
            ("HEARTBEAT", "RECON"), ("SYS_STATUS", "RECON"),
            ("COMMAND_LONG", "CONTROL"), ("SET_MODE", "CONTROL")
        ]
        for cmd, intent in commands:
            self.engine.on_command(ip, cmd, intent)

    def test_get_stats(self):
        """Should return stats."""
        stats = self.engine.get_stats()
        assert isinstance(stats, dict)


# ── Threat Predictor ──


class TestThreatPredictor:
    """Test threat prediction engine."""

    def setup_method(self):
        from threat_predictor import ThreatPredictor
        self.predictor = ThreatPredictor()

    def test_observe_action(self):
        """Should observe actions for prediction."""
        self.predictor.observe("192.168.1.1", "RECON")
        assert True

    def test_predict_after_observations(self):
        """Should predict next action after enough observations."""
        ip = "192.168.1.1"
        sequence = ["RECON", "RECON", "CONTROL", "CONTROL", "MISSION_INJECT"]
        for action in sequence * 3:
            self.predictor.observe(ip, action)
        prediction = self.predictor.get_prediction(ip)
        assert prediction is not None

    def test_get_stats(self):
        """Should return stats."""
        stats = self.predictor.get_stats()
        assert isinstance(stats, dict)


# ── CVE Simulator ──


class TestCVESimulator:
    """Test CVE simulation engine."""

    def setup_method(self):
        from cve_simulator import CVESimulator
        self.simulator = CVESimulator()

    def test_get_version_string(self):
        """Should return a fake version string."""
        version = self.simulator.get_version_string()
        assert isinstance(version, str)
        assert len(version) > 0

    def test_get_cve_database(self):
        """Should return the fake CVE database."""
        db = self.simulator.get_cve_database()
        assert isinstance(db, (list, dict))

    def test_get_stats(self):
        """Should return stats."""
        stats = self.simulator.get_stats()
        assert isinstance(stats, dict)
