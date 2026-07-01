#!/usr/bin/env python3
"""
Detection accuracy tests — verify that the semantic analyzer correctly
classifies known attack patterns with target accuracy thresholds.
"""

import os
import sys
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "honeypot"))

from honeypot.core.semantic_analyzer import SemanticAnalyzer, MAVLINK_SEMANTICS


class TestReconDetection:
    """RECON messages should be classified with >95% accuracy."""

    RECON_MSG_IDS = [0, 1, 2, 20, 21, 24, 27, 30, 33, 36, 42, 62, 74, 147, 148, 242, 245, 252, 253]

    def test_all_recon_classified(self):
        correct = sum(
            1 for mid in self.RECON_MSG_IDS
            if MAVLINK_SEMANTICS.get(mid, {}).get("intent") == "RECON"
        )
        accuracy = correct / len(self.RECON_MSG_IDS)
        assert accuracy >= 0.95, f"RECON accuracy {accuracy:.1%} < 95%"

    def test_recon_low_severity(self):
        for mid in self.RECON_MSG_IDS:
            if mid in MAVLINK_SEMANTICS:
                assert MAVLINK_SEMANTICS[mid]["severity"] <= 3, (
                    f"RECON msg {mid} has severity {MAVLINK_SEMANTICS[mid]['severity']}, expected ≤ 3"
                )


class TestGPSSpoofDetection:
    """GPS spoofing must be detected with >90% accuracy."""

    GPS_SPOOF_IDS = [113, 132]

    def test_all_gps_spoof_classified(self):
        correct = sum(
            1 for mid in self.GPS_SPOOF_IDS
            if MAVLINK_SEMANTICS.get(mid, {}).get("intent") == "GPS_SPOOF"
        )
        accuracy = correct / len(self.GPS_SPOOF_IDS)
        assert accuracy >= 0.90, f"GPS_SPOOF accuracy {accuracy:.1%} < 90%"

    def test_gps_spoof_high_severity(self):
        for mid in self.GPS_SPOOF_IDS:
            assert MAVLINK_SEMANTICS[mid]["severity"] >= 9


class TestHijackDetection:
    """Hijack messages should be classified correctly."""

    HIJACK_IDS = [83, 84, 86]

    def test_all_hijack_classified(self):
        correct = sum(
            1 for mid in self.HIJACK_IDS
            if MAVLINK_SEMANTICS.get(mid, {}).get("intent") == "HIJACK"
        )
        assert correct == len(self.HIJACK_IDS)

    def test_hijack_high_severity(self):
        for mid in self.HIJACK_IDS:
            assert MAVLINK_SEMANTICS[mid]["severity"] >= 8


class TestFalsePositiveRate:
    """Benign messages should not be classified as high-severity attacks."""

    BENIGN_MSG_IDS = [0, 1, 2, 24, 30, 74, 147, 252, 253]

    def test_false_positive_rate_below_5_percent(self):
        false_positives = sum(
            1 for mid in self.BENIGN_MSG_IDS
            if MAVLINK_SEMANTICS.get(mid, {}).get("severity", 0) >= 7
        )
        fp_rate = false_positives / len(self.BENIGN_MSG_IDS)
        assert fp_rate < 0.05, f"False positive rate {fp_rate:.1%} ≥ 5%"


class TestPatternDetection:
    """Test that multi-message patterns are correctly detected."""

    def test_dos_flood_detected(self):
        sa = SemanticAnalyzer()
        addr = ("10.0.0.1", 9999)
        # Send 55 messages rapidly
        for _ in range(55):
            sa.analyze_intent(0, addr)
        result = sa.analyze_intent(0, addr)
        assert result.get("detected_pattern") == "DOS_FLOOD"

    def test_gps_spoof_pattern_detected(self):
        sa = SemanticAnalyzer()
        result = sa.analyze_intent(113, ("10.0.0.2", 9999))
        assert result.get("detected_pattern") == "GPS_SPOOF_ATTEMPT"

    def test_hijack_sequence_detected(self):
        sa = SemanticAnalyzer()
        addr = ("10.0.0.3", 9999)
        sa.analyze_intent(400, addr)  # ARM
        sa.analyze_intent(76, addr)   # COMMAND_LONG
        result = sa.analyze_intent(84, addr)  # SET_POSITION
        assert result.get("detected_pattern") == "HIJACK_SEQUENCE"

    def test_recon_sweep_detected(self):
        sa = SemanticAnalyzer()
        addr = ("10.0.0.4", 9999)
        # Flood with recon messages
        for _ in range(12):
            sa.analyze_intent(0, addr)
        result = sa.analyze_intent(20, addr)
        assert result.get("detected_pattern") == "RECON_SWEEP"

    def test_config_tampering_detected(self):
        sa = SemanticAnalyzer()
        addr = ("10.0.0.5", 9999)
        for _ in range(3):
            sa.analyze_intent(23, addr)  # PARAM_SET
        result = sa.analyze_intent(23, addr)
        assert result.get("detected_pattern") is not None

    def test_normal_heartbeat_no_pattern(self):
        sa = SemanticAnalyzer()
        result = sa.analyze_intent(0, ("10.0.0.6", 9999))
        assert result.get("detected_pattern") is None
