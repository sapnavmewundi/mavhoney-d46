#!/usr/bin/env python3
"""
Property-based tests using Hypothesis.

These tests verify structural invariants that must hold for *all* inputs,
rather than checking specific examples.
"""

import os
import sys
import struct
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "honeypot"))

try:
    from hypothesis import given, strategies as st, settings as hsettings, assume
    HAS_HYPOTHESIS = True
except ImportError:
    HAS_HYPOTHESIS = False

from honeypot.core.protocol import MAVLinkProtocol
from honeypot.core.semantic_analyzer import SemanticAnalyzer, MAVLINK_SEMANTICS
from honeypot.core.state_machine import HoneypotStateMachine, ALL_STATES
from honeypot.core.session_manager import ConnectionSandbox
from honeypot.core.response_generator import ResponseGenerator

pytestmark = pytest.mark.skipif(not HAS_HYPOTHESIS, reason="hypothesis not installed")


# ── Protocol Parser Invariants ────────────────────────────────

class TestParserNeverCrashes:
    """The parser must return None or a valid dict — never raise."""

    @given(data=st.binary(min_size=0, max_size=512))
    @hsettings(max_examples=200)
    def test_random_bytes_no_crash(self, data):
        result = MAVLinkProtocol.parse_packet(data)
        assert result is None or isinstance(result, dict)

    @given(data=st.binary(min_size=0, max_size=512))
    @hsettings(max_examples=200)
    def test_parsed_dict_has_required_keys(self, data):
        result = MAVLinkProtocol.parse_packet(data)
        if result is not None:
            for key in ("version", "msg_id", "sys_id", "comp_id", "seq", "payload_len", "payload"):
                assert key in result

    @given(
        payload_len=st.integers(min_value=0, max_value=255),
        seq=st.integers(min_value=0, max_value=255),
        sys_id=st.integers(min_value=0, max_value=255),
        comp_id=st.integers(min_value=0, max_value=255),
        msg_id=st.integers(min_value=0, max_value=255),
    )
    @hsettings(max_examples=100)
    def test_valid_v1_structure_always_parses(self, payload_len, seq, sys_id, comp_id, msg_id):
        """A correctly structured v1 packet should always parse."""
        payload = b"\x00" * payload_len
        header = bytes([0xFE, payload_len, seq, sys_id, comp_id, msg_id])
        packet = header + payload + b"\x00\x00"
        result = MAVLinkProtocol.parse_packet(packet)
        assert result is not None
        assert result["version"] == 1
        assert result["msg_id"] == msg_id
        assert result["seq"] == seq


# ── Semantic Analyzer Invariants ──────────────────────────────

class TestSemanticAnalyzerInvariants:
    """Invariants about the semantic analyzer."""

    @given(msg_id=st.integers(min_value=0, max_value=65535))
    @hsettings(max_examples=200)
    def test_analyze_always_returns_dict(self, msg_id):
        sa = SemanticAnalyzer()
        result = sa.analyze_intent(msg_id, ("127.0.0.1", 12345))
        assert isinstance(result, dict)
        assert "name" in result
        assert "intent" in result
        assert "severity" in result

    @given(msg_id=st.integers(min_value=0, max_value=65535))
    @hsettings(max_examples=200)
    def test_severity_always_positive(self, msg_id):
        sa = SemanticAnalyzer()
        result = sa.analyze_intent(msg_id, ("127.0.0.1", 12345))
        assert result["severity"] >= 1

    @given(port=st.integers(min_value=1, max_value=65535))
    @hsettings(max_examples=50)
    def test_different_ports_independent_sessions(self, port):
        sa = SemanticAnalyzer()
        sa.analyze_intent(0, ("127.0.0.1", port))
        key = f"127.0.0.1:{port}"
        assert key in sa.session_data


# ── State Machine Invariants ─────────────────────────────────

class TestStateMachineInvariants:
    """State machine transitions must always produce valid states."""

    @given(
        severity=st.integers(min_value=0, max_value=15),
        intent=st.sampled_from(["RECON", "CONTROL", "HIJACK", "GPS_SPOOF",
                                "MISSION_INJECT", "CONFIG_ATTACK", "UNKNOWN"]),
    )
    @hsettings(max_examples=200)
    def test_state_always_valid(self, severity, intent):
        fsm = HoneypotStateMachine()
        sb = ConnectionSandbox.create()
        fsm.adapt_behavior(sb, severity, intent)
        assert sb.current_state in ALL_STATES

    @given(
        severity=st.integers(min_value=0, max_value=15),
        intent=st.sampled_from(["RECON", "CONTROL", "HIJACK", "GPS_SPOOF",
                                "MISSION_INJECT", "CONFIG_ATTACK", "UNKNOWN"]),
    )
    @hsettings(max_examples=200)
    def test_battery_never_negative(self, severity, intent):
        fsm = HoneypotStateMachine()
        sb = ConnectionSandbox.create()
        sb.decoy_battery = 6.0  # near minimum
        fsm.adapt_behavior(sb, severity, intent)
        assert sb.decoy_battery >= 5.0


# ── Response Generator Invariants ────────────────────────────

class TestResponseGeneratorInvariants:
    """Response generator must always return (bytes, str)."""

    @given(
        intent=st.sampled_from(["RECON", "CONTROL", "HIJACK", "GPS_SPOOF",
                                "MISSION_INJECT", "CONFIG_ATTACK", "UNKNOWN"]),
        state=st.sampled_from(list(ALL_STATES)),
    )
    @hsettings(max_examples=100)
    def test_always_returns_bytes_and_str(self, intent, state):
        proto = MAVLinkProtocol(sys_id=1, comp_id=1)
        rg = ResponseGenerator(proto, min_delay_ms=1, max_delay_ms=2)
        sb = ConnectionSandbox.create()
        sb.current_state = state
        data, rtype = rg.generate(sb, msg_id=0, intent=intent)
        assert isinstance(data, bytes)
        assert isinstance(rtype, str)
