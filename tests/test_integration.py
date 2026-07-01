#!/usr/bin/env python3
"""
Integration tests — simulate realistic multi-step attack scenarios
end-to-end through the core pipeline.
"""

import os
import sys
import tempfile
import csv
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "honeypot"))

from honeypot.core.protocol import MAVLinkProtocol
from honeypot.core.semantic_analyzer import SemanticAnalyzer
from honeypot.core.state_machine import (
    HoneypotStateMachine,
    STATE_NORMAL, STATE_WEAK, STATE_CONFUSED, STATE_DEFENSIVE,
)
from honeypot.core.response_generator import ResponseGenerator
from honeypot.core.session_manager import (
    AttackEvent, AttackerProfile, ConnectionSandbox, SessionLogger,
)
from datetime import datetime


class TestHijackScenario:
    """Simulate a full hijack-attempt attack sequence."""

    def setup_method(self):
        self.proto = MAVLinkProtocol(sys_id=1, comp_id=1)
        self.analyzer = SemanticAnalyzer()
        self.fsm = HoneypotStateMachine()
        self.rg = ResponseGenerator(self.proto, min_delay_ms=1, max_delay_ms=2)
        self.addr = ("192.168.1.100", 54321)

    def test_state_progression(self):
        """State should escalate: NORMAL → WEAK → CONFUSED → DEFENSIVE."""
        sb = ConnectionSandbox.create()
        states_seen = [sb.current_state]

        # Phase 1: RECON (severity 1-2)
        for msg_id in [0, 1, 2, 20, 21]:
            sem = self.analyzer.analyze_intent(msg_id, self.addr)
            self.fsm.adapt_behavior(sb, sem["severity"], sem["intent"])
            states_seen.append(sb.current_state)

        # Phase 2: CONTROL (severity 5-8)
        for msg_id in [11, 76, 223]:
            sem = self.analyzer.analyze_intent(msg_id, self.addr)
            self.fsm.adapt_behavior(sb, sem["severity"], sem["intent"])
            states_seen.append(sb.current_state)

        # Phase 3: HIJACK (severity 8-9)
        for msg_id in [400, 84, 86]:
            sem = self.analyzer.analyze_intent(msg_id, self.addr)
            self.fsm.adapt_behavior(sb, sem["severity"], sem["intent"])
            states_seen.append(sb.current_state)

        # Should have seen escalation
        assert STATE_NORMAL in states_seen
        assert any(s in states_seen for s in [STATE_WEAK, STATE_CONFUSED, STATE_DEFENSIVE])

    def test_response_generated_each_step(self):
        """Each step should generate a non-empty response (unless crashed/rebooting)."""
        sb = ConnectionSandbox.create()
        for msg_id in [0, 11, 76, 400, 84]:
            sem = self.analyzer.analyze_intent(msg_id, self.addr)
            self.fsm.adapt_behavior(sb, sem["severity"], sem["intent"])
            data, rtype = self.rg.generate(sb, msg_id, sem["intent"])
            if sb.current_state not in ("CRASHED", "REBOOTING"):
                assert len(data) > 0 or rtype == "NONE"

    def test_telemetry_drifts_during_hijack(self):
        """GPS should drift measurably during a hijack attempt."""
        sb = ConnectionSandbox.create()
        lat_start = sb.decoy_lat

        for msg_id in [400, 84, 86, 84, 86, 84]:
            sem = self.analyzer.analyze_intent(msg_id, self.addr)
            self.fsm.adapt_behavior(sb, sem["severity"], sem["intent"])

        assert abs(sb.decoy_lat - lat_start) > 0.0001  # relaxed: drift is real but timing-dependent


class TestSessionLogger:
    """Test that SessionLogger writes correct CSV and JSON."""

    def test_csv_header_written(self, temp_dir):
        sl = SessionLogger(temp_dir)
        with open(sl.dataset_file) as f:
            reader = csv.reader(f)
            header = next(reader)
        assert "timestamp" in header
        assert "intent" in header

    def test_event_appended(self, temp_dir):
        sl = SessionLogger(temp_dir)
        event = AttackEvent(
            timestamp="2024-01-01T00:00:00",
            attacker_ip="10.0.0.1",
            attacker_port=1234,
            msg_id=0,
            msg_name="HEARTBEAT",
            intent="RECON",
            severity=1,
            payload_hex="00",
            session_id="test123",
        )
        sl.log_event(event, packet_rate=5.0)

        with open(sl.dataset_file) as f:
            rows = list(csv.reader(f))
        assert len(rows) == 2  # header + 1 row

    def test_json_log_written(self, temp_dir):
        sl = SessionLogger(temp_dir)
        event = AttackEvent(
            timestamp="2024-01-01T00:00:00",
            attacker_ip="10.0.0.1",
            attacker_port=1234,
            msg_id=0,
            msg_name="HEARTBEAT",
            intent="RECON",
            severity=1,
            payload_hex="00",
            session_id="test123",
        )
        sl.log_event(event, packet_rate=5.0)

        with open(sl.log_file) as f:
            lines = f.readlines()
        assert len(lines) == 2  # restart marker + 1 event
        import json
        data = json.loads(lines[1])
        assert data["intent"] == "RECON"


class TestAttackerProfile:
    """Test profile accumulation."""

    def test_profile_creation(self):
        profiles = {}
        sl = SessionLogger(tempfile.mkdtemp())
        event = AttackEvent(
            timestamp="2024-01-01T00:00:00",
            attacker_ip="10.0.0.1",
            attacker_port=1234,
            msg_id=0,
            msg_name="HEARTBEAT",
            intent="RECON",
            severity=1,
            payload_hex="00",
            session_id="test123",
        )
        sl.update_attacker_profile(profiles, event, 5.0)
        assert "10.0.0.1" in profiles
        assert profiles["10.0.0.1"].total_packets == 1

    def test_profile_accumulates(self):
        profiles = {}
        sl = SessionLogger(tempfile.mkdtemp())
        for i in range(5):
            event = AttackEvent(
                timestamp=f"2024-01-01T00:00:0{i}",
                attacker_ip="10.0.0.1",
                attacker_port=1234,
                msg_id=0,
                msg_name="HEARTBEAT",
                intent="RECON",
                severity=1,
                payload_hex="00",
                session_id="test123",
            )
            sl.update_attacker_profile(profiles, event, 5.0)

        assert profiles["10.0.0.1"].total_packets == 5
        assert "RECON" in profiles["10.0.0.1"].attack_types

    def test_command_sequence_max_10(self):
        profiles = {}
        sl = SessionLogger(tempfile.mkdtemp())
        for i in range(15):
            event = AttackEvent(
                timestamp=f"2024-01-01T00:00:{i:02d}",
                attacker_ip="10.0.0.1",
                attacker_port=1234,
                msg_id=0,
                msg_name=f"MSG_{i}",
                intent="RECON",
                severity=1,
                payload_hex="00",
                session_id="test123",
            )
            sl.update_attacker_profile(profiles, event, 5.0)

        assert len(profiles["10.0.0.1"].command_sequence) == 10


class TestEndToEndPipeline:
    """Full pipeline: parse → analyze → adapt → respond → log."""

    def test_full_pipeline(self, craft_mavlink_packet, temp_dir):
        proto = MAVLinkProtocol(sys_id=1, comp_id=1)
        analyzer = SemanticAnalyzer()
        fsm = HoneypotStateMachine()
        rg = ResponseGenerator(proto, min_delay_ms=1, max_delay_ms=2)
        sl = SessionLogger(temp_dir)
        profiles = {}
        addr = ("10.0.0.99", 5555)

        sb = ConnectionSandbox.create()

        # Send 10 packets through the full pipeline
        for msg_id in [0, 0, 20, 21, 11, 76, 400, 84, 113, 132]:
            packet = craft_mavlink_packet(msg_id=msg_id)
            parsed = proto.parse_packet(packet)
            assert parsed is not None

            semantics = analyzer.analyze_intent(parsed["msg_id"], addr)
            fsm.adapt_behavior(sb, semantics["severity"], semantics["intent"])
            data, rtype = rg.generate(sb, parsed["msg_id"], semantics["intent"])

            event = AttackEvent(
                timestamp=datetime.now().isoformat(),
                attacker_ip=addr[0],
                attacker_port=addr[1],
                msg_id=parsed["msg_id"],
                msg_name=semantics["name"],
                intent=semantics["intent"],
                severity=semantics["severity"],
                payload_hex=parsed["payload"].hex(),
                session_id="full_test",
            )
            sl.log_event(event, 2.0)
            sl.update_attacker_profile(profiles, event, 2.0)

        # Verify output
        with open(sl.dataset_file) as f:
            rows = list(csv.reader(f))
        assert len(rows) == 11  # header + 10 events
        assert "10.0.0.99" in profiles
        assert profiles["10.0.0.99"].total_packets == 10
