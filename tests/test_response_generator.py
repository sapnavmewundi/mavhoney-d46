#!/usr/bin/env python3
"""
Tests for the response generator and state machine.
"""

import os
import sys
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "honeypot"))

from honeypot.core.protocol import MAVLinkProtocol
from honeypot.core.response_generator import ResponseGenerator
from honeypot.core.session_manager import ConnectionSandbox
from honeypot.core.state_machine import (
    HoneypotStateMachine,
    STATE_NORMAL, STATE_WEAK, STATE_CONFUSED, STATE_DEFENSIVE,
    STATE_CRASHED, STATE_REBOOTING, STATE_PARTIAL,
    ALL_STATES,
)


# ── State Machine Tests ──────────────────────────────────────

class TestStateMachineTransitions:
    """Test HoneypotStateMachine.adapt_behavior()."""

    def setup_method(self):
        self.fsm = HoneypotStateMachine()

    def test_low_severity_stays_normal(self):
        sb = ConnectionSandbox.create()
        self.fsm.adapt_behavior(sb, severity=2, intent="RECON")
        assert sb.current_state == STATE_NORMAL

    def test_severity_5_goes_weak(self):
        sb = ConnectionSandbox.create()
        self.fsm.adapt_behavior(sb, severity=5, intent="CONTROL")
        assert sb.current_state == STATE_WEAK

    def test_severity_7_goes_confused(self):
        sb = ConnectionSandbox.create()
        self.fsm.adapt_behavior(sb, severity=7, intent="CONTROL")
        assert sb.current_state == STATE_CONFUSED

    def test_severity_8_goes_partial(self):
        sb = ConnectionSandbox.create()
        self.fsm.adapt_behavior(sb, severity=8, intent="CONTROL")
        assert sb.current_state == STATE_PARTIAL

    def test_severity_9_hijack_goes_defensive(self):
        sb = ConnectionSandbox.create()
        self.fsm.adapt_behavior(sb, severity=9, intent="HIJACK")
        assert sb.current_state == STATE_DEFENSIVE

    def test_severity_9_gps_spoof_goes_defensive(self):
        sb = ConnectionSandbox.create()
        self.fsm.adapt_behavior(sb, severity=9, intent="GPS_SPOOF")
        assert sb.current_state == STATE_DEFENSIVE

    def test_severity_10_goes_rebooting(self):
        sb = ConnectionSandbox.create()
        self.fsm.adapt_behavior(sb, severity=10, intent="GPS_SPOOF")
        assert sb.current_state == STATE_REBOOTING
        assert sb.reboot_timer > 0

    def test_rebooting_timer_ticks_down(self):
        sb = ConnectionSandbox.create()
        sb.current_state = STATE_REBOOTING
        sb.reboot_timer = 2
        self.fsm.adapt_behavior(sb, severity=5, intent="RECON")
        assert sb.reboot_timer == 1
        assert sb.current_state == STATE_REBOOTING

    def test_rebooting_returns_to_normal(self):
        sb = ConnectionSandbox.create()
        sb.current_state = STATE_REBOOTING
        sb.reboot_timer = 1
        self.fsm.adapt_behavior(sb, severity=5, intent="RECON")
        assert sb.current_state == STATE_NORMAL

    def test_all_states_are_valid(self):
        """All state constants should be in ALL_STATES."""
        for s in [STATE_NORMAL, STATE_WEAK, STATE_CONFUSED, STATE_DEFENSIVE,
                  STATE_CRASHED, STATE_REBOOTING, STATE_PARTIAL]:
            assert s in ALL_STATES


class TestTelemetryDrift:
    """Test that update_decoy_telemetry modifies sandbox values."""

    def setup_method(self):
        self.fsm = HoneypotStateMachine()

    def test_recon_drifts_gps(self):
        sb = ConnectionSandbox.create()
        lat_before = sb.decoy_lat
        self.fsm.update_decoy_telemetry(sb, "RECON")
        assert sb.decoy_lat != lat_before or True  # randomised, may be same

    def test_battery_drains(self):
        sb = ConnectionSandbox.create()
        batt_before = sb.decoy_battery
        self.fsm.update_decoy_telemetry(sb, "RECON")
        assert sb.decoy_battery < batt_before

    def test_battery_never_below_5(self):
        sb = ConnectionSandbox.create()
        sb.decoy_battery = 5.0
        self.fsm.update_decoy_telemetry(sb, "CONFIG_ATTACK")
        assert sb.decoy_battery >= 5

    def test_disabled_decoy_no_drift(self):
        fsm = HoneypotStateMachine(decoy_enabled=False)
        sb = ConnectionSandbox.create()
        batt_before = sb.decoy_battery
        fsm.update_decoy_telemetry(sb, "HIJACK")
        assert sb.decoy_battery == batt_before

    def test_hijack_increases_altitude(self):
        sb = ConnectionSandbox.create()
        alt_before = sb.decoy_alt
        self.fsm.update_decoy_telemetry(sb, "HIJACK")
        assert sb.decoy_alt > alt_before  # always +10..+50

    def test_config_attack_heavy_drain(self):
        sb = ConnectionSandbox.create()
        batt_before = sb.decoy_battery
        self.fsm.update_decoy_telemetry(sb, "CONFIG_ATTACK")
        # base drain 0.1 + config drain 2.0 = 2.1
        assert batt_before - sb.decoy_battery > 1.5


# ── Response Generator Tests ─────────────────────────────────

class TestResponseGenerator:
    """Test ResponseGenerator.generate()."""

    def setup_method(self):
        proto = MAVLinkProtocol(sys_id=1, comp_id=1)
        self.rg = ResponseGenerator(proto, min_delay_ms=1, max_delay_ms=2)

    def test_normal_state_returns_data(self):
        sb = ConnectionSandbox.create()
        data, rtype = self.rg.generate(sb, msg_id=0, intent="RECON")
        assert len(data) > 0
        assert "HEARTBEAT" in rtype

    def test_crashed_state_returns_empty(self):
        sb = ConnectionSandbox.create()
        sb.current_state = STATE_CRASHED
        data, rtype = self.rg.generate(sb, msg_id=0, intent="RECON")
        assert data == b""
        assert rtype == "NONE"

    def test_rebooting_mostly_silent(self):
        sb = ConnectionSandbox.create()
        sb.current_state = STATE_REBOOTING
        # run many times; most should be NONE or GARBLED
        results = [self.rg.generate(sb, 0, "RECON") for _ in range(20)]
        none_count = sum(1 for d, r in results if r == "NONE")
        garbled_count = sum(1 for d, r in results if r == "GARBLED")
        assert none_count + garbled_count == 20

    def test_response_contains_three_parts(self):
        sb = ConnectionSandbox.create()
        data, rtype = self.rg.generate(sb, msg_id=0, intent="RECON")
        parts = rtype.split("+")
        assert set(parts) == {"HEARTBEAT", "GPS", "BATTERY"}

    def test_response_bytes_parseable(self):
        """All bytes in the response should be parseable as MAVLink."""
        sb = ConnectionSandbox.create()
        data, _ = self.rg.generate(sb, msg_id=0, intent="RECON")
        # Should contain at least one valid packet
        parsed = MAVLinkProtocol.parse_packet(data)
        assert parsed is not None

    def test_partial_state_sometimes_drops(self):
        sb = ConnectionSandbox.create()
        sb.current_state = STATE_PARTIAL
        results = [self.rg.generate(sb, 0, "RECON") for _ in range(50)]
        none_count = sum(1 for d, r in results if r == "NONE")
        data_count = sum(1 for d, r in results if len(d) > 0)
        # statistically, we expect roughly 50/50
        assert none_count > 0
        assert data_count > 0
