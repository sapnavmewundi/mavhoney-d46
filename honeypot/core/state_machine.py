"""
State Machine — Honeypot FSM and decoy telemetry drift.

Implements the 7-state finite-state machine that controls how the
honeypot behaves as an attacker escalates:

.. code-block:: text

    NORMAL ──▶ WEAK ──▶ CONFUSED ──▶ DEFENSIVE ──▶ CRASHED
                                                      │
                                         REBOOTING ◀──┘
                                            │
                                         PARTIAL ──▶ NORMAL

Higher severity pushes the honeypot toward a "distressed" state,
making the decoy appear more realistic to an attacker who expects
the drone to degrade under their attacks.
"""

from __future__ import annotations

import random
from typing import Optional

from honeypot.core.session_manager import ConnectionSandbox


# ── State Constants ──────────────────────────────────────────

STATE_NORMAL = "NORMAL"
STATE_WEAK = "WEAK"
STATE_CONFUSED = "CONFUSED"
STATE_DEFENSIVE = "DEFENSIVE"
STATE_CRASHED = "CRASHED"
STATE_REBOOTING = "REBOOTING"
STATE_PARTIAL = "PARTIAL"

#: All valid FSM states, exported for validation / tests.
ALL_STATES = frozenset({
    STATE_NORMAL, STATE_WEAK, STATE_CONFUSED,
    STATE_DEFENSIVE, STATE_CRASHED, STATE_REBOOTING, STATE_PARTIAL,
})


class HoneypotStateMachine:
    """Manages per-sandbox state transitions and decoy telemetry drift.

    The class is stateless itself — all mutable state lives inside the
    ``ConnectionSandbox`` that is passed to each method.  This makes it
    safe to share a single ``HoneypotStateMachine`` across threads.

    Args:
        decoy_enabled: Whether to apply telemetry drift.
        gps_drift: Maximum random GPS drift per tick (degrees).
        battery_drain: Battery drain per tick (percentage points).

    Example:
        >>> fsm = HoneypotStateMachine()
        >>> sb = ConnectionSandbox.create()
        >>> fsm.adapt_behavior(sb, severity=7, intent="CONTROL")
        >>> print(sb.current_state)
        'CONFUSED'
    """

    def __init__(
        self,
        decoy_enabled: bool = True,
        gps_drift: float = 0.001,
        battery_drain: float = 0.1,
    ) -> None:
        self.decoy_enabled = decoy_enabled
        self.gps_drift = gps_drift
        self.battery_drain = battery_drain

    def adapt_behavior(
        self,
        sandbox: ConnectionSandbox,
        severity: int,
        intent: str,
    ) -> None:
        """Transition the sandbox FSM based on threat *severity*.

        The transition rules are:

        ========== =============================================
        Severity   New State
        ========== =============================================
        ≥ 10       REBOOTING (simulated crash + reboot)
        ≥ 9        DEFENSIVE (if intent is HIJACK or GPS_SPOOF)
        ≥ 8        PARTIAL
        ≥ 7        CONFUSED
        ≥ 5        WEAK
        < 5        NORMAL
        ========== =============================================

        While in REBOOTING, a countdown timer ticks down each call;
        the sandbox transitions to NORMAL once it reaches zero.

        Args:
            sandbox: The per-connection sandbox to mutate.
            severity: Numeric severity (1–10) from semantic analysis.
            intent: Classified intent string.
        """
        if sandbox.current_state == STATE_REBOOTING:
            sandbox.reboot_timer -= 1
            if sandbox.reboot_timer <= 0:
                sandbox.current_state = STATE_NORMAL
            return

        if severity >= 10:
            sandbox.current_state = STATE_REBOOTING
            sandbox.reboot_timer = random.randint(3, 8)
        elif severity >= 9 and intent in ("HIJACK", "GPS_SPOOF"):
            sandbox.current_state = STATE_DEFENSIVE
        elif severity >= 8:
            sandbox.current_state = STATE_PARTIAL
        elif severity >= 7:
            sandbox.current_state = STATE_CONFUSED
        elif severity >= 5:
            sandbox.current_state = STATE_WEAK
        else:
            sandbox.current_state = STATE_NORMAL

        self.update_decoy_telemetry(sandbox, intent)

    def update_decoy_telemetry(
        self,
        sandbox: ConnectionSandbox,
        intent: str,
    ) -> None:
        """Drift the sandbox telemetry to match the current intent.

        Different intents produce different telemetry signatures so
        the attacker sees plausible behaviour:

        - **RECON**: gentle drift (hovering drone)
        - **GPS_SPOOF**: large GPS jumps (confused autopilot)
        - **HIJACK**: altitude climb, fast heading changes
        - **CONTROL**: moderate movement
        - **MISSION_INJECT**: steady waypoint-like trajectory
        - **CONFIG_ATTACK**: erratic, heavy battery drain

        Args:
            sandbox: The per-connection sandbox to mutate.
            intent: Classified intent string.
        """
        if not self.decoy_enabled:
            return

        sandbox.decoy_battery = max(5, sandbox.decoy_battery - self.battery_drain)

        if intent == "RECON":
            sandbox.decoy_lat += random.uniform(-0.0001, 0.0001)
            sandbox.decoy_lon += random.uniform(-0.0001, 0.0001)
            sandbox.decoy_heading = (sandbox.decoy_heading + random.randint(-2, 2)) % 360
            sandbox.decoy_speed = random.uniform(0.0, 1.5)
        elif intent == "GPS_SPOOF":
            sandbox.decoy_lat += random.uniform(-0.05, 0.05)
            sandbox.decoy_lon += random.uniform(-0.05, 0.05)
            sandbox.decoy_alt += random.uniform(-50, 50)
            sandbox.decoy_heading = random.randint(0, 360)
            sandbox.decoy_speed = random.uniform(0, 5)
            sandbox.decoy_battery = max(5, sandbox.decoy_battery - 0.5)
        elif intent == "HIJACK":
            sandbox.decoy_alt += random.uniform(10, 50)
            sandbox.decoy_speed = random.uniform(8, 20)
            sandbox.decoy_heading = (sandbox.decoy_heading + random.randint(15, 45)) % 360
            sandbox.decoy_lat += random.uniform(-0.005, 0.005)
            sandbox.decoy_lon += random.uniform(-0.005, 0.005)
            sandbox.decoy_battery = max(5, sandbox.decoy_battery - 1.0)
        elif intent == "CONTROL":
            sandbox.decoy_lat += random.uniform(-0.001, 0.001)
            sandbox.decoy_lon += random.uniform(-0.001, 0.001)
            sandbox.decoy_heading = (sandbox.decoy_heading + random.randint(-10, 10)) % 360
            sandbox.decoy_speed = random.uniform(2, 8)
            sandbox.decoy_alt += random.uniform(-5, 15)
            sandbox.decoy_battery = max(5, sandbox.decoy_battery - 0.3)
        elif intent == "MISSION_INJECT":
            sandbox.decoy_lat += random.uniform(0.001, 0.01)
            sandbox.decoy_lon += random.uniform(-0.01, -0.001)
            sandbox.decoy_alt = 100 + random.uniform(-5, 5)
            sandbox.decoy_heading = (sandbox.decoy_heading + random.randint(5, 20)) % 360
            sandbox.decoy_speed = random.uniform(5, 12)
            sandbox.decoy_battery = max(5, sandbox.decoy_battery - 0.5)
        elif intent == "CONFIG_ATTACK":
            sandbox.decoy_lat += random.uniform(-0.02, 0.02)
            sandbox.decoy_lon += random.uniform(-0.02, 0.02)
            sandbox.decoy_alt += random.uniform(-30, 30)
            sandbox.decoy_heading = random.randint(0, 360)
            sandbox.decoy_speed = random.uniform(0, 25)
            sandbox.decoy_battery = max(5, sandbox.decoy_battery - 2.0)
        else:
            sandbox.decoy_lat += random.uniform(-self.gps_drift, self.gps_drift)
            sandbox.decoy_lon += random.uniform(-self.gps_drift, self.gps_drift)
            sandbox.decoy_heading = (sandbox.decoy_heading + random.randint(-5, 5)) % 360
            sandbox.decoy_speed = random.uniform(0, 3)
