"""
Response Generator — Crafts adaptive MAVLink responses based on FSM state.

Combines the protocol crafting helpers with the state-machine logic to
produce responses that vary depending on what the attacker is doing and
how "damaged" the drone appears to be.
"""

from __future__ import annotations

import random
import time
from typing import Tuple

from honeypot.core.protocol import MAVLinkProtocol
from honeypot.core.session_manager import ConnectionSandbox
from honeypot.core.state_machine import (
    STATE_CRASHED,
    STATE_CONFUSED,
    STATE_DEFENSIVE,
    STATE_PARTIAL,
    STATE_REBOOTING,
)


class ResponseGenerator:
    """Generate deceptive MAVLink response packets.

    The generator consults the sandbox's ``current_state`` to decide
    whether to respond at all and what the response should look like:

    ============  ===========================================================
    State         Behaviour
    ============  ===========================================================
    CRASHED       No response (silent).
    REBOOTING     30 % chance of garbled random bytes; otherwise silent.
    PARTIAL       50 % chance of no response.
    CONFUSED      normal response with garbage custom mode.
    DEFENSIVE     normal response with base_mode = 0 (disarmed).
    NORMAL/WEAK   standard response with intent-appropriate mode flags.
    ============  ===========================================================

    Args:
        protocol: ``MAVLinkProtocol`` instance for packet crafting.
        min_delay_ms: Minimum response delay in ms (anti-fingerprint).
        max_delay_ms: Maximum response delay in ms.

    Example:
        >>> proto = MAVLinkProtocol()
        >>> rg = ResponseGenerator(proto)
        >>> sb = ConnectionSandbox.create()
        >>> data, rtype = rg.generate(sb, msg_id=0, intent="RECON")
    """

    def __init__(
        self,
        protocol: MAVLinkProtocol,
        min_delay_ms: int = 50,
        max_delay_ms: int = 400,
    ) -> None:
        self.protocol = protocol
        self.min_delay_ms = min_delay_ms
        self.max_delay_ms = max_delay_ms

    def _random_delay(self) -> None:
        """Apply a randomised response delay for anti-fingerprinting."""
        time.sleep(
            random.uniform(self.min_delay_ms / 1000, self.max_delay_ms / 1000)
        )

    def generate(
        self,
        sandbox: ConnectionSandbox,
        msg_id: int,
        intent: str = "UNKNOWN",
    ) -> Tuple[bytes, str]:
        """Generate an adaptive MAVLink response.

        Args:
            sandbox: Per-connection sandbox with current FSM state and
                decoy telemetry values.
            msg_id: The MAVLink message ID that triggered this response.
            intent: Classified intent of the incoming message.

        Returns:
            A ``(raw_bytes, response_type_label)`` tuple.  When the
            honeypot decides not to respond, ``raw_bytes`` is empty.
        """
        # ── State-based suppression / corruption ──
        if sandbox.current_state == STATE_CRASHED:
            return b"", "NONE"

        if sandbox.current_state == STATE_REBOOTING:
            if random.random() < 0.3:
                garbled = bytes(
                    [random.randint(0, 255) for _ in range(random.randint(5, 15))]
                )
                return garbled, "GARBLED"
            return b"", "NONE"

        if sandbox.current_state == STATE_PARTIAL:
            if random.random() < 0.5:
                return b"", "NONE"

        # ── Intent-specific mode and delay ──
        base_mode = 81
        custom_mode = 0

        if intent == "RECON":
            base_mode, custom_mode = 81, 4
            self._random_delay()
        elif intent == "GPS_SPOOF":
            base_mode = 81
            custom_mode = random.choice([0, 4, 5, 6])
            self._random_delay()
        elif intent == "HIJACK":
            base_mode = 81 | 128
            custom_mode = 4
            self._random_delay()
        elif intent == "CONTROL":
            base_mode = 81 | 128
            custom_mode = random.choice([3, 4, 5])
            self._random_delay()
        elif intent == "MISSION_INJECT":
            base_mode = 81 | 128
            custom_mode = 3
            self._random_delay()
        elif intent == "CONFIG_ATTACK":
            base_mode = random.choice([0, 81, 209])
            custom_mode = random.randint(900, 999)
            self._random_delay()
        else:
            if sandbox.current_state == STATE_DEFENSIVE:
                base_mode = 0
            elif sandbox.current_state == STATE_CONFUSED:
                custom_mode = random.randint(900, 999)
            self._random_delay()

        # ── Assemble multi-part response ──
        response = bytearray()
        parts = []

        response.extend(
            self.protocol.craft_heartbeat(
                base_mode=base_mode, custom_mode=custom_mode,
            )
        )
        parts.append("HEARTBEAT")

        response.extend(
            self.protocol.craft_gps_raw(
                lat=sandbox.decoy_lat,
                lon=sandbox.decoy_lon,
                alt=sandbox.decoy_alt,
                speed=sandbox.decoy_speed,
                heading=sandbox.decoy_heading,
            )
        )
        parts.append("GPS")

        response.extend(
            self.protocol.craft_battery_status(battery_pct=sandbox.decoy_battery)
        )
        parts.append("BATTERY")

        return bytes(response), "+".join(parts)
