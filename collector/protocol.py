"""
MAVLink Protocol — Packet parsing, validation, and crafting.

Handles the low-level binary details of the MAVLink v1.0 / v2.0 wire
protocol so that higher-level modules operate on structured dicts.
"""

from __future__ import annotations

import random
import struct
import time
from typing import Any, Dict, Optional


class MAVLinkProtocol:
    """Parse incoming MAVLink frames and craft outgoing decoy responses.

    Args:
        sys_id: System ID to embed in outgoing packets.  Randomised by
            default for anti-fingerprinting.
        comp_id: Component ID to embed in outgoing packets.

    Example:
        >>> proto = MAVLinkProtocol(sys_id=1, comp_id=1)
        >>> parsed = proto.parse_packet(b'\\xfe\\x09...')
        >>> if parsed:
        ...     print(parsed["msg_id"])
    """

    def __init__(
        self,
        sys_id: Optional[int] = None,
        comp_id: Optional[int] = None,
    ) -> None:
        self.sys_id: int = sys_id if sys_id is not None else random.randint(1, 254)
        self.comp_id: int = comp_id if comp_id is not None else random.choice([1, 190, 191])

    # ── Parsing ───────────────────────────────────────────────

    @staticmethod
    def parse_packet(data: bytes) -> Optional[Dict[str, Any]]:
        """Parse a raw MAVLink frame into a structured dict.

        Supports MAVLink v1.0 (STX ``0xFE``) and v2.0 (STX ``0xFD``).

        Args:
            data: Raw bytes received from the socket.

        Returns:
            A dict with keys ``version``, ``msg_id``, ``sys_id``,
            ``comp_id``, ``seq``, ``payload_len``, and ``payload``;
            or ``None`` if *data* cannot be parsed.

        Example:
            >>> MAVLinkProtocol.parse_packet(b'\\xfe\\x09\\x00\\x01\\x01\\x00...')
            {'version': 1, 'msg_id': 0, 'sys_id': 1, ...}
        """
        if len(data) < 6:
            return None

        if data[0] == 0xFE:  # MAVLink 1.0
            payload_len = data[1]
            return {
                "version": 1,
                "msg_id": data[5],
                "sys_id": data[3],
                "comp_id": data[4],
                "seq": data[2],
                "payload_len": payload_len,
                "payload": (
                    data[6 : 6 + payload_len]
                    if len(data) >= 6 + payload_len
                    else b""
                ),
            }

        if data[0] == 0xFD:  # MAVLink 2.0
            if len(data) < 10:
                return None
            payload_len = data[1]
            msg_id = struct.unpack("<I", data[7:10] + b"\x00")[0]
            return {
                "version": 2,
                "msg_id": msg_id,
                "sys_id": data[5],
                "comp_id": data[6],
                "seq": data[4],
                "payload_len": payload_len,
                "payload": (
                    data[10 : 10 + payload_len]
                    if len(data) >= 10 + payload_len
                    else b""
                ),
            }

        return None

    # ── Packet Crafting ───────────────────────────────────────

    def craft_heartbeat(
        self,
        base_mode: int = 81,
        custom_mode: int = 0,
    ) -> bytes:
        """Craft a MAVLink v1.0 HEARTBEAT response.

        Args:
            base_mode: MAV_MODE base-mode bitmask (default 81 = STABILIZE).
            custom_mode: Autopilot-specific custom mode value.

        Returns:
            Raw bytes of a complete MAVLink v1.0 HEARTBEAT frame.
        """
        msg = bytearray([
            0xFE, 9,
            random.randint(0, 255),  # seq (random for anti-fingerprint)
            self.sys_id,
            self.comp_id,
            0,  # msg_id = HEARTBEAT
        ])
        payload = struct.pack(
            "<IBBBB B",
            custom_mode,
            2,   # MAV_TYPE_QUADROTOR
            3,   # MAV_AUTOPILOT_ARDUPILOTMEGA
            base_mode,
            0,   # system_status = UNINIT (overridden per state)
            3,   # mavlink_version
        )
        msg.extend(payload)
        msg.extend(b"\x00\x00")  # CRC placeholder
        return bytes(msg)

    def craft_gps_raw(
        self,
        lat: float,
        lon: float,
        alt: float,
        speed: float,
        heading: int,
    ) -> bytes:
        """Craft a MAVLink v1.0 GPS_RAW_INT message.

        Args:
            lat: Latitude in WGS-84 degrees.
            lon: Longitude in WGS-84 degrees.
            alt: Altitude in metres AGL.
            speed: Ground speed in m/s.
            heading: Heading in degrees (0–360).

        Returns:
            Raw bytes of a complete GPS_RAW_INT frame.
        """
        msg = bytearray([
            0xFE, 30,
            random.randint(0, 255),
            self.sys_id, self.comp_id,
            24,  # msg_id = GPS_RAW_INT
        ])
        payload = struct.pack(
            "<QiiiHHHHBB",
            int(time.time() * 1e6) % (2**64),
            int(lat * 1e7),
            int(lon * 1e7),
            int(alt * 1000),
            65535, 65535,              # eph, epv (unknown)
            int(speed * 100),
            int(heading * 100),
            3,   # fix_type = 3D
            12,  # satellites_visible
        )
        msg.extend(payload)
        msg.extend(b"\x00\x00")
        return bytes(msg)

    def craft_battery_status(
        self,
        battery_pct: float,
    ) -> bytes:
        """Craft a MAVLink v1.0 BATTERY_STATUS message.

        Args:
            battery_pct: Battery percentage (0–100).

        Returns:
            Raw bytes of a complete BATTERY_STATUS frame.
        """
        msg = bytearray([
            0xFE, 36,
            random.randint(0, 255),
            self.sys_id, self.comp_id,
            147,  # msg_id = BATTERY_STATUS
        ])
        voltages = [int(battery_pct * 42)] + [65535] * 9
        payload = struct.pack(
            "<iih10HhBBBb",
            int(battery_pct * 100),       # current_consumed (mAh estimate)
            int((100 - battery_pct) * 10),  # energy_consumed
            -1,                             # temperature (unknown)
            *voltages,
            int(battery_pct * 10),          # current_battery
            0, 0, 0,                        # id, function, type
            int(battery_pct),               # battery_remaining
        )
        msg.extend(payload)
        msg.extend(b"\x00\x00")
        return bytes(msg)
