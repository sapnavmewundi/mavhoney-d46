#!/usr/bin/env python3
"""
MAVLink Static Honeypot — Baseline Control
============================================

Non-adaptive honeypot for A/B comparison with the adaptive version.
Same protocol fidelity, same logging, but NO adaptation:
- Always NORMAL state (no FSM transitions)
- Fixed responses (no game-theoretic strategy)
- No fingerprinting-based behavior changes
- Same CSV logging format for direct comparison

Usage::
    python -m honeypot.static_honeypot
"""

import csv
import hashlib
import os
import socket
import struct
import threading
import time
from datetime import datetime

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from logger import get_logger

logger = get_logger("honeypot.static")

# ── Constants ─────────────────────────────────────────────────
LISTEN_PORT = 5760
UDP_BEACON_PORT = 14550
SESSION_TIMEOUT = 60
MAX_PACKET_SIZE = 280

# Fixed decoy values (never change)
DECOY_LAT = 12.971600
DECOY_LON = 77.594560
DECOY_ALT = 45.0
DECOY_BATTERY = 78.0
DECOY_HEADING = 135
DECOY_SPEED = 0.0

# MAVLink message names for logging
MSG_NAMES = {
    0: "HEARTBEAT", 11: "SET_MODE", 20: "PARAM_REQUEST_READ",
    21: "PARAM_REQUEST_LIST", 23: "PARAM_SET", 33: "GLOBAL_POSITION_INT",
    39: "MISSION_ITEM", 40: "MISSION_REQUEST", 43: "MISSION_REQUEST_LIST",
    44: "MISSION_COUNT", 47: "MISSION_ACK", 48: "SET_GPS_GLOBAL_ORIGIN",
    66: "REQUEST_DATA_STREAM", 76: "COMMAND_LONG", 82: "SET_ATTITUDE_TARGET",
    84: "SET_POSITION_TARGET_LOCAL_NED",
    86: "SET_POSITION_TARGET_GLOBAL_INT",
    148: "AUTOPILOT_VERSION_REQUEST",
    246: "REQUEST_AUTOPILOT_CAPABILITIES",
}

# Intent mapping (same as adaptive, for consistent logging)
INTENT_MAP = {
    0: "RECON", 11: "CONTROL", 20: "RECON", 21: "RECON",
    23: "CONFIG_ATTACK", 39: "MISSION_INJECT", 40: "RECON",
    43: "RECON", 44: "MISSION_INJECT", 48: "GPS_SPOOF",
    66: "RECON", 76: "CONTROL", 82: "HIJACK", 84: "HIJACK",
    86: "HIJACK", 148: "RECON", 246: "RECON",
}

SEVERITY_MAP = {
    0: 1, 11: 5, 20: 2, 21: 2, 23: 6, 39: 7, 40: 3,
    43: 3, 44: 7, 48: 8, 66: 2, 76: 5, 82: 9, 84: 9,
    86: 9, 148: 1, 246: 1,
}


class StaticHoneypot:
    """Non-adaptive MAVLink honeypot for baseline comparison."""

    def __init__(self):
        self.listen_port = LISTEN_PORT
        self.dataset_file = self._init_dataset()
        self.connections = {}
        self._lock = threading.Lock()
        self._setup_telegram()

    def _setup_telegram(self):
        """Load Telegram notifier if configured."""
        self.telegram = None
        try:
            from telegram_bot import TelegramNotifier
            t = TelegramNotifier()
            if t.enabled:
                self.telegram = t
                logger.info("Telegram: LOADED")
        except Exception:
            pass

    def _init_dataset(self):
        """Initialize CSV dataset with fixed filename (persists across restarts)."""
        os.makedirs("datasets", exist_ok=True)
        path = "datasets/static_baseline.csv"
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            with open(path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "timestamp", "ip", "port", "msg_id", "msg_name",
                    "intent", "severity", "payload_hex", "session_id",
                    "honeypot_state", "packet_rate", "mode"
                ])
        return path

    def _log_event(self, ip, port, msg_id, payload_hex, session_id, packet_rate):
        """Log attack event to CSV."""
        msg_name = MSG_NAMES.get(msg_id, f"MSG_{msg_id}")
        intent = INTENT_MAP.get(msg_id, "UNKNOWN")
        severity = SEVERITY_MAP.get(msg_id, 3)

        with self._lock:
            with open(self.dataset_file, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    datetime.now().isoformat(), ip, port, msg_id, msg_name,
                    intent, severity, payload_hex, session_id,
                    "NORMAL",  # Always NORMAL — no adaptation
                    round(packet_rate, 2), "static"
                ])

        # Telegram alert
        if self.telegram and severity >= 1:
            self.telegram.send_alert({
                "intent": intent,
                "msg_name": msg_name,
                "severity": severity,
                "attacker_ip": ip,
                "timestamp": datetime.now().strftime("%H:%M:%S"),
            })

    def _parse_packet(self, data):
        """Parse MAVLink v1/v2 packet header."""
        if len(data) < 8:
            return None
        if data[0] == 0xFE and len(data) >= 8:  # MAVLink v1
            payload_len = data[1]
            msg_id = data[5]
            payload = data[6:6 + payload_len] if len(data) >= 6 + payload_len else b""
            return {"msg_id": msg_id, "payload": payload}
        elif data[0] == 0xFD and len(data) >= 10:  # MAVLink v2
            payload_len = data[1]
            msg_id = data[7] | (data[8] << 8) | (data[9] << 16)
            payload = data[10:10 + payload_len] if len(data) >= 10 + payload_len else b""
            return {"msg_id": msg_id, "payload": payload}
        return None

    def _craft_heartbeat(self):
        """Always the same heartbeat — no adaptation."""
        payload = struct.pack("<IBBBBB", 0, 3, 81, 0, 4, 3)
        return self._wrap_mavlink_v1(0, payload)

    def _craft_gps(self):
        """Always the same GPS — fixed position."""
        payload = struct.pack("<IiiiiHHHHBB",
            int(time.time() * 1000) & 0xFFFFFFFF,
            int(DECOY_LAT * 1e7), int(DECOY_LON * 1e7),
            int(DECOY_ALT * 1000), int(DECOY_ALT * 1000),
            int(DECOY_SPEED * 100), int(DECOY_SPEED * 100),
            int(DECOY_HEADING * 100), 150, 3, 12)
        return self._wrap_mavlink_v1(24, payload)

    def _craft_battery(self):
        """Always the same battery level."""
        return self._wrap_mavlink_v1(147, struct.pack("<Hb", 12600, int(DECOY_BATTERY)))

    def _wrap_mavlink_v1(self, msg_id, payload):
        """Wrap payload in MAVLink v1 frame."""
        header = struct.pack("<BBBBB", 0xFE, len(payload), 0, 1, 1) + struct.pack("B", msg_id)
        # Simple CRC (not protocol-accurate but sufficient)
        crc = sum(header[1:] + payload) & 0xFFFF
        return header + payload + struct.pack("<H", crc)

    def _get_response(self, msg_id):
        """Always return the same fixed response regardless of context."""
        # Static: always respond with heartbeat + GPS (no adaptation)
        return self._craft_heartbeat() + self._craft_gps()

    def handle_client(self, client_sock, addr):
        """Handle connection — no adaptation, fixed responses."""
        ip = addr[0]
        session_id = hashlib.md5(f"{ip}:{addr[1]}:{time.time()}".encode()).hexdigest()[:8]
        packet_count = 0
        start_time = time.time()

        logger.info("New connection from %s:%d (session: %s) [STATIC MODE]", ip, addr[1], session_id)

        # Alert on ANY connection
        if self.telegram:
            try:
                self.telegram.send_alert({
                    "intent": "NEW_CONNECTION",
                    "msg_name": "TCP_CONNECT",
                    "severity": 1,
                    "attacker_ip": ip,
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                })
            except Exception:
                pass

        try:
            client_sock.settimeout(SESSION_TIMEOUT)

            while True:
                try:
                    data = client_sock.recv(1024)
                except socket.timeout:
                    break

                if not data:
                    break

                if len(data) > MAX_PACKET_SIZE:
                    continue

                parsed = self._parse_packet(data)
                if not parsed:
                    continue

                msg_id = parsed["msg_id"]
                packet_count += 1
                elapsed = time.time() - start_time
                packet_rate = packet_count / max(elapsed, 0.01)

                msg_name = MSG_NAMES.get(msg_id, f"MSG_{msg_id}")
                intent = INTENT_MAP.get(msg_id, "UNKNOWN")
                severity = SEVERITY_MAP.get(msg_id, 3)

                self._log_event(ip, addr[1], msg_id, parsed["payload"].hex(),
                              session_id, packet_rate)

                logger.info("[NORMAL] %s -> %s (severity: %d) [STATIC]",
                           msg_name, intent, severity)

                # Always send the same fixed response
                response = self._get_response(msg_id)
                if response:
                    client_sock.send(response)

        except Exception as e:
            logger.error("Error handling %s: %s", addr, e)
        finally:
            # Log scanner sessions (0 valid packets)
            if packet_count == 0:
                self._log_event(ip, addr[1], 0, "", session_id, 0.0)
            client_sock.close()
            logger.info("Connection closed: %s:%d (pkts: %d) [STATIC]",
                       ip, addr[1], packet_count)

    def start(self):
        """Start the static honeypot server."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", self.listen_port))
        server.listen(5)

        # UDP beacon (same as adaptive for fair comparison)
        self._start_udp_beacon()

        logger.info("MAVLink STATIC Honeypot v1.0 (BASELINE)")
        logger.info("Mode: STATIC (no adaptation, fixed responses)")
        logger.info("TCP Listener: port %d", self.listen_port)
        logger.info("UDP Beacon: port %d", UDP_BEACON_PORT)
        logger.info("Dataset: %s", self.dataset_file)

        while True:
            client, addr = server.accept()
            t = threading.Thread(target=self.handle_client, args=(client, addr), daemon=True)
            t.start()

    def _start_udp_beacon(self):
        """Broadcast MAVLink heartbeats on UDP (same as adaptive)."""
        def beacon():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            while True:
                try:
                    hb = self._craft_heartbeat()
                    sock.sendto(hb, ("255.255.255.255", UDP_BEACON_PORT))
                    time.sleep(1)
                except Exception:
                    time.sleep(5)

        t = threading.Thread(target=beacon, daemon=True)
        t.start()


if __name__ == "__main__":
    honeypot = StaticHoneypot()
    honeypot.start()
