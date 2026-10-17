#!/usr/bin/env python3
"""
collector/telemetry_fix.py — MAVLink Honeypot Telemetry Response & Probe Logging Patch (Regime 2).

This module documents and provides the active telemetry-response patch deployed
on May 18, 2026 at ~05:26 UTC across all three collection sensors (S1, S2, S3).

Deployment Context & Daemon Regimes:
------------------------------------
- Regime 1 (April 16 – May 18 05:26 UTC, Days 1–32):
  Passive drop baseline. Incoming non-MAVLink wire bytes failed validate_packet(),
  were logged as "Invalid packet from ... dropped", and were silently discarded.
  sandbox.packets_received remained 0. At TCP disconnect, the fallback handler
  `if sandbox.packets_received == 0:` caught both unparsed wire probes and bare
  TCP connections, recording them as `NON_MAVLINK_PROBE` / `SCANNER` rows with
  packets=0 in connections.csv.

- Regime 2 (May 18 05:26 UTC – May 31, Days 33–46):
  Active telemetry response patch (MAVLink Adaptive Honeypot v2.0).
  When non-MAVLink probe bytes arrive, the daemon logs the initial wire bytes
  (up to 64 bytes) under `Probe payload hex:`, issues an active MAVLink telemetry
  burst (HEARTBEAT and SYS_STATUS decoy frames), and increments
  `sandbox.packets_received += 1`.
  Because `packets_received >= 1`, the disconnect fallback is not triggered,
  leaving these 11,837 external probe sessions without an adaptive event row
  in adaptive_data.csv while recording their raw hex in honeypot.log.
  Bare TCP connections (which send zero bytes) continue to have packets_received == 0
  and receive fallback SCANNER records (2,302 sessions in Regime 2).

This file provides:
1. The socket-level telemetry response handler.
2. An offline backfill parser to reconstruct unified 46-day event records with
   explicit `daemon_regime` and `provenance` annotations.
"""

import sys
import os
import re
import csv
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# Mock MAVLink v2 HEARTBEAT packet (autopilot=ARDUPILOTMEGA, type=QUADROTOR)
# Header: 0xFD 0x09 0x00 0x00 0x01 0x01 0x01 0x00 0x00 0x00 (msg_id=0)
DECOY_HEARTBEAT = bytes.fromhex("fd0900000101010000000000000006080000034a7d")

# Mock MAVLink v2 SYS_STATUS packet (sensors healthy, battery 98%)
DECOY_SYS_STATUS = bytes.fromhex("fd1f0000020101010000fc010000fc010000fc010000000003e80000000062000000000000003185")


def handle_non_mavlink_probe(client_sock, ip: str, port: int, data: bytes, sandbox) -> None:
    """
    Handle unparsed / non-MAVLink wire bytes according to Regime 2 logic:
    1. Log the probe payload fragment (initial 64 bytes in hex).
    2. Transmit an active MAVLink telemetry response burst to the client.
    3. Increment sandbox.packets_received counter to reflect the exchange.
    """
    # 1. Capture initial up to 64 bytes
    fragment_hex = data[:64].hex()
    print(f"WARNING: Non-MAVLink probe from {ip} ({len(data)} bytes) — responding with telemetry")
    print(f"INFO:    Probe payload hex: {fragment_hex}")

    # 2. Transmit decoy telemetry burst
    try:
        client_sock.sendall(DECOY_HEARTBEAT + DECOY_SYS_STATUS)
    except Exception as e:
        print(f"DEBUG: Failed to send telemetry burst to {ip}:{port}: {e}")

    # 3. Increment packet counter
    sandbox.packets_received += 1


def backfill_probe_events(
    log_path: str,
    connections_csv_path: str,
    sensor_name: str
) -> List[Dict[str, str]]:
    """
    Reconstruct unified event rows for Regime 2 probe sessions logged in honeypot.log
    that lacked an event row in adaptive_data.csv.

    Returns records matching adaptive_data.csv schema with added:
    - `daemon_regime`: 'regime_1_baseline' or 'regime_2_telemetry_patch'
    - `provenance`: 'live_fallback' or 'log_backfilled'
    """
    conn_pat = re.compile(r"New connection from (\S+):(\d+) \(session: ([0-9a-fA-F]+)\)")
    close_pat = re.compile(r"Connection closed: (\S+):(\d+)")
    payload_pat = re.compile(r"Probe payload hex:\s*([0-9a-fA-F]+)")
    date_pat = re.compile(r"^(\d{2}:\d{2}:\d{2})")

    # Load released sessions from connections.csv
    released_sessions = {}
    with open(connections_csv_path, 'r', errors='ignore') as f:
        reader = csv.DictReader(f)
        for r in reader:
            sid = r.get('session_id')
            if sid and sid not in released_sessions:
                released_sessions[sid] = r

    backfilled_events = []
    active_conns = {}  # (ip, port) -> session_id
    seen_backfill_sids = set()

    with open(log_path, 'r', errors='ignore') as f:
        for line in f:
            m_c = conn_pat.search(line)
            if m_c:
                ip, port, sid = m_c.group(1), m_c.group(2), m_c.group(3)
                active_conns[(ip, port)] = sid
                continue

            m_p = payload_pat.search(line)
            if m_p:
                payload_hex = m_p.group(1)
                # Find associated session
                # If active_conns has entries, take the last active
                sid = list(active_conns.values())[-1] if active_conns else None
                if sid and sid in released_sessions and sid not in seen_backfill_sids:
                    seen_backfill_sids.add(sid)
                    meta = released_sessions[sid]
                    backfilled_events.append({
                        'timestamp': meta.get('timestamp', ''),
                        'ip': meta.get('ip', ''),
                        'source_id': meta.get('source_id', ''),
                        'port': meta.get('port', ''),
                        'msg_id': '0',
                        'msg_name': 'NON_MAVLINK_PROBE',
                        'intent': 'SCANNER',
                        'payload_hex': payload_hex,
                        'session_id': sid,
                        'honeypot_state': 'NORMAL',
                        'packet_rate': '1.0',
                        'daemon_regime': 'regime_2_telemetry_patch',
                        'provenance': 'log_backfilled'
                    })

            m_cl = close_pat.search(line)
            if m_cl:
                ip, port = m_cl.group(1), m_cl.group(2)
                active_conns.pop((ip, port), None)

    return backfilled_events


if __name__ == "__main__":
    print("MAVLink Honeypot Telemetry Patch Module (Regime 2)")
    print("Deployed May 18, 2026 ~05:26 UTC to S1, S2, S3.")
