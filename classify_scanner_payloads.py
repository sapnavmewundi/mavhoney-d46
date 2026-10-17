#!/usr/bin/env python3
"""
classify_scanner_payloads.py — Classify probe payload fragments from honeypot.log.

Parses probe payload fragments logged under `Probe payload hex:` across honeypot.log
files and classifies them by application-layer protocol (HTTP, TLS/SSL, SSH, other/binary).

Daemon Collection Regimes:
- Regime 1 (April 16 – May 18 05:26 UTC): Passive-drop baseline. Incoming non-MAVLink
  bytes were dropped with 'Invalid packet from ... dropped', keeping packets_received == 0.
- Regime 2 (May 18 05:26 UTC – May 31): Active telemetry response patch (telemetry_fix.py).
  Incoming non-MAVLink wire bytes were captured under `Probe payload hex:` (first 64 bytes)
  and responded to with a MAVLink telemetry burst.

Reports:
1. Raw fragment-level distribution across all honeypot.log records (29,685 fragments).
2. Raw session-level initial probe distribution in honeypot.log (20,896 sessions).
3. Joined external session distribution against released connections.csv (11,967 sessions),
   reconciling the 8,929 internal health-check sessions filtered during dataset hygiene.
4. Optional export of backfilled event dataset with `daemon_regime` and `provenance` columns.

Usage:
    python3 classify_scanner_payloads.py [/path/to/dataset] [--backfill output_file.csv]
"""
import sys
import os
import glob
import csv
import re
from collections import Counter

def classify_payload(raw_bytes: bytes) -> str:
    """Heuristic protocol identification for non-MAVLink probe bytes."""
    text = raw_bytes.decode('latin1', errors='replace')
    if any(text.startswith(v) for v in ["GET ", "POST ", "HEAD ", "PUT ", "OPTIONS ", "CONNECT "]):
        return "HTTP"
    elif raw_bytes.startswith(b"\x16"):
        return "TLS/SSL"
    elif raw_bytes.startswith(b"SSH-"):
        return "SSH"
    else:
        return "other/binary"

def analyze_logs(base_dir: str, backfill_path: str = None) -> None:
    servers = ["india", "us", "static"]
    conn_pat = re.compile(r"New connection from (\d+\.\d+\.x\.x|\d+\.\d+\.\d+\.\d+):(\d+) \(session: ([0-9a-fA-F]+)\)")
    close_pat = re.compile(r"Connection closed: (\d+\.\d+\.x\.x|\d+\.\d+\.\d+\.\d+):(\d+)")
    payload_pat = re.compile(r"Probe payload hex:\s*([0-9a-fA-F]+)")

    # Load released external sessions from connections.csv if available
    released_sessions = {}
    for f in sorted(glob.glob(os.path.join(base_dir, "*", "connections.csv"))):
        with open(f, "r", errors="ignore") as fp:
            for row in csv.DictReader(fp):
                sid = row.get("session_id")
                if sid and sid not in released_sessions:
                    released_sessions[sid.strip()] = row

    released_sids = set(released_sessions.keys())

    fragment_counter = Counter()
    session_first_payload = {}
    session_counter = Counter()
    total_fragments = 0

    ext_fragment_counter = Counter()
    ext_session_first_payload = {}
    ext_session_first_hex = {}
    ext_session_counter = Counter()
    total_ext_fragments = 0

    for s in servers:
        log_path = os.path.join(base_dir, s, "honeypot.log")
        if not os.path.exists(log_path):
            continue
        with open(log_path, 'r', errors='ignore') as f:
            active_sids = []
            for l in f:
                m_c = conn_pat.search(l)
                if m_c:
                    active_sids.append(m_c.group(3))
                    continue
                m_p = payload_pat.search(l)
                if m_p:
                    total_fragments += 1
                    raw = bytes.fromhex(m_p.group(1))
                    proto = classify_payload(raw)
                    fragment_counter[proto] += 1

                    sid = active_sids[-1] if active_sids else None
                    if sid and sid not in session_first_payload:
                        session_first_payload[sid] = proto
                        session_counter[proto] += 1

                    if sid and sid in released_sids:
                        total_ext_fragments += 1
                        ext_fragment_counter[proto] += 1
                        if sid not in ext_session_first_payload:
                            ext_session_first_payload[sid] = proto
                            ext_session_first_hex[sid] = m_p.group(1)
                            ext_session_counter[proto] += 1

                m_cl = close_pat.search(l)
                if m_cl:
                    if active_sids:
                        active_sids.pop()

    print("=" * 65)
    print("MAVHoney-D46 — SCANNER Payload Composition Analysis (Regime 2)")
    print("=" * 65)
    print("Note: Probe payload hex fragments were recorded under Regime 2")
    print("(May 18–31) following deployment of the telemetry response patch.")
    print("-" * 65)
    print(f"\n1. RAW LOG PROBE FRAGMENTS (honeypot.log, all servers)")
    print(f"Total probe payload fragments: {total_fragments:,}")
    for p in ["other/binary", "HTTP", "TLS/SSL", "SSH"]:
        c = fragment_counter[p]
        pct = c / total_fragments * 100 if total_fragments else 0
        print(f"  {p:14s}: {c:>6,} ({pct:.1f}%)")

    total_sess = len(session_first_payload)
    print(f"\n2. RAW LOG SESSIONS WITH PROBE PAYLOAD (honeypot.log)")
    print(f"Total raw sessions with logged probe: {total_sess:,}")
    for p in ["HTTP", "other/binary", "TLS/SSL", "SSH"]:
        c = session_counter[p]
        pct = c / total_sess * 100 if total_sess else 0
        print(f"  {p:14s}: {c:>6,} ({pct:.1f}%)")

    if released_sids:
        total_ext_sess = len(ext_session_first_payload)
        filtered_internal = total_sess - total_ext_sess
        print(f"\n3. RELEASED EXTERNAL SESSIONS (joined to connections.csv)")
        print(f"Total released external sessions with logged probe: {total_ext_sess:,}")
        print(f"(Reconciliation: {total_sess:,} raw − {total_ext_sess:,} external = {filtered_internal:,} internal health-check sessions)")
        for p in ["HTTP", "other/binary", "TLS/SSL", "SSH"]:
            c = ext_session_counter[p]
            pct = c / total_ext_sess * 100 if total_ext_sess else 0
            print(f"  {p:14s}: {c:>6,} ({pct:.1f}%)")

        print(f"\n4. RELEASED EXTERNAL PROBE FRAGMENTS")
        print(f"Total external probe fragments: {total_ext_fragments:,}")
        for p in ["other/binary", "HTTP", "TLS/SSL", "SSH"]:
            c = ext_fragment_counter[p]
            pct = c / total_ext_fragments * 100 if total_ext_fragments else 0
            print(f"  {p:14s}: {c:>6,} ({pct:.1f}%)")

    if backfill_path and released_sids:
        print(f"\nGenerating backfilled dataset at {backfill_path}...")
        # Load existing adaptive_data.csv rows
        fieldnames = [
            'timestamp', 'ip', 'source_id', 'port', 'msg_id', 'msg_name',
            'intent', 'payload_hex', 'session_id', 'honeypot_state', 'packet_rate',
            'daemon_regime', 'provenance'
        ]
        written_sids = set()
        out_rows = []
        for f in sorted(glob.glob(os.path.join(base_dir, "*", "adaptive_data.csv"))):
            with open(f, 'r', errors='ignore') as fp:
                for row in csv.DictReader(fp):
                    sid = row.get('session_id')
                    ts = row.get('timestamp', '')
                    regime = 'regime_1_baseline' if ts < '2026-05-18T05:26:00' else 'regime_2_telemetry_patch'
                    row['daemon_regime'] = regime
                    row['provenance'] = 'live_fallback' if row.get('intent') == 'SCANNER' else 'live_decoded'
                    out_rows.append(row)
                    written_sids.add(sid)

        # Backfill external probe sessions that lacked an adaptive row
        backfilled_count = 0
        for sid, proto in ext_session_first_payload.items():
            if sid not in written_sids:
                meta = released_sessions[sid]
                out_rows.append({
                    'timestamp': meta.get('timestamp', ''),
                    'ip': meta.get('ip', ''),
                    'source_id': meta.get('source_id', ''),
                    'port': meta.get('port', ''),
                    'msg_id': '0',
                    'msg_name': 'NON_MAVLINK_PROBE',
                    'intent': 'SCANNER',
                    'payload_hex': ext_session_first_hex.get(sid, ''),
                    'session_id': sid,
                    'honeypot_state': 'NORMAL',
                    'packet_rate': '1.0',
                    'daemon_regime': 'regime_2_telemetry_patch',
                    'provenance': 'log_backfilled'
                })
                written_sids.add(sid)
                backfilled_count += 1

        with open(backfill_path, 'w', newline='') as fp:
            writer = csv.DictWriter(fp, fieldnames=fieldnames)
            writer.writeheader()
            for r in out_rows:
                writer.writerow({k: r.get(k, '') for k in fieldnames})
        print(f"Backfill complete: wrote {len(out_rows):,} rows ({backfilled_count:,} backfilled from honeypot.log).")

    print("=" * 65)

if __name__ == "__main__":
    base = "./dataset"
    backfill_out = None
    args = sys.argv[1:]
    idx = 0
    while idx < len(args):
        if args[idx] == "--backfill":
            backfill_out = args[idx+1]
            idx += 2
        else:
            base = args[idx]
            idx += 1

    if not os.path.exists(base):
        print(f"Dataset path not found: {base}")
        print("Usage: python3 classify_scanner_payloads.py [/path/to/dataset] [--backfill output.csv]")
        sys.exit(1)
    analyze_logs(base, backfill_out)
