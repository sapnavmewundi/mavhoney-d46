#!/usr/bin/env python3
"""
classify_scanner_payloads.py — Classify probe payload fragments from honeypot.log.

Parses probe payload fragments logged under `Probe payload hex:` across honeypot.log
files and classifies them by application-layer protocol (HTTP, TLS/SSL, SSH, other/binary),
reporting both per-fragment and per-session initial-probe distributions as described in
the manuscript (Data Records: SCANNER Payload Composition).

Usage:
    python3 classify_scanner_payloads.py [/path/to/dataset]
"""
import sys
import os
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

def analyze_logs(base_dir: str) -> None:
    servers = ["india", "us", "static"]
    conn_pat = re.compile(r"New connection from (\d+\.\d+\.x\.x|\d+\.\d+\.\d+\.\d+):(\d+) \(session: ([0-9a-fA-F]+)\)")
    close_pat = re.compile(r"Connection closed: (\d+\.\d+\.x\.x|\d+\.\d+\.\d+\.\d+):(\d+)")
    payload_pat = re.compile(r"Probe payload hex:\s*([0-9a-fA-F]+)")

    fragment_counter = Counter()
    session_first_payload = {}
    session_counter = Counter()
    total_fragments = 0

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
                m_cl = close_pat.search(l)
                if m_cl:
                    if active_sids:
                        active_sids.pop()

    print("=" * 60)
    print("MAVHoney-D46 — SCANNER Payload Composition")
    print("=" * 60)
    print(f"Total probe payload fragments: {total_fragments:,}")
    for p in ["HTTP", "TLS/SSL", "SSH", "other/binary"]:
        c = fragment_counter[p]
        pct = c / total_fragments * 100 if total_fragments else 0
        print(f"  {p:12s}: {c:>6,} ({pct:.1f}%)")

    total_sess = len(session_first_payload)
    print(f"\nTotal sessions with logged initial payload: {total_sess:,}")
    for p in ["HTTP", "TLS/SSL", "SSH", "other/binary"]:
        c = session_counter[p]
        pct = c / total_sess * 100 if total_sess else 0
        print(f"  {p:12s}: {c:>6,} ({pct:.1f}%)")

if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "./dataset"
    if not os.path.exists(base):
        print(f"Dataset path not found: {base}")
        print("Usage: python3 classify_scanner_payloads.py [/path/to/dataset]")
        sys.exit(1)
    analyze_logs(base)
