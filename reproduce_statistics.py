#!/usr/bin/env python3
"""
reproduce_statistics.py — Reproduce all statistics reported in the MAVHoney-D46
manuscript from the released dataset files.

Usage:
    python3 reproduce_statistics.py /path/to/dataset

The dataset directory should contain subdirectories: india/, us/, static/
Each with: connections.csv, adaptive_data.csv, honeypot.log
"""
import csv
import sys
import os
from collections import Counter, defaultdict

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 reproduce_statistics.py /path/to/dataset")
        sys.exit(1)
    
    base = sys.argv[1]
    servers = ['india', 'us', 'static']
    
    print("=" * 60)
    print("MAVHoney-D46 — Reproducibility Verification")
    print("=" * 60)
    
    # ── 1. Connection Statistics ──
    print("\n1. CONNECTION STATISTICS")
    total_rows = 0
    total_sessions = 0
    total_disconnects = 0
    per_server = {}
    all_source_ids = {}
    
    for server in servers:
        path = os.path.join(base, server, "connections.csv")
        if not os.path.exists(path):
            print(f"  ⚠ {server}/connections.csv not found")
            continue
        
        rows = 0
        connects = 0
        disconnects = 0
        sids = set()
        
        with open(path) as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows += 1
                sid_col = 'source_id' if 'source_id' in row else None
                if sid_col:
                    sids.add(row[sid_col])
                
                if row.get('event_type') == 'CONNECT':
                    connects += 1
                elif row.get('event_type') == 'DISCONNECT':
                    disconnects += 1
        
        per_server[server] = {
            'rows': rows, 'connects': connects, 
            'disconnects': disconnects, 'source_ids': sids
        }
        all_source_ids[server] = sids
        total_rows += rows
        total_sessions += connects
        total_disconnects += disconnects
        
        print(f"  {server}: {rows:,} rows, {connects:,} sessions, "
              f"{len(sids):,} source_ids")
    
    interrupted = total_sessions - total_disconnects
    print(f"\n  Total rows:     {total_rows:,}")
    print(f"  Total sessions: {total_sessions:,}")
    print(f"  Interrupted:    {interrupted:,}")
    print(f"  Expected rows:  2 × {total_sessions:,} - {interrupted:,} "
          f"= {2*total_sessions - interrupted:,}")
    
    # ── 2. Adaptive Data / Intent Distribution ──
    print("\n2. INTENT DISTRIBUTION")
    intent_row_counts = Counter()
    session_intents = {}
    mavlink_sessions = set()
    non_mavlink_sessions = set()
    
    for server in servers:
        path = os.path.join(base, server, "adaptive_data.csv")
        if not os.path.exists(path):
            continue
        
        with open(path) as f:
            reader = csv.DictReader(f)
            for row in reader:
                intent = row.get('intent', 'SCANNER')
                sess = row.get('session_id', '')
                msg_name = row.get('msg_name', '')
                msg_id = int(row.get('msg_id', 0)) if row.get('msg_id', '') else 0
                
                intent_row_counts[intent] += 1
                
                # Track highest-priority intent per session
                priority = {'CONTROL': 4, 'RECON': 3, 'UNKNOWN': 2, 'SCANNER': 1}
                if sess not in session_intents or \
                   priority.get(intent, 0) > priority.get(session_intents[sess], 0):
                    session_intents[sess] = intent
                
                # MAVLink detection
                if msg_name and msg_name != 'NON_MAVLINK_PROBE':
                    mavlink_sessions.add(sess)
                else:
                    non_mavlink_sessions.add(sess)
    
    total_adapt = sum(intent_row_counts.values())
    print(f"  Total adaptive rows: {total_adapt:,}")
    for intent in ['SCANNER', 'UNKNOWN', 'RECON', 'CONTROL']:
        c = intent_row_counts[intent]
        pct = c / total_adapt * 100 if total_adapt > 0 else 0
        print(f"  {intent:10s}: {c:>6,} ({pct:.1f}%)")
    
    # ── 3. MAVLink Contingency ──
    print("\n3. MAVLINK CONTINGENCY TABLE")
    print(f"  MAVLink-valid sessions: {len(mavlink_sessions):,}")
    
    session_intent_counts = Counter(session_intents.values())
    print(f"\n  {'Intent':12s} {'MAVLink':>8s} {'Non-MAV':>8s} {'Total':>8s}")
    print(f"  {'─'*40}")
    for intent in ['SCANNER', 'UNKNOWN', 'RECON', 'CONTROL']:
        intent_sess = {s for s, i in session_intents.items() if i == intent}
        mav = intent_sess & mavlink_sessions
        non = intent_sess - mavlink_sessions
        print(f"  {intent:12s} {len(mav):>8,} {len(non):>8,} {len(intent_sess):>8,}")
    
    # ── 4. Cross-Server Overlap ──
    print("\n4. CROSS-SERVER SOURCE OVERLAP")
    if len(all_source_ids) == 3:
        s1 = all_source_ids.get('india', set())
        s2 = all_source_ids.get('us', set())
        s3 = all_source_ids.get('static', set())
        
        total_unique = len(s1 | s2 | s3)
        three_way = len(s1 & s2 & s3)
        
        print(f"  India:  {len(s1):,}")
        print(f"  US:     {len(s2):,}")
        print(f"  Static: {len(s3):,}")
        print(f"  Total unique: {total_unique:,}")
        print(f"  S1∩S2: {len(s1 & s2):,}")
        print(f"  S1∩S3: {len(s1 & s3):,}")
        print(f"  S2∩S3: {len(s2 & s3):,}")
        print(f"  All three: {three_way:,}")
        multi = len((s1 & s2) | (s1 & s3) | (s2 & s3))
        print(f"  On ≥2 servers: {multi:,} ({multi/total_unique*100:.1f}%)")
    
    # ── 5. Log Entries ──
    print("\n5. LOG ENTRIES")
    total_log = 0
    for server in servers:
        path = os.path.join(base, server, "honeypot.log")
        if os.path.exists(path):
            with open(path) as f:
                lines = sum(1 for _ in f)
            total_log += lines
            print(f"  {server}: {lines:,} lines")
    print(f"  Total: {total_log:,}")
    
    # ── Summary ──
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  Sessions:        {total_sessions:,}")
    print(f"  Connection rows: {total_rows:,}")
    print(f"  Adaptive rows:   {total_adapt:,}")
    print(f"  Classified:      {len(session_intents):,}")
    print(f"  Unclassified:    {total_sessions - len(session_intents):,}")
    print(f"  MAVLink-valid:   {len(mavlink_sessions):,}")
    print(f"  Log entries:     {total_log:,}")

if __name__ == '__main__':
    main()
