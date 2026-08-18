#!/usr/bin/env python3
"""
master_pipeline.py — Single source of truth for ALL MAVHoney-D46 statistics
and figure generation.

Generates:
  1. All verified numbers for the manuscript
  2. Figure 1: Daily connection time series
  3. Figure 2: Intent distribution (donut + bar)
  4. Figure 3: Venn diagram (from actual source_id)
  5. Figure 4: Session scatter plot (NO "SYN-only")
  6. Figure 5: Data lineage diagram
"""
import csv
import hashlib
import hmac
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta

# ═══════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════
CUTOFF = "2026-05-31T23:59:59.999999"
SRC = "/Users/apple/mavlink_honeypot/attack_data/2026-06-08"
HMAC_KEY = b"mavhoney-d46-2026-pes-university"
SERVERS = ["india", "us", "static"]
SERVER_LABELS = {"india": "S1 (India)", "us": "S2 (US East)", "static": "S3 (India Static)"}
FIG_DIR = "/Users/apple/mavlink_honeypot/dataset_paper/figures"
PRIORITY = {"CONTROL": 4, "RECON": 3, "UNKNOWN": 2, "SCANNER": 1}

def make_source_id(ip):
    return hmac.new(HMAC_KEY, ip.encode(), hashlib.sha256).hexdigest()[:16]

print("=" * 70)
print("  MAVHoney-D46 MASTER PIPELINE")
print("  All numbers and figures generated from raw data")
print("=" * 70)

# ═══════════════════════════════════════════════════════════════
# PHASE 1: PARSE ALL DATA
# ═══════════════════════════════════════════════════════════════

# -- Connections --
per_server_conn = {}
per_server_daily = {}   # server -> {date: count}
per_server_ips = {}     # server -> set(ip)
per_server_sids = {}    # server -> set(source_id)
all_sessions = {}       # session_id -> {server, ip, sid, packets, duration, date}
per_server_dates = {}   # server -> set(date)

for server in SERVERS:
    path = os.path.join(SRC, server, "connections.csv")
    rows = 0
    connects = 0
    disconnects = 0
    ips = set()
    sids = set()
    daily = Counter()
    dates = set()
    
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['timestamp'] > CUTOFF:
                continue
            rows += 1
            ip = row['ip']
            sid = make_source_id(ip)
            ips.add(ip)
            sids.add(sid)
            date = row['timestamp'][:10]
            dates.add(date)
            
            if row['event_type'] == 'CONNECT':
                connects += 1
                daily[date] += 1
                all_sessions[row['session_id']] = {
                    'server': server, 'ip': ip, 'sid': sid,
                    'packets': 0, 'duration': 0.0, 'date': date
                }
            elif row['event_type'] == 'DISCONNECT':
                disconnects += 1
                if row['session_id'] in all_sessions:
                    all_sessions[row['session_id']]['packets'] = int(row['packets'])
                    all_sessions[row['session_id']]['duration'] = float(row['duration_sec'])
    
    per_server_conn[server] = {'rows': rows, 'connects': connects, 'disconnects': disconnects}
    per_server_daily[server] = daily
    per_server_ips[server] = ips
    per_server_sids[server] = sids
    per_server_dates[server] = dates

# -- Adaptive data --
session_intent = {}      # session_id -> highest-priority intent
session_has_mavlink = {}  # session_id -> bool
row_intents = Counter()   # row-level intent counts
per_server_session_intent = defaultdict(Counter)  # server -> {intent: count}

for server in SERVERS:
    path = os.path.join(SRC, server, "adaptive_data.csv")
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['timestamp'] > CUTOFF:
                continue
            sess = row['session_id']
            intent = row.get('intent', 'SCANNER')
            msg_name = row.get('msg_name', '')
            
            row_intents[intent] += 1
            
            if sess not in session_intent or PRIORITY.get(intent, 0) > PRIORITY.get(session_intent[sess], 0):
                session_intent[sess] = intent
            
            if msg_name and msg_name != 'NON_MAVLINK_PROBE':
                session_has_mavlink[sess] = True
            elif sess not in session_has_mavlink:
                session_has_mavlink[sess] = False

# Assign per-server session intents
for sess, intent in session_intent.items():
    if sess in all_sessions:
        srv = all_sessions[sess]['server']
        per_server_session_intent[srv][intent] += 1

# -- Log lines --
log_lines = {}
for server in SERVERS:
    path = os.path.join(SRC, server, "honeypot.log")
    if os.path.exists(path):
        with open(path) as f:
            log_lines[server] = sum(1 for _ in f)

# ═══════════════════════════════════════════════════════════════
# PHASE 2: COMPUTE ALL STATISTICS
# ═══════════════════════════════════════════════════════════════

total_conn_rows = sum(s['rows'] for s in per_server_conn.values())
total_sessions_count = sum(s['connects'] for s in per_server_conn.values())
total_disconnects = sum(s['disconnects'] for s in per_server_conn.values())
interrupted = total_sessions_count - total_disconnects

all_ips = set()
for s in per_server_ips.values():
    all_ips |= s
all_sids = set()
for s in per_server_sids.values():
    all_sids |= s

session_intent_counts = Counter(session_intent.values())
total_classified_sessions = sum(session_intent_counts.values())
unclassified = total_sessions_count - total_classified_sessions

total_mavlink = sum(1 for s in session_intent if session_has_mavlink.get(s, False))
total_log = sum(log_lines.values())

# Row-level totals
total_adapt_rows = sum(row_intents.values())

# Venn diagram
s1 = per_server_sids['india']
s2 = per_server_sids['us']
s3 = per_server_sids['static']
venn = {
    's1_only': len(s1 - s2 - s3),
    's2_only': len(s2 - s1 - s3),
    's3_only': len(s3 - s1 - s2),
    's1_s2': len((s1 & s2) - s3),
    's1_s3': len((s1 & s3) - s2),
    's2_s3': len((s2 & s3) - s1),
    's1_s2_s3': len(s1 & s2 & s3),
}
multi_server = len((s1 & s2) | (s1 & s3) | (s2 & s3))

# Temporal
all_dates = set()
for d in per_server_dates.values():
    all_dates |= d
simultaneous = per_server_dates['india'] & per_server_dates['us'] & per_server_dates['static']

# Persistence: is it computed prospectively or retrospectively?
# Answer: retrospectively (uses full 46-day dataset)

# ═══════════════════════════════════════════════════════════════
# PHASE 3: PRINT ALL VERIFIED NUMBERS
# ═══════════════════════════════════════════════════════════════

print("\n" + "─" * 70)
print("  VERIFIED NUMBERS FOR MANUSCRIPT")
print("─" * 70)

print(f"""
CONNECTION STATISTICS
  Total connection rows:     {total_conn_rows:,}
  Total sessions (CONNECT):  {total_sessions_count:,}
  Total DISCONNECT:          {total_disconnects:,}
  Interrupted sessions:      {interrupted:,}
  Rows = 2×sessions - interrupted: 2×{total_sessions_count:,} - {interrupted:,} = {2*total_sessions_count - interrupted:,} ({'✅' if 2*total_sessions_count - interrupted == total_conn_rows else '❌'})

PER-SERVER SESSIONS:
  India:  {per_server_conn['india']['connects']:,} sessions, {len(per_server_ips['india']):,} IPs, {len(per_server_sids['india']):,} source_ids
  US:     {per_server_conn['us']['connects']:,} sessions, {len(per_server_ips['us']):,} IPs, {len(per_server_sids['us']):,} source_ids  
  Static: {per_server_conn['static']['connects']:,} sessions, {len(per_server_ips['static']):,} IPs, {len(per_server_sids['static']):,} source_ids

UNIQUE SOURCES
  Unique IPs (unmasked):     {len(all_ips):,}
  Unique source_ids:         {len(all_sids):,}
  Multi-server (≥2):         {multi_server:,} ({multi_server/len(all_sids)*100:.1f}%)

ADAPTIVE DATA
  Total adaptive rows:       {total_adapt_rows:,}
  Unique classified sessions:{total_classified_sessions:,}
  Multi-row sessions:        {total_adapt_rows - total_classified_sessions:,}
  Unclassified:              {unclassified:,}

SESSION-LEVEL INTENT (for Table 5):""")

for intent in ['SCANNER', 'UNKNOWN', 'RECON', 'CONTROL']:
    c = session_intent_counts[intent]
    pct = c / total_classified_sessions * 100
    print(f"  {intent:10s}: {c:>6,} ({pct:.1f}%)")
print(f"  {'TOTAL':10s}: {total_classified_sessions:>6,}")

print(f"""
ROW-LEVEL INTENT (for reference):""")
for intent in ['SCANNER', 'UNKNOWN', 'RECON', 'CONTROL']:
    c = row_intents[intent]
    print(f"  {intent:10s}: {c:>6,} rows")
print(f"  {'TOTAL':10s}: {total_adapt_rows:>6,} rows")

print(f"""
MAVLINK CONTINGENCY TABLE:
  {'Intent':12s} {'MAVLink':>8s} {'Non-MAV':>8s} {'Total':>8s}
  {'─'*40}""")
for intent in ['SCANNER', 'UNKNOWN', 'RECON', 'CONTROL']:
    sess_i = {s for s, v in session_intent.items() if v == intent}
    mav = sum(1 for s in sess_i if session_has_mavlink.get(s, False))
    non = len(sess_i) - mav
    print(f"  {intent:12s} {mav:>8,} {non:>8,} {len(sess_i):>8,}")
print(f"  {'─'*40}")
print(f"  {'TOTAL':12s} {total_mavlink:>8,} {total_classified_sessions - total_mavlink:>8,} {total_classified_sessions:>8,}")

print(f"""
LOGICAL VERIFICATION:
  RECON all MAVLink-valid:   {all(session_has_mavlink.get(s,False) for s,v in session_intent.items() if v=='RECON')}
  CONTROL all MAVLink-valid: {all(session_has_mavlink.get(s,False) for s,v in session_intent.items() if v=='CONTROL')}
  SCANNER all non-MAVLink:   {all(not session_has_mavlink.get(s,False) for s,v in session_intent.items() if v=='SCANNER')}

VENN DIAGRAM (source_id based):
  S1 only:     {venn['s1_only']:,}
  S2 only:     {venn['s2_only']:,}
  S3 only:     {venn['s3_only']:,}
  S1∩S2 only:  {venn['s1_s2']:,}
  S1∩S3 only:  {venn['s1_s3']:,}
  S2∩S3 only:  {venn['s2_s3']:,}
  S1∩S2∩S3:    {venn['s1_s2_s3']:,}
  Sum:         {sum(venn.values()):,} (should = {len(all_sids):,})
  
  Pairwise (inclusive):
  S1∩S2:       {len(s1 & s2):,}
  S1∩S3:       {len(s1 & s3):,}
  S2∩S3:       {len(s2 & s3):,}

TEMPORAL COVERAGE:
  India:  {len(per_server_dates['india'])} active days
  US:     {len(per_server_dates['us'])} active days
  Static: {len(per_server_dates['static'])} active days
  All 3 simultaneous: {len(simultaneous)} days

DAILY AVAILABILITY MATRIX (sample):""")

# Print daily availability
all_dates_sorted = sorted(all_dates)
active_days_all3 = 0
for d in all_dates_sorted:
    i = '✓' if d in per_server_dates['india'] else '✗'
    u = '✓' if d in per_server_dates['us'] else '✗'
    s = '✓' if d in per_server_dates['static'] else '✗'
    a = '✓' if d in simultaneous else ' '
    if d in simultaneous:
        active_days_all3 += 1
print(f"  Dates with all 3 active: {active_days_all3}")

print(f"""
LOG ENTRIES:
  India:  {log_lines.get('india', 0):,}
  US:     {log_lines.get('us', 0):,}
  Static: {log_lines.get('static', 0):,}
  Total:  {total_log:,}

PERSISTENCE CALCULATION:
  Computed RETROSPECTIVELY using complete 46-day dataset.
  For time-disjoint ML evaluation, persistence must be
  recomputed using only training-set data.
""")

# ═══════════════════════════════════════════════════════════════
# PHASE 4: GENERATE FIGURES
# ═══════════════════════════════════════════════════════════════
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    from matplotlib.patches import FancyBboxPatch
    import numpy as np
    HAS_MPL = True
except ImportError:
    HAS_MPL = False
    print("⚠ matplotlib not available — skipping figure generation")

if HAS_MPL:
    os.makedirs(FIG_DIR, exist_ok=True)
    
    # ── Figure 1: Daily Connections ──
    print("Generating Figure 1: Daily connections...")
    fig, ax = plt.subplots(figsize=(12, 4))
    start = datetime.strptime("2026-04-16", "%Y-%m-%d")
    end = datetime.strptime("2026-05-31", "%Y-%m-%d")
    dates_range = [(start + timedelta(days=i)).strftime("%Y-%m-%d") 
                   for i in range((end - start).days + 1)]
    
    colors = {'india': '#e74c3c', 'us': '#3498db', 'static': '#2ecc71'}
    for server in SERVERS:
        counts = [per_server_daily[server].get(d, 0) for d in dates_range]
        ax.plot(range(len(dates_range)), counts, '-o', markersize=3,
                label=SERVER_LABELS[server], color=colors[server], linewidth=1.5)
    
    ax.set_xlabel('Day of Collection', fontsize=11)
    ax.set_ylabel('Connections', fontsize=11)
    ax.set_title('Daily Connection Volume by Server', fontsize=13, fontweight='bold')
    ax.legend(fontsize=10)
    tick_idx = list(range(0, len(dates_range), 5))
    ax.set_xticks(tick_idx)
    ax.set_xticklabels([dates_range[i][5:] for i in tick_idx], rotation=45, fontsize=9)
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    fig.savefig(os.path.join(FIG_DIR, 'fig1_daily_connections.pdf'), dpi=300)
    fig.savefig(os.path.join(FIG_DIR, 'fig1_daily_connections.png'), dpi=300)
    plt.close()
    print("  ✅ fig1_daily_connections.pdf/png")
    
    # ── Figure 2: Intent Distribution ──
    print("Generating Figure 2: Intent distribution...")
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    
    # Donut chart
    labels_d = ['SCANNER', 'UNKNOWN', 'RECON', 'CONTROL']
    sizes = [session_intent_counts[l] for l in labels_d]
    colors_d = ['#3498db', '#f39c12', '#e74c3c', '#9b59b6']
    wedges, texts, autotexts = ax1.pie(sizes, labels=labels_d, colors=colors_d,
                                        autopct='%1.1f%%', startangle=90,
                                        pctdistance=0.75, textprops={'fontsize': 10})
    centre_circle = plt.Circle((0, 0), 0.50, fc='white')
    ax1.add_artist(centre_circle)
    ax1.set_title(f'(a) Overall Distribution\n({total_classified_sessions:,} sessions)',
                  fontsize=11, fontweight='bold')
    
    # Per-server bar chart (log scale)
    x = np.arange(len(labels_d))
    width = 0.25
    for i, server in enumerate(SERVERS):
        vals = [per_server_session_intent[server].get(l, 0) for l in labels_d]
        # Replace 0 with 0.1 for log scale
        vals_plot = [max(v, 0.1) for v in vals]
        ax2.bar(x + i * width, vals_plot, width, label=SERVER_LABELS[server],
                color=list(colors.values())[i])
    
    ax2.set_yscale('log')
    ax2.set_xticks(x + width)
    ax2.set_xticklabels(labels_d, fontsize=10)
    ax2.set_ylabel('Sessions (log scale)', fontsize=11)
    ax2.set_title('(b) Per-Server Breakdown', fontsize=11, fontweight='bold')
    ax2.legend(fontsize=9)
    ax2.grid(True, alpha=0.3, axis='y')
    
    plt.tight_layout()
    fig.savefig(os.path.join(FIG_DIR, 'fig2_intent_distribution.pdf'), dpi=300)
    fig.savefig(os.path.join(FIG_DIR, 'fig2_intent_distribution.png'), dpi=300)
    plt.close()
    print("  ✅ fig2_intent_distribution.pdf/png")
    
    # ── Figure 3: Venn Diagram ──
    print("Generating Figure 3: Venn diagram...")
    try:
        from matplotlib_venn import venn3
        fig, ax = plt.subplots(figsize=(8, 8))
        v = venn3(subsets=(venn['s1_only'], venn['s2_only'], venn['s1_s2'],
                          venn['s3_only'], venn['s1_s3'], venn['s2_s3'],
                          venn['s1_s2_s3']),
                  set_labels=(f'S1 India\n({len(s1):,})',
                             f'S2 US\n({len(s2):,})',
                             f'S3 Static\n({len(s3):,})'),
                  ax=ax)
        ax.set_title(f'Cross-Server Source Overlap\n({len(all_sids):,} unique source_ids, '
                     f'{multi_server:,} on ≥2 servers [{multi_server/len(all_sids)*100:.1f}%])',
                     fontsize=12, fontweight='bold')
        plt.tight_layout()
        fig.savefig(os.path.join(FIG_DIR, 'fig3_venn_overlap.pdf'), dpi=300)
        fig.savefig(os.path.join(FIG_DIR, 'fig3_venn_overlap.png'), dpi=300)
        plt.close()
        print("  ✅ fig3_venn_overlap.pdf/png")
    except ImportError:
        print("  ⚠ matplotlib_venn not installed, creating manual Venn...")
        # Fallback: create a simple text-based Venn representation
        fig, ax = plt.subplots(figsize=(8, 6))
        ax.text(0.5, 0.95, f'Cross-Server Source Overlap ({len(all_sids):,} unique source_ids)', 
                ha='center', va='top', fontsize=13, fontweight='bold', transform=ax.transAxes)
        
        circles = [
            plt.Circle((0.35, 0.55), 0.28, fill=False, edgecolor='red', linewidth=2.5),
            plt.Circle((0.65, 0.55), 0.28, fill=False, edgecolor='blue', linewidth=2.5),
            plt.Circle((0.50, 0.30), 0.28, fill=False, edgecolor='green', linewidth=2.5),
        ]
        for c in circles:
            ax.add_patch(c)
        
        ax.text(0.20, 0.70, f'{venn["s1_only"]}', ha='center', fontsize=11, fontweight='bold')
        ax.text(0.80, 0.70, f'{venn["s2_only"]}', ha='center', fontsize=11, fontweight='bold')
        ax.text(0.50, 0.12, f'{venn["s3_only"]}', ha='center', fontsize=11, fontweight='bold')
        ax.text(0.50, 0.70, f'{venn["s1_s2"]}', ha='center', fontsize=11)
        ax.text(0.33, 0.35, f'{venn["s1_s3"]}', ha='center', fontsize=11)
        ax.text(0.67, 0.35, f'{venn["s2_s3"]}', ha='center', fontsize=11)
        ax.text(0.50, 0.48, f'{venn["s1_s2_s3"]}', ha='center', fontsize=12, fontweight='bold', color='darkred')
        
        ax.text(0.15, 0.88, f'S1 India ({len(s1):,})', fontsize=11, color='red', fontweight='bold')
        ax.text(0.65, 0.88, f'S2 US ({len(s2):,})', fontsize=11, color='blue', fontweight='bold')
        ax.text(0.35, 0.02, f'S3 Static ({len(s3):,})', fontsize=11, color='green', fontweight='bold')
        
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.axis('off')
        plt.tight_layout()
        fig.savefig(os.path.join(FIG_DIR, 'fig3_venn_overlap.pdf'), dpi=300)
        fig.savefig(os.path.join(FIG_DIR, 'fig3_venn_overlap.png'), dpi=300)
        plt.close()
        print("  ✅ fig3_venn_overlap.pdf/png (manual)")
    
    # ── Figure 4: Session Scatter (NO SYN-only!) ──
    print("Generating Figure 4: Session scatter plot...")
    fig, ax = plt.subplots(figsize=(10, 6))
    
    intent_colors = {'SCANNER': '#3498db', 'UNKNOWN': '#f39c12', 
                     'RECON': '#e74c3c', 'CONTROL': '#9b59b6'}
    
    for intent in ['SCANNER', 'UNKNOWN', 'RECON', 'CONTROL']:
        sessions = [(all_sessions[s]['duration'], all_sessions[s]['packets'])
                    for s, v in session_intent.items() if v == intent and s in all_sessions]
        if sessions:
            durations, packets = zip(*sessions)
            alpha = 0.3 if intent == 'SCANNER' else 0.8
            size = 10 if intent == 'SCANNER' else 40
            ax.scatter(durations, packets, s=size, alpha=alpha, 
                      color=intent_colors[intent], label=intent, edgecolors='none')
    
    ax.set_xlabel('Session Duration (seconds)', fontsize=11)
    ax.set_ylabel('Packet Count', fontsize=11)
    ax.set_title('Session Duration vs Packet Count by Intent Class', fontsize=13, fontweight='bold')
    ax.set_xscale('log')
    ax.set_yscale('log')
    ax.legend(fontsize=10)
    ax.grid(True, alpha=0.3)
    
    # Add annotation for zero-application-data connections (NOT "SYN-only"!)
    zero_data = sum(1 for s in all_sessions.values() if s['packets'] == 0)
    ax.annotate(f'{zero_data:,} zero-application-data\nconnections (packets=0)',
                xy=(0.02, 0.98), xycoords='axes fraction', fontsize=9,
                ha='left', va='top',
                bbox=dict(boxstyle='round,pad=0.3', facecolor='lightyellow', alpha=0.8))
    
    plt.tight_layout()
    fig.savefig(os.path.join(FIG_DIR, 'fig4_session_scatter.pdf'), dpi=300)
    fig.savefig(os.path.join(FIG_DIR, 'fig4_session_scatter.png'), dpi=300)
    plt.close()
    print("  ✅ fig4_session_scatter.pdf/png")
    
    # ── Figure 5: Data Lineage ──
    print("Generating Figure 5: Data lineage diagram...")
    fig, ax = plt.subplots(1, 1, figsize=(10, 14))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 16)
    ax.axis('off')
    
    C_RAW = '#1a5276'
    C_SESSION = '#117a65'
    C_CSV = '#6c3483'
    C_PKT = '#b9770e'
    C_LABEL = '#c0392b'
    C_EDGE = '#2c3e50'
    C_NOTE = '#566573'
    fig.patch.set_facecolor('#fdfefe')
    
    def draw_box(x, y, w, h, text, subtext, color, fs=11, ss=8.5):
        box = FancyBboxPatch((x-w/2, y-h/2), w, h, boxstyle="round,pad=0.15",
                            facecolor=color, edgecolor='white', linewidth=2, alpha=0.92)
        ax.add_patch(box)
        ax.text(x, y+0.18, text, ha='center', va='center', fontsize=fs,
                fontweight='bold', color='white')
        if subtext:
            ax.text(x, y-0.25, subtext, ha='center', va='center', fontsize=ss,
                    color='#ecf0f1', style='italic')
    
    def draw_arrow(x1, y1, x2, y2):
        ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
                   arrowprops=dict(arrowstyle='->', color=C_EDGE, lw=2.2, mutation_scale=18))
    
    def draw_note(x, y, text, align='left'):
        ax.text(x, y, text, ha=align, va='center', fontsize=8, color=C_NOTE,
                style='italic', bbox=dict(boxstyle='round,pad=0.3', facecolor='#f8f9fa',
                                         edgecolor='#d5d8dc', alpha=0.9))
    
    ax.text(5, 15.3, 'Data Lineage: From Raw Log Events to Classified Sessions',
            ha='center', va='center', fontsize=14, fontweight='bold', color=C_EDGE)
    ax.plot([1.2, 8.8], [14.95, 14.95], color=C_EDGE, lw=1.5, alpha=0.3)
    
    # Level 1: Log entries
    draw_box(5, 14, 5.2, 1.2,
             f'{total_log:,}  Log Entries',
             'honeypot.log  ×  3 servers',
             C_RAW, fs=12)
    
    draw_arrow(5, 13.35, 5, 12.45)
    draw_note(7.5, 12.9, 'Session grouping by\n(server, source_ip, port, seq)\n+ CONNECT/DISCONNECT pairing')
    
    # Level 2: Connection rows
    draw_box(5, 11.7, 5.2, 1.2,
             f'{total_conn_rows:,}  Rows in connections.csv',
             f'CONNECT + DISCONNECT events × 3 servers',
             C_CSV, fs=12)
    
    draw_arrow(5, 11.05, 5, 10.15)
    draw_note(7.5, 10.6, f'Deduplication: each session counted once\n'
              f'2×{total_sessions_count:,} − {interrupted:,} interrupted = {total_conn_rows:,}')
    
    # Level 3: Deduplicated sessions
    draw_box(5, 9.4, 5.2, 1.2,
             f'{total_sessions_count:,}  Deduplicated Sessions',
             f'{len(all_sids):,} unique source_ids across {len(all_dates)} days',
             C_SESSION, fs=12)
    
    draw_arrow(5, 8.75, 5, 7.85)
    draw_note(7.5, 8.3, f'{unclassified:,} sessions with no application\n'
              f'data (zero-application-data connections)')
    
    # Level 4: Adaptive data
    draw_box(5, 7.1, 5.2, 1.2,
             f'{total_adapt_rows:,}  Adaptive Data Rows',
             f'Packet-level MAVLink decode events',
             C_PKT, fs=12)
    
    draw_arrow(5, 6.45, 5, 5.55)
    draw_note(7.5, 6.0, f'Session-level intent assignment\n'
              f'(highest priority per session)\n'
              f'{total_adapt_rows - total_classified_sessions} multi-packet sessions collapsed')
    
    # Level 5: Classified sessions
    draw_box(5, 4.8, 5.2, 1.2,
             f'{total_classified_sessions:,}  Classified Sessions',
             f'SCANNER {session_intent_counts["SCANNER"]:,} | '
             f'UNKNOWN {session_intent_counts["UNKNOWN"]:,} | '
             f'RECON {session_intent_counts["RECON"]:,} | '
             f'CONTROL {session_intent_counts["CONTROL"]:,}',
             C_LABEL, fs=12)
    
    # Summary box
    summary = (f'Sessions: {total_sessions_count:,}\n'
               f'Classified: {total_classified_sessions:,}\n'
               f'MAVLink-valid: {total_mavlink:,}\n'
               f'Unclassified: {unclassified:,}')
    ax.text(5, 2.5, summary, ha='center', va='center', fontsize=10,
            bbox=dict(boxstyle='round,pad=0.5', facecolor='#eaf2f8', edgecolor='#2980b9'))
    
    plt.tight_layout()
    fig.savefig(os.path.join(FIG_DIR, 'fig5_data_lineage.pdf'), dpi=300)
    fig.savefig(os.path.join(FIG_DIR, 'fig5_data_lineage.png'), dpi=300)
    plt.close()
    print("  ✅ fig5_data_lineage.pdf/png")

print("\n" + "=" * 70)
print("  PIPELINE COMPLETE")
print("=" * 70)
