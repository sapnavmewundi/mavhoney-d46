#!/usr/bin/env python3
"""
MAVLink Honeypot — Automated Report Generator
Generates comprehensive HTML reports for incident response.
"""

import os
import json
import glob
from datetime import datetime
from collections import defaultdict
from typing import Dict, List


PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(PROJECT_ROOT, 'logs')
OUTPUT_DIR = os.path.join(PROJECT_ROOT, 'reports')


def load_json_safe(filepath: str) -> dict:
    """Load JSON file, return empty dict on failure."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception:
        return {}


def load_all_events() -> List[dict]:
    """Load all attack events from log files."""
    events = []
    log_pattern = os.path.join(LOGS_DIR, "attacker_intel_*.json")
    for filepath in sorted(glob.glob(log_pattern)):
        data = load_json_safe(filepath)
        for ip, profile in data.items():
            for evt in profile.get("events", []):
                evt["attacker_ip"] = ip
                events.append(evt)
    return sorted(events, key=lambda e: e.get("timestamp", ""))


def generate_report(output_path: str = None) -> str:
    """
    Generate a comprehensive HTML report.

    Returns:
        Path to the generated HTML file.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(OUTPUT_DIR, f"report_{timestamp}.html")

    # Load data
    events = load_all_events()
    fingerprints = load_json_safe(os.path.join(LOGS_DIR, "fingerprints.json"))
    campaigns = load_json_safe(os.path.join(LOGS_DIR, "campaigns.json"))
    deception = load_json_safe(os.path.join(LOGS_DIR, "deception_scores.json"))
    fleet = load_json_safe(os.path.join(LOGS_DIR, "fleet_state.json"))

    # Compute statistics
    total_attacks = len(events)
    unique_ips = set(e.get("attacker_ip", "") for e in events)
    intent_counts = defaultdict(int)
    severity_counts = defaultdict(int)
    hourly_counts = defaultdict(int)

    for e in events:
        intent_counts[e.get("intent", "UNKNOWN")] += 1
        severity_counts[e.get("severity", 0)] += 1
        try:
            hour = datetime.fromisoformat(e["timestamp"]).hour
            hourly_counts[hour] += 1
        except Exception:
            pass

    # Skill distribution
    skill_counts = defaultdict(int)
    for fp_id, fp in fingerprints.items():
        skill_counts[fp.get("skill_level", "UNKNOWN")] += 1

    # Campaign stats
    campaign_types = defaultdict(int)
    for cid, c in campaigns.items():
        campaign_types[c.get("campaign_type", "UNKNOWN")] += 1

    # Build HTML
    now = datetime.now().strftime("%B %d, %Y at %H:%M")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MAVLink Honeypot — Threat Intelligence Report</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700;900&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    font-family: 'Inter', sans-serif;
    background: #0a0a0f;
    color: #e0e0e0;
    line-height: 1.6;
    padding: 40px;
}}
.container {{ max-width: 1100px; margin: 0 auto; }}
h1 {{
    font-size: 2.2em;
    font-weight: 900;
    background: linear-gradient(135deg, #00d4ff, #7b68ee, #ff6b9d);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin-bottom: 8px;
}}
.subtitle {{ color: #888; font-size: 0.95em; margin-bottom: 40px; }}
h2 {{
    font-size: 1.4em;
    font-weight: 700;
    color: #00d4ff;
    margin: 40px 0 16px 0;
    padding-bottom: 8px;
    border-bottom: 1px solid rgba(0,212,255,0.2);
}}
.stats-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    margin: 20px 0;
}}
.stat-card {{
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 12px;
    padding: 20px;
    text-align: center;
}}
.stat-value {{
    font-size: 2em;
    font-weight: 900;
    color: #00d4ff;
    font-family: 'JetBrains Mono', monospace;
}}
.stat-label {{ font-size: 0.8em; color: #888; text-transform: uppercase; letter-spacing: 0.1em; }}
.chart-container {{
    background: rgba(255,255,255,0.03);
    border-radius: 12px;
    padding: 24px;
    margin: 20px 0;
}}
.chart-row {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    margin: 16px 0;
    font-size: 0.9em;
}}
th {{
    background: rgba(0,212,255,0.1);
    color: #00d4ff;
    text-align: left;
    padding: 10px 14px;
    font-weight: 600;
    text-transform: uppercase;
    font-size: 0.8em;
    letter-spacing: 0.05em;
}}
td {{ padding: 10px 14px; border-bottom: 1px solid rgba(255,255,255,0.05); }}
tr:hover td {{ background: rgba(255,255,255,0.02); }}
.badge {{
    display: inline-block;
    padding: 2px 10px;
    border-radius: 20px;
    font-size: 0.75em;
    font-weight: 700;
    text-transform: uppercase;
}}
.badge-critical {{ background: rgba(255,59,48,0.2); color: #ff3b30; }}
.badge-high {{ background: rgba(255,149,0,0.2); color: #ff9500; }}
.badge-medium {{ background: rgba(255,204,0,0.2); color: #ffcc00; }}
.badge-low {{ background: rgba(52,199,89,0.2); color: #34c759; }}
.badge-apt {{ background: rgba(175,82,222,0.2); color: #af52de; }}
.badge-advanced {{ background: rgba(255,59,48,0.2); color: #ff3b30; }}
.badge-intermediate {{ background: rgba(255,149,0,0.2); color: #ff9500; }}
.badge-script_kiddie {{ background: rgba(52,199,89,0.2); color: #34c759; }}
.footer {{
    text-align: center;
    color: #555;
    font-size: 0.8em;
    margin-top: 60px;
    padding-top: 20px;
    border-top: 1px solid rgba(255,255,255,0.05);
}}
@media print {{
    body {{ background: white; color: #333; }}
    .stat-value {{ color: #0066cc; }}
    h2 {{ color: #0066cc; }}
}}
</style>
</head>
<body>
<div class="container">

<h1>🛡️ MAVLink Honeypot — Threat Intelligence Report</h1>
<p class="subtitle">Generated {now} • Covering {total_attacks} attack events from {len(unique_ips)} unique sources</p>

<h2>📊 Executive Summary</h2>
<div class="stats-grid">
    <div class="stat-card">
        <div class="stat-value">{total_attacks}</div>
        <div class="stat-label">Total Attacks</div>
    </div>
    <div class="stat-card">
        <div class="stat-value">{len(unique_ips)}</div>
        <div class="stat-label">Unique Attackers</div>
    </div>
    <div class="stat-card">
        <div class="stat-value">{len(campaigns)}</div>
        <div class="stat-label">Campaigns</div>
    </div>
    <div class="stat-card">
        <div class="stat-value">{len(fingerprints)}</div>
        <div class="stat-label">Fingerprints</div>
    </div>
    <div class="stat-card">
        <div class="stat-value">{max(severity_counts.keys()) if severity_counts else 0}</div>
        <div class="stat-label">Peak Severity</div>
    </div>
</div>

<h2>🎯 Attack Distribution</h2>
<div class="chart-row">
    <div class="chart-container">
        <canvas id="intentChart"></canvas>
    </div>
    <div class="chart-container">
        <canvas id="severityChart"></canvas>
    </div>
</div>

<h2>🏷️ Attack Types</h2>
<table>
<tr><th>Attack Type</th><th>Count</th><th>Percentage</th></tr>
"""

    for intent, count in sorted(intent_counts.items(), key=lambda x: -x[1]):
        pct = round(count / total_attacks * 100, 1) if total_attacks else 0
        html += f"<tr><td>{intent}</td><td>{count}</td><td>{pct}%</td></tr>\n"

    html += "</table>\n"

    # Attacker profiles
    html += "<h2>🌐 Top Attackers</h2>\n<table>\n"
    html += "<tr><th>IP Address</th><th>Attacks</th><th>Types</th><th>Threat</th></tr>\n"

    ip_stats = defaultdict(lambda: {"count": 0, "types": set()})
    for e in events:
        ip = e.get("attacker_ip", "")
        ip_stats[ip]["count"] += 1
        ip_stats[ip]["types"].add(e.get("intent", ""))

    for ip, stats in sorted(ip_stats.items(), key=lambda x: -x[1]["count"])[:15]:
        types_str = ", ".join(sorted(stats["types"]))
        threat = "HIGH" if stats["count"] > 10 else ("MEDIUM" if stats["count"] > 3 else "LOW")
        badge_class = f"badge-{threat.lower()}"
        html += (f"<tr><td><code>{ip}</code></td><td>{stats['count']}</td>"
                 f"<td>{types_str}</td>"
                 f"<td><span class='badge {badge_class}'>{threat}</span></td></tr>\n")

    html += "</table>\n"

    # Fingerprints
    if fingerprints:
        html += "<h2>🧬 Attacker Fingerprints</h2>\n<table>\n"
        html += "<tr><th>ID</th><th>Skill</th><th>Sessions</th><th>IPs</th><th>Threat</th></tr>\n"
        for fp_id, fp in fingerprints.items():
            skill = fp.get("skill_level", "UNKNOWN")
            badge_class = f"badge-{skill.lower()}"
            html += (f"<tr><td><code>{fp_id}</code></td>"
                     f"<td><span class='badge {badge_class}'>{skill}</span></td>"
                     f"<td>{fp.get('sessions', 0)}</td>"
                     f"<td>{len(fp.get('ips_used', []))}</td>"
                     f"<td>{fp.get('threat_score', 0)}</td></tr>\n")
        html += "</table>\n"

    # Campaigns
    if campaigns:
        html += "<h2>🔗 Attack Campaigns</h2>\n<table>\n"
        html += "<tr><th>Name</th><th>Type</th><th>Events</th><th>IPs</th><th>Threat</th></tr>\n"
        for cid, c in campaigns.items():
            threat = c.get("threat_level", "LOW")
            badge_class = f"badge-{threat.lower()}"
            html += (f"<tr><td>{c.get('name', 'Unknown')}</td>"
                     f"<td>{c.get('campaign_type', 'UNKNOWN')}</td>"
                     f"<td>{c.get('total_events', 0)}</td>"
                     f"<td>{len(c.get('attacker_ips', []))}</td>"
                     f"<td><span class='badge {badge_class}'>{threat}</span></td></tr>\n")
        html += "</table>\n"

    # Fleet status
    if fleet:
        html += "<h2>🛩️ Decoy Fleet Status</h2>\n<table>\n"
        html += "<tr><th>Drone</th><th>Model</th><th>Status</th><th>Attacks</th><th>Targeted</th></tr>\n"
        for did, d in fleet.items():
            html += (f"<tr><td>{d.get('callsign', did)}</td>"
                     f"<td>{d.get('model', 'Unknown')}</td>"
                     f"<td>{d.get('status', 'UNKNOWN')}</td>"
                     f"<td>{d.get('attacks_received', 0)}</td>"
                     f"<td>{'🎯 YES' if d.get('is_targeted') else 'No'}</td></tr>\n")
        html += "</table>\n"

    # Charts
    intent_labels = json.dumps(list(intent_counts.keys()))
    intent_data = json.dumps(list(intent_counts.values()))
    sev_labels = json.dumps([f"Sev {k}" for k in sorted(severity_counts.keys())])
    sev_data = json.dumps([severity_counts[k] for k in sorted(severity_counts.keys())])

    colors = [
        "'rgba(0,212,255,0.7)'", "'rgba(123,104,238,0.7)'",
        "'rgba(255,107,157,0.7)'", "'rgba(255,149,0,0.7)'",
        "'rgba(52,199,89,0.7)'", "'rgba(175,82,222,0.7)'",
        "'rgba(255,59,48,0.7)'", "'rgba(255,204,0,0.7)'",
        "'rgba(90,200,250,0.7)'",
    ]
    color_list = "[" + ",".join(colors[:len(intent_counts)]) + "]"

    html += f"""
<h2>📝 Recommendations</h2>
<ul style="padding-left:20px;">
<li>Monitor IPs with HIGH threat level for continued activity</li>
<li>Block repeat offenders identified by behavioral fingerprinting</li>
<li>Review campaigns classified as APT or TARGETED for further investigation</li>
<li>Update MAVLink protocol rules based on observed attack patterns</li>
<li>Consider sharing threat intelligence via STIX/TAXII with partner organizations</li>
</ul>

<div class="footer">
    MAVLink Honeypot — Drone Security Research Platform<br>
    Report generated automatically • {now}
</div>

</div>

<script>
const intentCtx = document.getElementById('intentChart');
if (intentCtx) {{
    new Chart(intentCtx, {{
        type: 'doughnut',
        data: {{
            labels: {intent_labels},
            datasets: [{{
                data: {intent_data},
                backgroundColor: {color_list},
                borderWidth: 0,
            }}]
        }},
        options: {{
            responsive: true,
            plugins: {{
                title: {{ display: true, text: 'Attack Types', color: '#ccc' }},
                legend: {{ labels: {{ color: '#aaa' }} }}
            }}
        }}
    }});
}}

const sevCtx = document.getElementById('severityChart');
if (sevCtx) {{
    new Chart(sevCtx, {{
        type: 'bar',
        data: {{
            labels: {sev_labels},
            datasets: [{{
                label: 'Events',
                data: {sev_data},
                backgroundColor: 'rgba(0,212,255,0.5)',
                borderColor: 'rgba(0,212,255,1)',
                borderWidth: 1,
            }}]
        }},
        options: {{
            responsive: true,
            plugins: {{
                title: {{ display: true, text: 'Severity Distribution', color: '#ccc' }},
                legend: {{ display: false }}
            }},
            scales: {{
                x: {{ ticks: {{ color: '#888' }}, grid: {{ color: 'rgba(255,255,255,0.05)' }} }},
                y: {{ ticks: {{ color: '#888' }}, grid: {{ color: 'rgba(255,255,255,0.05)' }} }}
            }}
        }}
    }});
}}
</script>

</body>
</html>
"""

    with open(output_path, 'w') as f:
        f.write(html)

    print(f"📄 Report generated: {output_path}")
    return output_path


if __name__ == "__main__":
    path = generate_report()
    print(f"Open in browser: file://{path}")
