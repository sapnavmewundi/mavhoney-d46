#!/usr/bin/env python3
"""
MAVLink Honeypot — Automated Graph Generator
Generates analysis charts using matplotlib:
- Attack frequency over time
- Command distribution histogram
- Attacker skill level distribution
- Anomaly score distribution
"""

import os
import json
import glob
from datetime import datetime, timedelta
from collections import defaultdict, Counter

try:
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    MPL_AVAILABLE = True
except ImportError:
    MPL_AVAILABLE = False

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(PROJECT_ROOT, 'logs')
REPORTS_DIR = os.path.join(PROJECT_ROOT, 'reports')

# Color palette
COLORS = {
    'primary': '#00d4ff',
    'secondary': '#7b68ee',
    'accent': '#ff6b9d',
    'warning': '#ff9500',
    'success': '#34c759',
    'danger': '#ff3b30',
    'bg': '#0a0a0f',
    'text': '#e0e0e0',
    'grid': '#1a1a2e',
}


def _load_events() -> list:
    """Load all attack events."""
    events = []
    log_files = sorted(glob.glob(os.path.join(LOGS_DIR, "*.log")))
    for lf in log_files:
        try:
            with open(lf, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('{'):
                        events.append(json.loads(line))
        except (json.JSONDecodeError, OSError):
            continue

    # Also try CSV datasets
    dataset_dir = os.path.join(PROJECT_ROOT, 'datasets')
    if os.path.isdir(dataset_dir):
        import csv
        for csvf in sorted(glob.glob(os.path.join(dataset_dir, "*.csv"))):
            try:
                with open(csvf, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        events.append(row)
            except Exception:
                continue
    return events


def _setup_dark_style(ax, title: str):
    """Apply dark theme to axes."""
    ax.set_facecolor(COLORS['bg'])
    ax.figure.set_facecolor(COLORS['bg'])
    ax.set_title(title, color=COLORS['primary'], fontsize=14, fontweight='bold', pad=12)
    ax.tick_params(colors=COLORS['text'])
    for spine in ax.spines.values():
        spine.set_color(COLORS['grid'])
    ax.grid(True, alpha=0.15, color=COLORS['text'])


def generate_attack_frequency(events: list, output_path: str = None) -> str:
    """Generate attack frequency over time chart."""
    if not MPL_AVAILABLE:
        return ""

    if output_path is None:
        output_path = os.path.join(REPORTS_DIR, 'attack_frequency.png')

    hourly = defaultdict(int)
    for e in events:
        ts = e.get('timestamp', '')
        try:
            dt = datetime.fromisoformat(ts)
            key = dt.replace(minute=0, second=0, microsecond=0)
            hourly[key] += 1
        except (ValueError, TypeError):
            continue

    if not hourly:
        return ""

    times = sorted(hourly.keys())
    counts = [hourly[t] for t in times]

    fig, ax = plt.subplots(figsize=(12, 5))
    _setup_dark_style(ax, 'Attack Frequency Over Time')

    ax.fill_between(times, counts, alpha=0.3, color=COLORS['primary'])
    ax.plot(times, counts, color=COLORS['primary'], linewidth=2)
    ax.set_xlabel('Time', color=COLORS['text'])
    ax.set_ylabel('Attacks per Hour', color=COLORS['text'])

    if len(times) > 24:
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%m/%d'))
    else:
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
    fig.autofmt_xdate()

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    return output_path


def generate_command_distribution(events: list, output_path: str = None) -> str:
    """Generate command distribution histogram."""
    if not MPL_AVAILABLE:
        return ""

    if output_path is None:
        output_path = os.path.join(REPORTS_DIR, 'command_distribution.png')

    intents = Counter()
    for e in events:
        intents[e.get('intent', 'UNKNOWN')] += 1

    if not intents:
        return ""

    # Top 15 intents
    top = intents.most_common(15)
    labels = [t[0] for t in top]
    values = [t[1] for t in top]

    palette = [COLORS['primary'], COLORS['secondary'], COLORS['accent'],
               COLORS['warning'], COLORS['success'], COLORS['danger'],
               '#af52de', '#ffcc00', '#5ac8fa', '#ff6b6b',
               '#48dbfb', '#feca57', '#ff9ff3', '#54a0ff', '#00d2d3']

    fig, ax = plt.subplots(figsize=(10, 6))
    _setup_dark_style(ax, 'Command/Intent Distribution')

    bars = ax.barh(range(len(labels)), values, color=palette[:len(labels)], edgecolor='none')
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels, fontsize=9, color=COLORS['text'])
    ax.set_xlabel('Count', color=COLORS['text'])
    ax.invert_yaxis()

    for bar, val in zip(bars, values):
        ax.text(bar.get_width() + max(values) * 0.02, bar.get_y() + bar.get_height() / 2,
                str(val), va='center', color=COLORS['text'], fontsize=8)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    return output_path


def generate_skill_distribution(output_path: str = None) -> str:
    """Generate attacker skill level distribution chart."""
    if not MPL_AVAILABLE:
        return ""

    if output_path is None:
        output_path = os.path.join(REPORTS_DIR, 'skill_distribution.png')

    fp_file = os.path.join(LOGS_DIR, 'fingerprints.json')
    if not os.path.exists(fp_file):
        return ""

    with open(fp_file, 'r') as f:
        fingerprints = json.load(f)

    skills = Counter()
    for fp_id, fp in fingerprints.items():
        skills[fp.get('skill_level', 'UNKNOWN')] += 1

    if not skills:
        return ""

    labels = list(skills.keys())
    values = list(skills.values())
    colors_map = {
        'SCRIPT_KIDDIE': COLORS['success'], 'BEGINNER': '#5ac8fa',
        'INTERMEDIATE': COLORS['warning'], 'ADVANCED': COLORS['danger'],
        'APT': '#af52de', 'UNKNOWN': '#888888',
    }
    pie_colors = [colors_map.get(s, '#888') for s in labels]

    fig, ax = plt.subplots(figsize=(8, 8))
    fig.set_facecolor(COLORS['bg'])
    ax.set_facecolor(COLORS['bg'])

    wedges, texts, autotexts = ax.pie(
        values, labels=labels, colors=pie_colors, autopct='%1.0f%%',
        startangle=90, textprops={'color': COLORS['text'], 'fontsize': 10}
    )
    for at in autotexts:
        at.set_color('white')
        at.set_fontweight('bold')

    ax.set_title('Attacker Skill Distribution', color=COLORS['primary'],
                 fontsize=14, fontweight='bold', pad=20)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    return output_path


def generate_anomaly_distribution(events: list, output_path: str = None) -> str:
    """Generate anomaly score distribution histogram."""
    if not MPL_AVAILABLE:
        return ""

    if output_path is None:
        output_path = os.path.join(REPORTS_DIR, 'anomaly_distribution.png')

    severities = []
    for e in events:
        try:
            severities.append(int(e.get('severity', 0)))
        except (ValueError, TypeError):
            continue

    if not severities:
        return ""

    fig, ax = plt.subplots(figsize=(10, 5))
    _setup_dark_style(ax, 'Severity / Anomaly Score Distribution')

    ax.hist(severities, bins=range(0, 12), color=COLORS['primary'],
            edgecolor=COLORS['bg'], alpha=0.7, rwidth=0.85)
    ax.set_xlabel('Severity Score', color=COLORS['text'])
    ax.set_ylabel('Event Count', color=COLORS['text'])
    ax.set_xticks(range(0, 11))

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    return output_path


def generate_all() -> list:
    """Generate all charts and return list of output paths."""
    os.makedirs(REPORTS_DIR, exist_ok=True)

    events = _load_events()
    paths = []

    print(f"  Loaded {len(events)} events for graph generation")

    for name, gen_fn in [
        ('attack_frequency', lambda: generate_attack_frequency(events)),
        ('command_distribution', lambda: generate_command_distribution(events)),
        ('skill_distribution', lambda: generate_skill_distribution()),
        ('anomaly_distribution', lambda: generate_anomaly_distribution(events)),
    ]:
        try:
            path = gen_fn()
            if path:
                paths.append(path)
                print(f"  ✓ {name} → {path}")
            else:
                print(f"  ⊘ {name} — no data")
        except Exception as ex:
            print(f"  ✗ {name} — error: {ex}")

    return paths


if __name__ == "__main__":
    print("Graph Generator — Test")
    if not MPL_AVAILABLE:
        print("  matplotlib not available — install with: pip install matplotlib")
    else:
        paths = generate_all()
        print(f"\n  Generated {len(paths)} charts")
