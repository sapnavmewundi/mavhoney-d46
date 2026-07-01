#!/usr/bin/env python3
"""
MAVLink Honeypot — Threat Intelligence Export
Exports attacker data in standard formats: CSV, STIX 2.1 JSON, and text report.

Usage:
    python3 export_threat_intel.py --format csv
    python3 export_threat_intel.py --format stix
    python3 export_threat_intel.py --format text
    python3 export_threat_intel.py --format all
    python3 export_threat_intel.py --format csv --days 7
"""

import json
import csv
import os
import sys
import hashlib
import argparse
from datetime import datetime, timedelta


PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(PROJECT_ROOT, 'logs')
OUTPUT_DIR = os.path.join(PROJECT_ROOT, 'threat_intel_exports')


def load_attacker_data() -> dict:
    """Load attacker intelligence data."""
    intel_file = os.path.join(LOGS_DIR, 'attacker_intel.json')
    if not os.path.exists(intel_file):
        print(f"❌ No attacker intel found at {intel_file}")
        print("   Run the honeypot and attack simulator first.")
        sys.exit(1)

    with open(intel_file, 'r') as f:
        data = json.load(f)

    print(f"📂 Loaded {len(data)} attacker profiles")
    return data


def load_fingerprints() -> dict:
    """Load behavioral fingerprints if available."""
    fp_file = os.path.join(LOGS_DIR, 'fingerprints.json')
    if os.path.exists(fp_file):
        with open(fp_file, 'r') as f:
            return json.load(f)
    return {}


def load_deception_scores() -> dict:
    """Load deception scores if available."""
    ds_file = os.path.join(LOGS_DIR, 'deception_scores.json')
    if os.path.exists(ds_file):
        with open(ds_file, 'r') as f:
            return json.load(f)
    return {}


def filter_by_timerange(data: dict, days: int = None) -> dict:
    """Filter attackers by time range."""
    if days is None:
        return data

    cutoff = datetime.now() - timedelta(days=days)
    filtered = {}

    for ip, profile in data.items():
        try:
            last_seen = datetime.fromisoformat(profile.get('last_seen', ''))
            if last_seen >= cutoff:
                filtered[ip] = profile
        except (ValueError, TypeError):
            filtered[ip] = profile  # Keep if can't parse date

    print(f"   Filtered to {len(filtered)} profiles (last {days} days)")
    return filtered


def classify_threat(profile: dict) -> str:
    """Classify threat level from profile data."""
    attack_count = profile.get('attack_count', 0)
    attacks = profile.get('attacks', [])

    high_severity_types = {'hijack', 'gps_spoof', 'dos_flood', 'kill_switch', 'geofence_breach'}
    has_high = any(a.get('type', '') in high_severity_types for a in attacks)

    if attack_count >= 10 or has_high:
        return "CRITICAL"
    elif attack_count >= 5:
        return "HIGH"
    elif attack_count >= 2:
        return "MEDIUM"
    else:
        return "LOW"


def export_csv(data: dict, fingerprints: dict, deception: dict, output_dir: str):
    """Export to CSV format."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = os.path.join(output_dir, f'threat_intel_{timestamp}.csv')

    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'ip', 'country', 'city', 'isp', 'first_seen', 'last_seen',
            'visit_count', 'attack_count', 'threat_level', 'attack_types',
            'vpn_detected', 'behavior_signature', 'linked_identities'
        ])

        for ip, profile in data.items():
            attack_types = set(a.get('type', 'unknown') for a in profile.get('attacks', []))
            threat_level = classify_threat(profile)

            # Get fingerprint signature
            fp = fingerprints.get(ip, {})
            sig = fp.get('fingerprint_id', hashlib.md5(ip.encode()).hexdigest()[:8])

            linked = ','.join(profile.get('linked_identities', []))

            writer.writerow([
                ip,
                profile.get('country', 'Unknown'),
                profile.get('city', 'Unknown'),
                profile.get('isp', 'Unknown'),
                profile.get('first_seen', ''),
                profile.get('last_seen', ''),
                profile.get('visit_count', 0),
                profile.get('attack_count', 0),
                threat_level,
                '|'.join(attack_types),
                profile.get('vpn_detected', False),
                sig,
                linked
            ])

    print(f"   ✅ CSV exported: {filename}")
    return filename


def load_campaigns() -> dict:
    """Load campaigns if available."""
    cp_file = os.path.join(LOGS_DIR, 'campaigns.json')
    if os.path.exists(cp_file):
        with open(cp_file, 'r') as f:
            return json.load(f)
    return {}


def export_stix(data: dict, fingerprints: dict, output_dir: str):
    """Export in STIX 2.1 JSON format with campaigns and tool fingerprints."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = os.path.join(output_dir, f'threat_intel_{timestamp}.stix.json')
    campaigns = load_campaigns()

    stix_bundle = {
        "type": "bundle",
        "id": f"bundle--{hashlib.md5(timestamp.encode()).hexdigest()}",
        "objects": []
    }

    # Create identity for the honeypot
    honeypot_identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": f"identity--mavlink-honeypot-{hashlib.md5(b'mavlink-honeypot').hexdigest()[:8]}",
        "created": datetime.now().isoformat() + "Z",
        "modified": datetime.now().isoformat() + "Z",
        "name": "MAVLink Adaptive Honeypot",
        "identity_class": "system",
        "description": "MAVLink drone protocol honeypot with semantic analysis"
    }
    stix_bundle["objects"].append(honeypot_identity)

    indicator_ids = {}  # ip -> stix id

    for ip, profile in data.items():
        threat_level = classify_threat(profile)
        attack_types = set(a.get('type', 'unknown') for a in profile.get('attacks', []))

        # Get fingerprint enrichment
        fp = fingerprints.get(ip, {})
        skill_level = fp.get('skill_level', 'UNKNOWN')
        threat_score = fp.get('threat_score', 0)

        indicator_id = f"indicator--{hashlib.md5(ip.encode()).hexdigest()}"
        indicator_ids[ip] = indicator_id

        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": profile.get('first_seen', datetime.now().isoformat()) + ("Z" if not profile.get('first_seen', '').endswith('Z') else ""),
            "modified": profile.get('last_seen', datetime.now().isoformat()) + ("Z" if not profile.get('last_seen', '').endswith('Z') else ""),
            "name": f"MAVLink Attacker {ip}",
            "description": f"Attacker from {profile.get('country', 'Unknown')} ({profile.get('city', 'Unknown')}) "
                          f"with {profile.get('attack_count', 0)} attacks. "
                          f"Threat level: {threat_level}. Skill: {skill_level}. "
                          f"Attack types: {', '.join(attack_types)}.",
            "indicator_types": ["malicious-activity"],
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "pattern_type": "stix",
            "valid_from": profile.get('first_seen', datetime.now().isoformat()),
            "labels": [f"threat-level-{threat_level.lower()}"],
            "custom_properties": {
                "x_mavlink_country": profile.get('country', 'Unknown'),
                "x_mavlink_city": profile.get('city', 'Unknown'),
                "x_mavlink_isp": profile.get('isp', 'Unknown'),
                "x_mavlink_attack_count": profile.get('attack_count', 0),
                "x_mavlink_visit_count": profile.get('visit_count', 0),
                "x_mavlink_vpn_detected": profile.get('vpn_detected', False),
                "x_mavlink_threat_level": threat_level,
                "x_mavlink_attack_types": list(attack_types),
                "x_mavlink_skill_level": skill_level,
                "x_mavlink_threat_score": threat_score,
            }
        }
        stix_bundle["objects"].append(indicator)

        # Create attack pattern objects
        for attack_type in attack_types:
            ap_id = f"attack-pattern--{hashlib.md5(f'{ip}-{attack_type}'.encode()).hexdigest()}"
            ap = {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": ap_id,
                "created": datetime.now().isoformat() + "Z",
                "modified": datetime.now().isoformat() + "Z",
                "name": f"MAVLink {attack_type.replace('_', ' ').title()}",
                "description": f"MAVLink protocol attack: {attack_type}"
            }
            stix_bundle["objects"].append(ap)

            # Relationship: indicator -> uses -> attack-pattern
            rel = {
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{hashlib.md5(f'{indicator_id}-{ap_id}'.encode()).hexdigest()}",
                "created": datetime.now().isoformat() + "Z",
                "modified": datetime.now().isoformat() + "Z",
                "relationship_type": "uses",
                "source_ref": indicator_id,
                "target_ref": ap_id,
            }
            stix_bundle["objects"].append(rel)

    # Add campaigns as Grouping objects
    for cid, campaign in campaigns.items():
        member_refs = []
        for ip in campaign.get('attacker_ips', []):
            if ip in indicator_ids:
                member_refs.append(indicator_ids[ip])

        grouping = {
            "type": "grouping",
            "spec_version": "2.1",
            "id": f"grouping--{hashlib.md5(cid.encode()).hexdigest()}",
            "created": campaign.get('first_seen', datetime.now().isoformat()) + "Z",
            "modified": campaign.get('last_seen', datetime.now().isoformat()) + "Z",
            "name": campaign.get('name', f'Campaign {cid}'),
            "description": f"Campaign type: {campaign.get('campaign_type', 'UNKNOWN')}, "
                          f"Threat: {campaign.get('threat_level', 'LOW')}, "
                          f"Events: {campaign.get('total_events', 0)}, "
                          f"Coordinated: {campaign.get('is_coordinated', False)}",
            "context": "suspicious-activity",
            "object_refs": member_refs,
        }
        stix_bundle["objects"].append(grouping)

    with open(filename, 'w') as f:
        json.dump(stix_bundle, f, indent=2, default=str)

    print(f"   ✅ STIX 2.1 exported: {filename}")
    print(f"      Objects: {len(stix_bundle['objects'])} "
          f"(1 identity + {len(data)} indicators + patterns + "
          f"{len(campaigns)} campaigns + relationships)")
    return filename


def export_text_report(data: dict, fingerprints: dict, deception: dict, output_dir: str):
    """Export human-readable text report."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = os.path.join(output_dir, f'threat_report_{timestamp}.txt')

    with open(filename, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("  MAVLink Honeypot — Threat Intelligence Report\n")
        f.write(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 70 + "\n\n")

        # Summary
        total_attacks = sum(p.get('attack_count', 0) for p in data.values())
        countries = set(p.get('country', 'Unknown') for p in data.values())
        vpn_count = sum(1 for p in data.values() if p.get('vpn_detected'))

        f.write("SUMMARY\n")
        f.write("-" * 40 + "\n")
        f.write(f"  Total attackers:     {len(data)}\n")
        f.write(f"  Total attacks:       {total_attacks}\n")
        f.write(f"  Countries:           {len(countries)}\n")
        f.write(f"  VPN users:           {vpn_count}\n\n")

        # High-priority threats
        critical = [(ip, p) for ip, p in data.items() if classify_threat(p) == "CRITICAL"]
        high = [(ip, p) for ip, p in data.items() if classify_threat(p) == "HIGH"]

        if critical:
            f.write("🔴 CRITICAL THREATS\n")
            f.write("-" * 40 + "\n")
            for ip, profile in critical:
                attack_types = set(a.get('type', '') for a in profile.get('attacks', []))
                f.write(f"\n  IP:           {ip}\n")
                f.write(f"  Country:      {profile.get('country', 'Unknown')} ({profile.get('city', 'Unknown')})\n")
                f.write(f"  ISP:          {profile.get('isp', 'Unknown')}\n")
                f.write(f"  Attacks:      {profile.get('attack_count', 0)}\n")
                f.write(f"  Types:        {', '.join(attack_types)}\n")
                f.write(f"  VPN:          {'Yes' if profile.get('vpn_detected') else 'No'}\n")
                f.write(f"  First seen:   {profile.get('first_seen', 'N/A')}\n")
                f.write(f"  Last seen:    {profile.get('last_seen', 'N/A')}\n")
                linked = profile.get('linked_identities', [])
                if linked:
                    f.write(f"  Linked IPs:   {', '.join(linked)}\n")

        if high:
            f.write(f"\n🟠 HIGH THREATS\n")
            f.write("-" * 40 + "\n")
            for ip, profile in high:
                attack_types = set(a.get('type', '') for a in profile.get('attacks', []))
                f.write(f"\n  IP:           {ip}\n")
                f.write(f"  Country:      {profile.get('country', 'Unknown')}\n")
                f.write(f"  Attacks:      {profile.get('attack_count', 0)}\n")
                f.write(f"  Types:        {', '.join(attack_types)}\n")

        # All attackers table
        f.write(f"\n\nALL ATTACKERS\n")
        f.write("-" * 70 + "\n")
        f.write(f"{'IP':<20} {'Country':<15} {'Attacks':>8} {'Level':<10} {'VPN':>4}\n")
        f.write("-" * 70 + "\n")

        for ip, profile in sorted(data.items(), key=lambda x: x[1].get('attack_count', 0), reverse=True):
            threat = classify_threat(profile)
            f.write(f"{ip:<20} {profile.get('country', 'Unknown'):<15} {profile.get('attack_count', 0):>8} {threat:<10} {'Yes' if profile.get('vpn_detected') else 'No':>4}\n")

        f.write(f"\n{'='*70}\n")
        f.write("  End of Report\n")
        f.write(f"{'='*70}\n")

    print(f"   ✅ Text report exported: {filename}")
    return filename


def main():
    parser = argparse.ArgumentParser(description='MAVLink Honeypot Threat Intelligence Export')
    parser.add_argument('--format', choices=['csv', 'stix', 'text', 'all'], default='all',
                       help='Export format (default: all)')
    parser.add_argument('--days', type=int, default=None,
                       help='Only include data from last N days')
    args = parser.parse_args()

    print("\n🔍 MAVLink Honeypot — Threat Intelligence Export")
    print("=" * 50)

    # Load data
    data = load_attacker_data()
    fingerprints = load_fingerprints()
    deception = load_deception_scores()

    # Filter by time
    if args.days:
        data = filter_by_timerange(data, args.days)

    if not data:
        print("❌ No data to export.")
        sys.exit(1)

    # Create output directory
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Export
    exported = []

    if args.format in ('csv', 'all'):
        exported.append(export_csv(data, fingerprints, deception, OUTPUT_DIR))

    if args.format in ('stix', 'all'):
        exported.append(export_stix(data, fingerprints, OUTPUT_DIR))

    if args.format in ('text', 'all'):
        exported.append(export_text_report(data, fingerprints, deception, OUTPUT_DIR))

    print(f"\n✅ Export complete! {len(exported)} file(s) created in {OUTPUT_DIR}/")


if __name__ == "__main__":
    main()
