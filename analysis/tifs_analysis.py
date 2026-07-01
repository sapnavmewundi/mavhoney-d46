#!/usr/bin/env python3
"""
TIFS-Level Statistical Analysis Suite
Generates: survival analysis, bootstrap CIs, temporal stability,
           deception metrics, composite engagement scores.
"""

import csv
import json
import math
import random
import os
from collections import defaultdict
from datetime import datetime, timedelta

random.seed(42)

BASE = "/Users/apple/mavlink_honeypot"
EXCLUDE_IPS = {"223.31.218.223", "152.57.179.137"}

# ── Load Data ──────────────────────────────────────────────

def load_connections(path):
    rows = []
    with open(path, "r") as f:
        for r in csv.DictReader(f):
            if r["ip"] in EXCLUDE_IPS:
                continue
            r["duration_sec"] = float(r.get("duration_sec", 0))
            r["packets"] = int(r.get("packets", 0))
            rows.append(r)
    return rows

def load_adaptive(path):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, "r") as f:
        for r in csv.DictReader(f):
            if r.get("ip") in EXCLUDE_IPS:
                continue
            rows.append(r)
    return rows

def load_firewall(path):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, "r") as f:
        reader = csv.reader(f)
        for r in reader:
            if len(r) >= 2 and r[1] not in EXCLUDE_IPS:
                rows.append({"timestamp": r[0], "ip": r[1]})
    return rows

# ── 1. Survival Analysis ──────────────────────────────────

def survival_analysis(conns):
    """Kaplan-Meier-style session survival analysis."""
    sessions = {}
    for r in conns:
        sid = r["session_id"]
        if r["event_type"] == "DISCONNECT":
            sessions[sid] = {
                "ip": r["ip"],
                "duration": r["duration_sec"],
                "packets": r["packets"],
            }
    
    durations = sorted([s["duration"] for s in sessions.values()])
    if not durations:
        return {}
    
    n = len(durations)
    # Kaplan-Meier at key time points
    time_points = [0, 1, 5, 10, 15, 30, 60, 120, 300, 600]
    km_curve = []
    for t in time_points:
        surviving = sum(1 for d in durations if d > t)
        km_curve.append({"time_sec": t, "survival_prob": round(surviving / n, 4)})
    
    # Percentiles
    median = durations[n // 2] if n > 0 else 0
    p25 = durations[n // 4] if n > 0 else 0
    p75 = durations[3 * n // 4] if n > 0 else 0
    mean_dur = sum(durations) / n if n > 0 else 0
    
    # Sessions > 10 sec (meaningful engagement)
    engaged = sum(1 for d in durations if d > 10)
    
    return {
        "total_sessions": n,
        "mean_duration_sec": round(mean_dur, 2),
        "median_duration_sec": round(median, 2),
        "p25_duration": round(p25, 2),
        "p75_duration": round(p75, 2),
        "max_duration_sec": round(max(durations), 2),
        "sessions_gt_10s": engaged,
        "sessions_gt_10s_pct": round(100 * engaged / n, 1),
        "km_curve": km_curve,
    }

# ── 2. Bootstrap Confidence Intervals ─────────────────────

def bootstrap_ci(data, n_boot=10000, ci=0.95):
    """Bootstrap 95% CI for the mean."""
    if not data:
        return {"mean": 0, "ci_lower": 0, "ci_upper": 0}
    
    n = len(data)
    means = []
    for _ in range(n_boot):
        sample = [data[random.randint(0, n-1)] for _ in range(n)]
        means.append(sum(sample) / n)
    
    means.sort()
    alpha = (1 - ci) / 2
    lo = means[int(alpha * n_boot)]
    hi = means[int((1 - alpha) * n_boot)]
    
    return {
        "mean": round(sum(data) / n, 4),
        "ci_lower": round(lo, 4),
        "ci_upper": round(hi, 4),
        "n": n,
    }

def compute_daily_metrics(conns, fw_data):
    """Compute daily aggregates for bootstrap analysis."""
    daily_conns = defaultdict(int)
    daily_packets = defaultdict(int)
    
    for r in conns:
        if r["event_type"] == "DISCONNECT":
            day = r["timestamp"][:10]
            daily_conns[day] += 1
            daily_packets[day] += r["packets"]
    
    daily_fw = defaultdict(int)
    for r in fw_data:
        ts = r["timestamp"]
        # Parse "Apr 15 11:21:33" format
        try:
            dt = datetime.strptime(f"2026 {ts}", "%Y %b %d %H:%M:%S")
            day = dt.strftime("%Y-%m-%d")
        except:
            day = ts[:10]
        daily_fw[day] += 1
    
    return daily_conns, daily_packets, daily_fw

# ── 3. Temporal Stability (Autocorrelation) ────────────────

def autocorrelation(series, lag=1):
    """Compute autocorrelation at given lag."""
    if len(series) < lag + 2:
        return 0
    n = len(series)
    mean = sum(series) / n
    var = sum((x - mean)**2 for x in series) / n
    if var == 0:
        return 0
    cov = sum((series[i] - mean) * (series[i + lag] - mean) for i in range(n - lag)) / (n - lag)
    return round(cov / var, 4)

# ── 4. Deception Effectiveness Metrics ─────────────────────

def deception_metrics(adaptive_data, conns):
    """Compute per-attacker deception effectiveness."""
    # Per-attacker command diversity
    attacker_cmds = defaultdict(list)
    attacker_intents = defaultdict(set)
    attacker_states = defaultdict(set)
    
    for r in adaptive_data:
        ip = r.get("ip", "")
        msg_id = r.get("msg_id", "")
        intent = r.get("intent", "")
        state = r.get("honeypot_state", "")
        attacker_cmds[ip].append(msg_id)
        if intent:
            attacker_intents[ip].add(intent)
        if state:
            attacker_states[ip].add(state)
    
    # Shannon entropy per attacker
    entropies = []
    for ip, cmds in attacker_cmds.items():
        if len(cmds) < 3:
            continue
        counts = defaultdict(int)
        for c in cmds:
            counts[c] += 1
        n = len(cmds)
        h = -sum((cnt/n) * math.log2(cnt/n) for cnt in counts.values() if cnt > 0)
        entropies.append({"ip": ip, "entropy": round(h, 4), "unique_cmds": len(counts), "total_cmds": n})
    
    # Session durations per attacker
    sessions_by_ip = defaultdict(list)
    for r in conns:
        if r["event_type"] == "DISCONNECT" and r["duration_sec"] > 0:
            sessions_by_ip[r["ip"]].append(r["duration_sec"])
    
    # Revisit probability
    multi_visit = sum(1 for ip, sessions in sessions_by_ip.items() if len(sessions) > 1)
    total_attackers = len(sessions_by_ip)
    revisit_prob = round(multi_visit / total_attackers, 4) if total_attackers > 0 else 0
    
    # FSM state depth per attacker
    state_depths = [len(states) for states in attacker_states.values() if len(states) > 0]
    
    return {
        "total_attackers_with_commands": len(attacker_cmds),
        "mean_entropy": round(sum(e["entropy"] for e in entropies) / len(entropies), 4) if entropies else 0,
        "max_entropy": max((e["entropy"] for e in entropies), default=0),
        "mean_unique_cmds": round(sum(e["unique_cmds"] for e in entropies) / len(entropies), 2) if entropies else 0,
        "revisit_probability": revisit_prob,
        "multi_visit_attackers": multi_visit,
        "total_unique_attackers": total_attackers,
        "mean_state_depth": round(sum(state_depths) / len(state_depths), 2) if state_depths else 0,
        "max_state_depth": max(state_depths, default=0),
        "top_entropy_attackers": sorted(entropies, key=lambda x: -x["entropy"])[:5],
    }

# ── 5. Composite Engagement Score ──────────────────────────

def composite_engagement(adaptive_data, conns):
    """Compute composite engagement score E = w1*D + w2*H + w3*T + w4*R."""
    # Weights
    w1, w2, w3, w4 = 0.3, 0.3, 0.25, 0.15
    
    # Per-attacker metrics
    ip_cmds = defaultdict(list)
    for r in adaptive_data:
        ip_cmds[r.get("ip", "")].append(r.get("msg_id", ""))
    
    ip_durations = defaultdict(list)
    for r in conns:
        if r["event_type"] == "DISCONNECT":
            ip_durations[r["ip"]].append(r["duration_sec"])
    
    all_ips = set(ip_cmds.keys()) | set(ip_durations.keys())
    scores = []
    
    max_duration = max((max(durs) for durs in ip_durations.values() if durs), default=1)
    max_cmds = max((len(set(cmds)) for cmds in ip_cmds.values() if cmds), default=1)
    
    for ip in all_ips:
        # D: interaction depth (normalized unique commands)
        cmds = ip_cmds.get(ip, [])
        D = len(set(cmds)) / max_cmds if max_cmds > 0 else 0
        
        # H: command entropy (normalized)
        if len(cmds) >= 2:
            counts = defaultdict(int)
            for c in cmds:
                counts[c] += 1
            n = len(cmds)
            h = -sum((cnt/n) * math.log2(cnt/n) for cnt in counts.values() if cnt > 0)
            max_h = math.log2(len(counts)) if len(counts) > 1 else 1
            H = h / max_h if max_h > 0 else 0
        else:
            H = 0
        
        # T: session duration (normalized)
        durs = ip_durations.get(ip, [0])
        T = max(durs) / max_duration if max_duration > 0 else 0
        
        # R: revisit (binary)
        R = 1.0 if len(durs) > 1 else 0.0
        
        E = w1 * D + w2 * H + w3 * T + w4 * R
        scores.append({"ip": ip, "E": round(E, 4), "D": round(D, 4), "H": round(H, 4), "T": round(T, 4), "R": R})
    
    scores.sort(key=lambda x: -x["E"])
    mean_E = sum(s["E"] for s in scores) / len(scores) if scores else 0
    
    return {
        "mean_composite_score": round(mean_E, 4),
        "max_composite_score": scores[0]["E"] if scores else 0,
        "n_attackers": len(scores),
        "top_10": scores[:10],
    }

# ── Main ───────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("TIFS-Level Analysis Suite")
    print("=" * 60)
    
    # Load data
    india_conns = load_connections(f"{BASE}/datasets/connections.csv")
    us_conns = load_connections(f"{BASE}/datasets/us_connections.csv")
    india_adaptive = load_adaptive(f"{BASE}/datasets/adaptive_data.csv")
    india_fw = load_firewall(f"{BASE}/datasets/india/firewall_blocks.csv")
    static_fw = load_firewall(f"{BASE}/datasets/static/firewall_blocks.csv")
    
    results = {}
    
    # ── 1. Survival Analysis ──
    print("\n📊 1. SURVIVAL ANALYSIS")
    print("-" * 40)
    
    india_surv = survival_analysis(india_conns)
    us_surv = survival_analysis(us_conns)
    
    print(f"  India (adaptive): {india_surv['total_sessions']} sessions")
    print(f"    Mean duration: {india_surv['mean_duration_sec']}s")
    print(f"    Median: {india_surv['median_duration_sec']}s")
    print(f"    Max: {india_surv['max_duration_sec']}s")
    print(f"    Sessions >10s: {india_surv['sessions_gt_10s']} ({india_surv['sessions_gt_10s_pct']}%)")
    print(f"  Kaplan-Meier curve:")
    for pt in india_surv["km_curve"]:
        bar = "█" * int(pt["survival_prob"] * 40)
        print(f"    t={pt['time_sec']:>4}s: {pt['survival_prob']:.3f} {bar}")
    
    print(f"\n  US (adaptive): {us_surv['total_sessions']} sessions")
    print(f"    Mean: {us_surv['mean_duration_sec']}s, Median: {us_surv['median_duration_sec']}s")
    
    results["survival"] = {"india": india_surv, "us": us_surv}
    
    # ── 2. Bootstrap CIs ──
    print("\n📊 2. BOOTSTRAP CONFIDENCE INTERVALS (10,000 resamples)")
    print("-" * 40)
    
    # Daily connection counts
    india_daily, india_pkts, india_fw_daily = compute_daily_metrics(india_conns, india_fw)
    _, _, static_fw_daily = compute_daily_metrics([], static_fw)
    
    india_daily_vals = list(india_daily.values())
    static_daily_vals = list(static_fw_daily.values())
    india_pkt_vals = list(india_pkts.values())
    
    ci_conns = bootstrap_ci(india_daily_vals)
    ci_fw_india = bootstrap_ci(list(india_fw_daily.values()))
    ci_fw_static = bootstrap_ci(static_daily_vals)
    
    print(f"  India daily connections: {ci_conns['mean']} [{ci_conns['ci_lower']}, {ci_conns['ci_upper']}] (n={ci_conns['n']})")
    print(f"  India daily FW blocks: {ci_fw_india['mean']} [{ci_fw_india['ci_lower']}, {ci_fw_india['ci_upper']}]")
    print(f"  Static daily FW blocks: {ci_fw_static['mean']} [{ci_fw_static['ci_lower']}, {ci_fw_static['ci_upper']}]")
    
    results["bootstrap"] = {
        "india_daily_conns": ci_conns,
        "india_daily_fw": ci_fw_india,
        "static_daily_fw": ci_fw_static,
    }
    
    # ── 3. Temporal Stability ──
    print("\n📊 3. TEMPORAL STABILITY (Autocorrelation)")
    print("-" * 40)
    
    ac1 = autocorrelation(india_daily_vals, 1)
    ac7 = autocorrelation(india_daily_vals, 7)
    ac1_s = autocorrelation(static_daily_vals, 1)
    
    print(f"  India lag-1 autocorrelation: {ac1}")
    print(f"  India lag-7 autocorrelation: {ac7}")
    print(f"  Static lag-1 autocorrelation: {ac1_s}")
    
    results["temporal"] = {
        "india_ac_lag1": ac1,
        "india_ac_lag7": ac7,
        "static_ac_lag1": ac1_s,
    }
    
    # ── 4. Deception Metrics ──
    print("\n📊 4. DECEPTION EFFECTIVENESS METRICS")
    print("-" * 40)
    
    dec = deception_metrics(india_adaptive, india_conns)
    
    print(f"  Attackers with commands: {dec['total_attackers_with_commands']}")
    print(f"  Mean command entropy: {dec['mean_entropy']}")
    print(f"  Max entropy: {dec['max_entropy']}")
    print(f"  Mean unique cmds/attacker: {dec['mean_unique_cmds']}")
    print(f"  Revisit probability: {dec['revisit_probability']}")
    print(f"  Multi-visit attackers: {dec['multi_visit_attackers']}/{dec['total_unique_attackers']}")
    print(f"  Mean FSM state depth: {dec['mean_state_depth']}")
    print(f"  Max FSM state depth: {dec['max_state_depth']}")
    
    if dec["top_entropy_attackers"]:
        print(f"  Top entropy attackers:")
        for a in dec["top_entropy_attackers"][:3]:
            print(f"    {a['ip']}: H={a['entropy']}, {a['unique_cmds']} unique / {a['total_cmds']} total")
    
    results["deception"] = dec
    
    # ── 5. Composite Engagement Score ──
    print("\n📊 5. COMPOSITE ENGAGEMENT SCORE")
    print("-" * 40)
    print("  E = 0.3·D + 0.3·H + 0.25·T + 0.15·R")
    
    comp = composite_engagement(india_adaptive, india_conns)
    
    print(f"  Mean E: {comp['mean_composite_score']}")
    print(f"  Max E: {comp['max_composite_score']}")
    print(f"  n attackers: {comp['n_attackers']}")
    print(f"  Top engaged:")
    for s in comp["top_10"][:5]:
        print(f"    {s['ip']}: E={s['E']} (D={s['D']}, H={s['H']}, T={s['T']}, R={s['R']})")
    
    results["composite"] = comp
    
    # ── 6. Ablation Study ──
    print("\n📊 6. ABLATION STUDY (from existing data)")
    print("-" * 40)
    
    abl_path = f"{BASE}/reproducibility/results/ablation_study.json"
    if os.path.exists(abl_path):
        with open(abl_path) as f:
            abl = json.load(f)
        
        for config, data in abl["summary"].items():
            score = data["avg_deception_score"]
            states = data["avg_states_reached"]
            diversity = data["avg_response_diversity"]
            print(f"  {config:>16}: score={score:.1f}, states={states:.1f}, diversity={diversity:.2f}")
    
    results["ablation"] = abl["summary"] if os.path.exists(abl_path) else {}
    
    # ── Save Results ──
    out_path = f"{BASE}/analysis/tifs_results.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\n✅ Results saved to {out_path}")
    print("=" * 60)

if __name__ == "__main__":
    main()
