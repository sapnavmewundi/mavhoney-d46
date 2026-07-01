#!/usr/bin/env python3
"""
Mode Scheduler — Bi-Weekly Adaptive ON/OFF Toggle
===================================================

Automatically switches the honeypot between adaptive and static modes
every 2 weeks for the ON/OFF experiment.

Schedule:
    Week 1-2:  Adaptive ON
    Week 3-4:  Adaptive OFF (static)
    Week 5-6:  Adaptive ON
    Week 7-8:  Adaptive OFF (static)
    Week 9-10: Adaptive ON

Usage::
    # Check current mode
    python -m honeypot.mode_scheduler status

    # Manual toggle
    python -m honeypot.mode_scheduler toggle

    # Install cron job for automatic bi-weekly switching
    python -m honeypot.mode_scheduler install-cron

    # Get current schedule
    python -m honeypot.mode_scheduler schedule
"""

import json
import os
import subprocess
import sys
from datetime import datetime, timedelta

STATE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config", "mode_state.json"
)

# Deployment start date — update this to your actual start
DEPLOYMENT_START = "2026-04-16"
TOGGLE_INTERVAL_DAYS = 14  # bi-weekly


def get_state():
    """Read current mode state."""
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return {
        "current_mode": "adaptive",
        "last_toggle": datetime.now().isoformat(),
        "toggle_history": [],
        "deployment_start": DEPLOYMENT_START,
    }


def save_state(state):
    """Save mode state."""
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def get_scheduled_mode():
    """Calculate what mode should be active based on deployment schedule."""
    start = datetime.strptime(DEPLOYMENT_START, "%Y-%m-%d")
    now = datetime.now()
    days_elapsed = (now - start).days
    period = days_elapsed // TOGGLE_INTERVAL_DAYS

    # Even periods = adaptive ON, Odd periods = static (OFF)
    return "adaptive" if period % 2 == 0 else "static"


def toggle_mode():
    """Toggle between adaptive and static mode."""
    state = get_state()
    old_mode = state["current_mode"]
    new_mode = "static" if old_mode == "adaptive" else "adaptive"

    state["current_mode"] = new_mode
    state["last_toggle"] = datetime.now().isoformat()
    state["toggle_history"].append({
        "from": old_mode,
        "to": new_mode,
        "timestamp": datetime.now().isoformat(),
    })

    save_state(state)

    # Restart honeypot with new mode
    if new_mode == "adaptive":
        service_exec = "/usr/bin/python3 -m honeypot.mavlink_honeypot"
    else:
        service_exec = "/usr/bin/python3 -m honeypot.static_honeypot"

    # Update systemd service
    service_content = f"""[Unit]
Description=MAVLink Honeypot ({new_mode.upper()} mode)
After=network.target
[Service]
Type=simple
WorkingDirectory=/root/mavlink_honeypot
ExecStart={service_exec}
Restart=always
RestartSec=5
StandardOutput=append:/root/honeypot.log
StandardError=append:/root/honeypot.log
[Install]
WantedBy=multi-user.target
"""

    with open("/etc/systemd/system/honeypot.service", "w") as f:
        f.write(service_content)

    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "restart", "honeypot"], check=True)

    print(f"🔄 Mode switched: {old_mode} → {new_mode}")
    print(f"   Timestamp: {state['last_toggle']}")
    print(f"   Service restarted with: {service_exec}")

    return new_mode


def show_status():
    """Show current mode and schedule."""
    state = get_state()
    scheduled = get_scheduled_mode()
    start = datetime.strptime(DEPLOYMENT_START, "%Y-%m-%d")
    now = datetime.now()
    days = (now - start).days
    period = days // TOGGLE_INTERVAL_DAYS
    next_toggle = start + timedelta(days=(period + 1) * TOGGLE_INTERVAL_DAYS)
    days_until_toggle = (next_toggle - now).days

    print("╔══════════════════════════════════════╗")
    print("║   🔄 Mode Scheduler Status           ║")
    print("╠══════════════════════════════════════╣")
    print(f"║   Current mode:    {state['current_mode'].upper():>10}       ║")
    print(f"║   Scheduled mode:  {scheduled.upper():>10}       ║")
    print(f"║   Day of deployment: {days:>5}           ║")
    print(f"║   Current period:  {period + 1:>5}             ║")
    print(f"║   Next toggle in:  {days_until_toggle:>5} days        ║")
    print(f"║   Next toggle:     {next_toggle.strftime('%Y-%m-%d'):>10}       ║")
    print("╚══════════════════════════════════════╝")

    if state["current_mode"] != scheduled:
        print(f"\n⚠️  Mode mismatch! Should be {scheduled.upper()}. Run: python -m honeypot.mode_scheduler toggle")

    if state["toggle_history"]:
        print(f"\nToggle history ({len(state['toggle_history'])} switches):")
        for h in state["toggle_history"][-5:]:
            print(f"  {h['timestamp']}: {h['from']} → {h['to']}")


def show_schedule():
    """Display the full ON/OFF schedule."""
    start = datetime.strptime(DEPLOYMENT_START, "%Y-%m-%d")
    print("\n📅 Full ON/OFF Schedule:")
    print("=" * 50)
    for i in range(5):
        begin = start + timedelta(days=i * TOGGLE_INTERVAL_DAYS)
        end = begin + timedelta(days=TOGGLE_INTERVAL_DAYS - 1)
        mode = "ADAPTIVE ON ✅" if i % 2 == 0 else "STATIC OFF ⬜"
        print(f"  Week {i*2+1}-{i*2+2}: {begin.strftime('%d %b')} - {end.strftime('%d %b')}  →  {mode}")
    print()


def install_cron():
    """Install cron job for automatic bi-weekly checking."""
    cron_cmd = f"0 0 * * 0 cd /root/mavlink_honeypot && /usr/bin/python3 -m honeypot.mode_scheduler auto-check >> /root/mode_toggle.log 2>&1"
    
    # Add to crontab
    result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    existing = result.stdout if result.returncode == 0 else ""
    
    if "mode_scheduler" not in existing:
        new_crontab = existing.strip() + "\n" + cron_cmd + "\n"
        proc = subprocess.run(["crontab", "-"], input=new_crontab, text=True)
        print("✅ Cron job installed (checks every Sunday midnight)")
    else:
        print("ℹ️  Cron job already exists")


def auto_check():
    """Auto-check and toggle if schedule says so."""
    state = get_state()
    scheduled = get_scheduled_mode()
    
    if state["current_mode"] != scheduled:
        print(f"[{datetime.now().isoformat()}] Schedule says {scheduled}, currently {state['current_mode']}. Toggling...")
        toggle_mode()
    else:
        print(f"[{datetime.now().isoformat()}] Mode {state['current_mode']} matches schedule. No change needed.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        show_status()
        sys.exit(0)

    cmd = sys.argv[1]
    if cmd == "status":
        show_status()
    elif cmd == "toggle":
        toggle_mode()
    elif cmd == "schedule":
        show_schedule()
    elif cmd == "install-cron":
        install_cron()
    elif cmd == "auto-check":
        auto_check()
    else:
        print(f"Unknown command: {cmd}")
        print("Usage: python -m honeypot.mode_scheduler [status|toggle|schedule|install-cron|auto-check]")
