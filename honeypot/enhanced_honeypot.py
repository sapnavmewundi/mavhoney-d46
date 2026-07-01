#!/usr/bin/env python3
"""
Enhanced MAVLink Honeypot with GeoIP Integration
Combines semantic analysis with geographic profiling
"""

import sys
import os
sys.path.append(os.path.dirname(__file__))

from mavlink_honeypot import AdaptiveHoneypot, AttackEvent
from geoip_service import GeoIPService, AttackerProfiler
import json
import threading
import time


class EnhancedHoneypot(AdaptiveHoneypot):
    """
    Enhanced honeypot with GeoIP and advanced profiling
    """
    
    def __init__(self, listen_port=5760, sitl_port=5761):
        super().__init__(listen_port, sitl_port)
        
        # Add GeoIP services
        self.geo_service = GeoIPService()
        self.profiler = AttackerProfiler()
        
        # Enhanced dataset with geo data
        self.geo_dataset_file = f"datasets/geo_attack_dataset_{time.strftime('%Y%m%d_%H%M%S')}.csv"
        self._init_geo_dataset()
        
        print("🌍 GeoIP integration enabled")
    
    def _init_geo_dataset(self):
        """Initialize enhanced dataset with geo fields"""
        import csv
        with open(self.geo_dataset_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'timestamp', 'ip', 'port', 'msg_id', 'msg_name', 
                'intent', 'severity', 'payload_hex', 'session_id',
                'honeypot_state', 'packet_rate',
                # GeoIP fields
                'country', 'country_code', 'city', 'region', 'isp', 'org',
                'latitude', 'longitude', 'timezone', 'distance_km', 'rtt_ms',
                'threat_level', 'behavior_signature'
            ])
    
    def handle_client(self, client_sock, addr):
        """Enhanced client handler with GeoIP lookup"""
        import hashlib
        import csv
        
        session_id = hashlib.md5(f"{addr[0]}:{addr[1]}:{time.time()}".encode()).hexdigest()[:8]
        
        # Perform GeoIP lookup once per connection
        geo_data = self.geo_service.lookup(addr[0])
        
        if geo_data:
            print(f"🎯 New connection from {addr[0]}:{addr[1]} (session: {session_id})")
            print(f"   📍 Location: {geo_data.city}, {geo_data.country} ({geo_data.distance:.0f} km away)")
            print(f"   🏢 ISP: {geo_data.isp}")
        else:
            print(f"🎯 New connection from {addr[0]}:{addr[1]} (session: {session_id})")
        
        try:
            while True:
                data = client_sock.recv(1024)
                if not data:
                    break
                
                # Parse MAVLink
                parsed = self.parse_mavlink_packet(data)
                if not parsed:
                    continue
                
                msg_id = parsed["msg_id"]
                
                # Real-time semantic analysis
                semantics = self.analyze_intent(msg_id, addr)
                
                # Calculate packet rate
                session_key = f"{addr[0]}:{addr[1]}"
                packet_rate = len(self.msg_timestamps.get(session_key, [])) / 5.0
                
                # Create attack event
                event = AttackEvent(
                    timestamp=time.strftime('%Y-%m-%dT%H:%M:%S'),
                    attacker_ip=addr[0],
                    attacker_port=addr[1],
                    msg_id=msg_id,
                    msg_name=semantics["name"],
                    intent=semantics["intent"],
                    severity=semantics["severity"],
                    payload_hex=parsed["payload"].hex(),
                    session_id=session_id
                )
                
                # Log and update
                self.events.append(event)
                self.log_event(event, packet_rate)
                self.update_attacker_profile(event, packet_rate)
                
                # Enhanced logging with geo data
                if geo_data:
                    profile_data = {
                        'ip': addr[0],
                        'severity_score': semantics["severity"],
                        'avg_packet_rate': packet_rate,
                        'attack_types': {semantics["intent"]: 1}
                    }
                    threat_level = self.profiler.classify_threat_level(profile_data)
                    behavior_sig = self.profiler.generate_behavior_signature(
                        self.session_data[session_key]
                    )
                    
                    # Write to enhanced dataset
                    with open(self.geo_dataset_file, 'a', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow([
                            event.timestamp, event.attacker_ip, event.attacker_port,
                            event.msg_id, event.msg_name, event.intent, event.severity,
                            event.payload_hex, event.session_id, self.current_state,
                            packet_rate,
                            geo_data.country, geo_data.country_code, geo_data.city,
                            geo_data.region, geo_data.isp, geo_data.org,
                            geo_data.latitude, geo_data.longitude, geo_data.timezone,
                            geo_data.estimated_distance_km, geo_data.rtt_ms,
                            threat_level, behavior_sig
                        ])
                
                # Adapt behavior
                self.adapt_behavior(semantics["severity"], semantics["intent"])
                
                print(f"  📨 [{self.current_state}] {semantics['name']} -> {semantics['intent']} (severity: {semantics['severity']})")
                
                # Send adaptive response
                response = self.generate_response(msg_id)
                if response:
                    client_sock.send(response)
        
        except Exception as e:
            print(f"  ❌ Error handling {addr}: {e}")
        
        finally:
            client_sock.close()
            print(f"  🔌 Connection closed: {addr[0]}:{addr[1]}")
    
    def export_attacker_report(self, output_file="attacker_report.json"):
        """Export detailed attacker profiles"""
        profiles = []
        
        for ip, profile in self.attacker_profiles.items():
            geo = self.geo_service.lookup(ip)
            
            profile_dict = {
                'ip': ip,
                'first_seen': profile.first_seen,
                'last_seen': profile.last_seen,
                'total_packets': profile.total_packets,
                'attack_types': profile.attack_types,
                'severity_score': round(profile.severity_score, 2),
                'command_sequence': profile.command_sequence,
                'avg_packet_rate': round(profile.avg_packet_rate, 2),
            }
            
            if geo:
                profile_dict.update({
                    'country': geo.country,
                    'city': geo.city,
                    'isp': geo.isp,
                    'distance_km': round(geo.estimated_distance_km, 2),
                    'rtt_ms': geo.rtt_ms
                })
            
            # Classify threat
            threat = self.profiler.classify_threat_level(profile_dict)
            profile_dict['threat_level'] = threat
            
            profiles.append(profile_dict)
        
        # Save to file
        with open(output_file, 'w') as f:
            json.dump(profiles, f, indent=2)
        
        print(f"\n📊 Attacker report saved to: {output_file}")
        return profiles


def export_thread(honeypot):
    """Background thread to periodically export reports"""
    while True:
        time.sleep(300)  # Every 5 minutes
        try:
            honeypot.export_attacker_report("logs/attacker_report_latest.json")
        except Exception as e:
            print(f"⚠️  Error exporting report: {e}")


if __name__ == "__main__":
    # Create enhanced honeypot
    honeypot = EnhancedHoneypot()
    
    # Start background export thread
    export_t = threading.Thread(target=export_thread, args=(honeypot,), daemon=True)
    export_t.start()
    
    # Start honeypot
    honeypot.start()
