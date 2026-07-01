#!/usr/bin/env python3
"""
GeoIP Integration & Advanced Attacker Profiling
Primary: MaxMind GeoLite2 local database (fast, offline, no rate limits)
Fallback: ip-api.com free API (for when mmdb file is not available)
"""

import socket
import time
import os
from typing import Dict, Optional
from dataclasses import dataclass
from math import radians, cos, sin, asin, sqrt

# Try MaxMind first
try:
    import geoip2.database
    import geoip2.errors
    MAXMIND_AVAILABLE = True
except ImportError:
    MAXMIND_AVAILABLE = False

# Fallback to HTTP API
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


@dataclass
class GeoLocation:
    """Geographic location data"""
    ip: str
    country: str
    country_code: str
    city: str
    region: str
    isp: str
    org: str
    latitude: float
    longitude: float
    timezone: str
    estimated_distance_km: float = 0.0
    rtt_ms: float = 0.0


class GeoIPService:
    """
    GeoIP lookup and distance estimation service.
    Uses MaxMind GeoLite2 database if available, falls back to ip-api.com.
    """

    # Search for mmdb file in common locations
    MMDB_SEARCH_PATHS = [
        os.path.join(os.path.dirname(__file__), 'GeoLite2-City.mmdb'),
        os.path.join(os.path.dirname(os.path.dirname(__file__)), 'GeoLite2-City.mmdb'),
        '/usr/share/GeoIP/GeoLite2-City.mmdb',
        os.path.expanduser('~/GeoLite2-City.mmdb'),
    ]

    def __init__(self, honeypot_lat=37.7749, honeypot_lon=-122.4194):
        self.honeypot_lat = honeypot_lat
        self.honeypot_lon = honeypot_lon
        self.cache = {}
        self.maxmind_reader = None
        self.use_maxmind = False

        # Try to initialize MaxMind
        if MAXMIND_AVAILABLE:
            for mmdb_path in self.MMDB_SEARCH_PATHS:
                if os.path.exists(mmdb_path):
                    try:
                        self.maxmind_reader = geoip2.database.Reader(mmdb_path)
                        self.use_maxmind = True
                        print(f"🌍 GeoIP: Using MaxMind database ({mmdb_path})")
                        break
                    except Exception as e:
                        print(f"⚠️  Failed to load MaxMind DB: {e}")

        if not self.use_maxmind:
            if REQUESTS_AVAILABLE:
                print("🌍 GeoIP: Using ip-api.com fallback (rate limited)")
                self.api_url = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,city,lat,lon,isp,org,as,timezone"
            else:
                print("⚠️  GeoIP: No provider available (install geoip2 or requests)")

    def lookup(self, ip: str) -> Optional[GeoLocation]:
        """Lookup IP geolocation"""
        # Check cache
        if ip in self.cache:
            return self.cache[ip]

        # Skip private/local IPs
        if self._is_private_ip(ip):
            return GeoLocation(
                ip=ip,
                country="Private",
                country_code="XX",
                city="Local",
                region="Private Network",
                isp="N/A",
                org="N/A",
                latitude=0.0,
                longitude=0.0,
                timezone="N/A"
            )

        # Try MaxMind first
        if self.use_maxmind:
            result = self._lookup_maxmind(ip)
            if result:
                self.cache[ip] = result
                return result

        # Fallback to API
        if REQUESTS_AVAILABLE:
            result = self._lookup_api(ip)
            if result:
                self.cache[ip] = result
                return result

        return None

    def _lookup_maxmind(self, ip: str) -> Optional[GeoLocation]:
        """Lookup using MaxMind GeoLite2 database"""
        try:
            response = self.maxmind_reader.city(ip)

            lat = response.location.latitude or 0.0
            lon = response.location.longitude or 0.0

            distance = self._calculate_distance(
                lat, lon, self.honeypot_lat, self.honeypot_lon
            )

            rtt = self._measure_rtt(ip)

            return GeoLocation(
                ip=ip,
                country=response.country.name or "Unknown",
                country_code=response.country.iso_code or "XX",
                city=response.city.name or "Unknown",
                region=response.subdivisions.most_specific.name if response.subdivisions else "Unknown",
                isp="N/A",  # GeoLite2-City doesn't include ISP
                org="N/A",
                latitude=lat,
                longitude=lon,
                timezone=response.location.time_zone or "Unknown",
                estimated_distance_km=distance,
                rtt_ms=rtt
            )
        except geoip2.errors.AddressNotFoundError:
            return None
        except Exception as e:
            print(f"⚠️  MaxMind lookup failed for {ip}: {e}")
            return None

    def _lookup_api(self, ip: str) -> Optional[GeoLocation]:
        """Fallback: Lookup using ip-api.com"""
        try:
            response = requests.get(
                self.api_url.format(ip=ip),
                timeout=5
            )

            if response.status_code == 200:
                data = response.json()

                if data.get('status') == 'success':
                    distance = self._calculate_distance(
                        data['lat'], data['lon'],
                        self.honeypot_lat, self.honeypot_lon
                    )
                    rtt = self._measure_rtt(ip)

                    return GeoLocation(
                        ip=ip,
                        country=data.get('country', 'Unknown'),
                        country_code=data.get('countryCode', 'XX'),
                        city=data.get('city', 'Unknown'),
                        region=data.get('region', 'Unknown'),
                        isp=data.get('isp', 'Unknown'),
                        org=data.get('org', 'Unknown'),
                        latitude=data.get('lat', 0.0),
                        longitude=data.get('lon', 0.0),
                        timezone=data.get('timezone', 'Unknown'),
                        estimated_distance_km=distance,
                        rtt_ms=rtt
                    )

            # Rate limiting — wait
            time.sleep(1.5)

        except Exception as e:
            print(f"⚠️  GeoIP API lookup failed for {ip}: {e}")

        return None

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local"""
        private_ranges = [
            ('10.0.0.0', '10.255.255.255'),
            ('172.16.0.0', '172.31.255.255'),
            ('192.168.0.0', '192.168.255.255'),
            ('127.0.0.0', '127.255.255.255'),
        ]

        try:
            ip_int = int.from_bytes(socket.inet_aton(ip), 'big')
            for start, end in private_ranges:
                start_int = int.from_bytes(socket.inet_aton(start), 'big')
                end_int = int.from_bytes(socket.inet_aton(end), 'big')
                if start_int <= ip_int <= end_int:
                    return True
        except Exception:
            pass

        return False

    def _calculate_distance(self, lat1, lon1, lat2, lon2) -> float:
        """Calculate distance using Haversine formula"""
        lon1, lat1, lon2, lat2 = map(radians, [lon1, lat1, lon2, lat2])
        dlon = lon2 - lon1
        dlat = lat2 - lat1
        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * asin(sqrt(a))
        r = 6371  # Earth radius in kilometers
        return c * r

    def _measure_rtt(self, ip: str, port=80, timeout=2) -> float:
        """Measure Round-Trip Time to estimate distance"""
        try:
            start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            rtt = (time.time() - start) * 1000
            sock.close()
            return round(rtt, 2)
        except Exception:
            return 0.0

    def __del__(self):
        """Clean up MaxMind reader"""
        if self.maxmind_reader:
            try:
                self.maxmind_reader.close()
            except Exception:
                pass


class AttackerProfiler:
    """Advanced attacker behavioral profiling"""

    def __init__(self):
        self.geo_service = GeoIPService()

    def enrich_profile(self, profile_data: Dict) -> Dict:
        """Enrich attacker profile with geo data"""
        ip = profile_data.get('ip')

        if not ip:
            return profile_data

        geo = self.geo_service.lookup(ip)

        if geo:
            profile_data['country'] = geo.country
            profile_data['country_code'] = geo.country_code
            profile_data['city'] = geo.city
            profile_data['region'] = geo.region
            profile_data['isp'] = geo.isp
            profile_data['org'] = geo.org
            profile_data['latitude'] = geo.latitude
            profile_data['longitude'] = geo.longitude
            profile_data['timezone'] = geo.timezone
            profile_data['estimated_distance_km'] = geo.estimated_distance_km
            profile_data['rtt_ms'] = geo.rtt_ms

        return profile_data

    def classify_threat_level(self, profile_data: Dict) -> str:
        """Classify threat level based on behavior"""
        severity = profile_data.get('severity_score', 0)
        packet_rate = profile_data.get('avg_packet_rate', 0)
        attack_types = profile_data.get('attack_types', {})

        high_threat_patterns = ['HIJACK', 'GPS_SPOOF', 'DOS_FLOOD']
        has_high_threat = any(
            attack_type in high_threat_patterns
            for attack_type in attack_types.keys()
        )

        if severity >= 8 or has_high_threat:
            return "CRITICAL"
        elif severity >= 6 or packet_rate > 20:
            return "HIGH"
        elif severity >= 4:
            return "MEDIUM"
        else:
            return "LOW"

    def generate_behavior_signature(self, command_sequence: list) -> str:
        """Generate unique behavior signature from command sequence"""
        import hashlib

        if not command_sequence:
            return "NO_PATTERN"

        sig = '_'.join(command_sequence[-10:])
        return hashlib.md5(sig.encode()).hexdigest()[:8].upper()


# Standalone test
if __name__ == "__main__":
    print("🌍 Testing GeoIP Service...")
    print(f"   MaxMind available: {MAXMIND_AVAILABLE}")
    print(f"   Requests available: {REQUESTS_AVAILABLE}")

    geo = GeoIPService()

    test_ips = [
        "8.8.8.8",       # Google DNS (USA)
        "1.1.1.1",       # Cloudflare (USA)
        "185.199.108.1", # GitHub (USA)
        "127.0.0.1",     # Localhost
    ]

    for ip in test_ips:
        print(f"\n📍 Looking up: {ip}")
        result = geo.lookup(ip)
        if result:
            print(f"   Country: {result.country} ({result.country_code})")
            print(f"   City: {result.city}")
            print(f"   ISP: {result.isp}")
            print(f"   Distance: {result.estimated_distance_km:.2f} km")
            print(f"   RTT: {result.rtt_ms} ms")
