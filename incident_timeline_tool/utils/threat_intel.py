import json
import socket
import requests
from typing import Dict, List, Optional
from datetime import datetime, timezone

THREAT_INTEL_FILE = "data/threat_intel.json"
LOCAL_BLOCKLIST = "data/blocklist.json"

class ThreatIntel:
    def __init__(self):
        self.threat_data = self._load_threat_data()
        self.blocklist = self._load_blocklist()

    def _load_threat_data(self) -> Dict:
        try:
            with open(THREAT_INTEL_FILE, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {'indicators': []}

    def _load_blocklist(self) -> Dict:
        try:
            with open(LOCAL_BLOCKLIST, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {'blocked_ips': [], 'blocked_domains': []}

    def check_ip(self, ip: str) -> Optional[Dict]:
        if ip in self.blocklist.get('blocked_ips', []):
            return {
                'indicator': ip,
                'type': 'ip',
                'risk': 'CRITICAL',
                'source': 'local_blocklist',
                'description': 'IP found in local blocklist'
            }
        
        for indicator in self.threat_data.get('indicators', []):
            if indicator.get('type') == 'ip' and indicator.get('value') == ip:
                return {
                    'indicator': ip,
                    'type': 'ip',
                    'risk': indicator.get('risk', 'HIGH'),
                    'source': indicator.get('source', 'local'),
                    'description': indicator.get('description', '')
                }
        return None

    def check_domain(self, domain: str) -> Optional[Dict]:
        if domain in self.blocklist.get('blocked_domains', []):
            return {
                'indicator': domain,
                'type': 'domain',
                'risk': 'CRITICAL',
                'source': 'local_blocklist',
                'description': 'Domain found in local blocklist'
            }
        
        for indicator in self.threat_data.get('indicators', []):
            if indicator.get('type') == 'domain' and indicator.get('value') == domain:
                return {
                    'indicator': domain,
                    'type': 'domain',
                    'risk': indicator.get('risk', 'HIGH'),
                    'source': indicator.get('source', 'local'),
                    'description': indicator.get('description', '')
                }
        return None

    def enrich_alert(self, alert: Dict) -> Dict:
        enriched = alert.copy()
        threat_info = []
        
        if alert.get('source_ip'):
            threat = self.check_ip(alert['source_ip'])
            if threat:
                threat_info.append(threat)
        
        if alert.get('destination_ip'):
            threat = self.check_ip(alert['destination_ip'])
            if threat:
                threat_info.append(threat)
        
        enriched['threat_intel'] = threat_info
        enriched['threat_detected'] = len(threat_info) > 0
        return enriched

    def update_blocklist(self, ip: str = None, domain: str = None):
        if 'blocked_ips' not in self.blocklist:
            self.blocklist['blocked_ips'] = []
        if 'blocked_domains' not in self.blocklist:
            self.blocklist['blocked_domains'] = []
        
        if ip and ip not in self.blocklist['blocked_ips']:
            self.blocklist['blocked_ips'].append(ip)
        
        if domain and domain not in self.blocklist['blocked_domains']:
            self.blocklist['blocked_domains'].append(domain)
        
        import os
        os.makedirs("data", exist_ok=True)
        with open(LOCAL_BLOCKLIST, 'w') as f:
            json.dump(self.blocklist, f, indent=2)

    def get_reputation(self, ip: str) -> Dict:
        result = {
            'ip': ip,
            'reputation': 'unknown',
            'checks': []
        }
        
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            result['hostname'] = hostname
        except socket.herror:
            result['checks'].append({'source': 'dns', 'status': 'no_reverse_lookup'})
        
        threat = self.check_ip(ip)
        if threat:
            result['reputation'] = threat['risk']
            result['checks'].append(threat)
        
        return result

def create_sample_threat_intel():
    sample_data = {
        'indicators': [
            {
                'type': 'ip',
                'value': '192.168.1.100',
                'risk': 'HIGH',
                'source': 'security_team',
                'description': 'Known malicious actor'
            },
            {
                'type': 'domain',
                'value': 'malware.example.com',
                'risk': 'CRITICAL',
                'source': 'threat_feed',
                'description': 'C2 domain'
            }
        ],
        'last_updated': datetime.now(timezone.utc).isoformat()
    }
    
    import os
    os.makedirs("data", exist_ok=True)
    with open(THREAT_INTEL_FILE, 'w') as f:
        json.dump(sample_data, f, indent=2)
    
    print(f"Created sample threat intel at {THREAT_INTEL_FILE}")

if __name__ == "__main__":
    ti = ThreatIntel()
    
    if input("Create sample threat intel data? (y/n): ") == 'y':
        create_sample_threat_intel()
        ti = ThreatIntel()
    
    test_ip = "192.168.1.100"
    result = ti.check_ip(test_ip)
    print(f"Threat check for {test_ip}: {result}")
    
    test_ip2 = "10.0.0.1"
    result2 = ti.check_ip(test_ip2)
    print(f"Threat check for {test_ip2}: {result2}")
