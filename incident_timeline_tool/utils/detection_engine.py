import json
import re
from datetime import datetime, timezone
from typing import List, Dict, Optional
from pathlib import Path
from db.alert_store import AlertStore

DETECTION_RULES = {
    'BRUTE-001': {
        'name': 'Brute Force Attack',
        'severity': 'HIGH',
        'description': 'Multiple failed login attempts detected',
        'pattern': r'Failed password for.*from (\d+\.\d+\.\d+\.\d+)',
        'threshold': 5,
        'timewindow': 300,
        'mitre': ['T1110']
    },
    'SSH-001': {
        'name': 'SSH Authentication Success',
        'severity': 'LOW',
        'description': 'Successful SSH login',
        'pattern': r'Accepted password for (\w+)',
        'mitre': ['T1078']
    },
    'SUDO-001': {
        'name': 'Sudo Command Execution',
        'severity': 'MEDIUM',
        'description': 'User executed command with sudo',
        'pattern': r'COMMAND=/.*',
        'mitre': ['T1548']
    },
    'ROOT-001': {
        'name': 'Root Login Detected',
        'severity': 'CRITICAL',
        'description': 'Root user login detected',
        'pattern': r'Accepted.*for root',
        'mitre': ['T1078', 'T1005']
    },
    'FAIL-001': {
        'name': 'Authentication Failure',
        'severity': 'MEDIUM',
        'description': 'Authentication failure detected',
        'pattern': r'authentication failure.*user=(\w+)',
        'mitre': ['T1110']
    },
    'CRON-001': {
        'name': 'Cron Job Execution',
        'severity': 'LOW',
        'description': 'Scheduled cron job executed',
        'pattern': r'CMD \((.*?)\)',
        'mitre': ['T1053']
    },
    'WARN-001': {
        'name': 'Warning Message',
        'severity': 'LOW',
        'description': 'System warning detected',
        'pattern': r'warning:|warn:',
        'mitre': []
    },
    'ERR-001': {
        'name': 'Error Message',
        'severity': 'MEDIUM',
        'description': 'System error detected',
        'pattern': r'error:|failed:',
        'mitre': []
    },
    'SUSP-001': {
        'name': 'Suspicious Activity',
        'severity': 'HIGH',
        'description': 'Suspicious activity pattern detected',
        'pattern': r'invalid user|unknown user',
        'mitre': ['T1110', 'T1078']
    }
}

class DetectionEngine:
    def __init__(self, log_dir: str = "logs", alert_store: AlertStore = None):
        self.log_dir = log_dir
        self.alert_store = alert_store or AlertStore()
        self.alert_store.connect()
        self.detection_counts = {}

    def scan_log_file(self, filepath: str) -> List[Dict]:
        detections = []
        with open(filepath, 'r') as f:
            for line in f:
                for rule_id, rule in DETECTION_RULES.items():
                    match = re.search(rule['pattern'], line, re.IGNORECASE)
                    if match:
                        detection = {
                            'rule_id': rule_id,
                            'timestamp': datetime.now(timezone.utc).isoformat(),
                            'severity': rule['severity'],
                            'title': rule['name'],
                            'description': rule['description'],
                            'matched_text': line.strip(),
                            'hostname': Path(filepath).stem,
                            'mitre_techniques': json.dumps(rule['mitre'])
                        }
                        if match.groups():
                            detection['source_ip'] = match.group(1)
                        detections.append(detection)
        return detections

    def run_detection(self) -> int:
        total_alerts = 0
        log_files = list(Path(self.log_dir).glob("*.log"))
        
        for log_file in log_files:
            detections = self.scan_log_file(str(log_file))
            for detection in detections:
                self.alert_store.insert_alert(detection)
                total_alerts += 1
        
        return total_alerts

    def detect_brute_force(self, log_file: str) -> List[Dict]:
        brute_force_alerts = []
        ip_attempts = {}
        
        with open(log_file, 'r') as f:
            for line in f:
                match = re.search(r'Failed password for.*from (\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    ip = match.group(1)
                    if ip not in ip_attempts:
                        ip_attempts[ip] = []
                    ip_attempts[ip].append(datetime.now(timezone.utc))
        
        for ip, attempts in ip_attempts.items():
            recent_attempts = [a for a in attempts 
                             if (datetime.now(timezone.utc) - a).total_seconds() < 300]
            if len(recent_attempts) >= 5:
                brute_force_alerts.append({
                    'rule_id': 'BRUTE-001',
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'severity': 'HIGH',
                    'title': 'Brute Force Attack Detected',
                    'description': f'{len(recent_attempts)} failed login attempts from {ip}',
                    'source_ip': ip,
                    'mitre_techniques': json.dumps(['T1110'])
                })
        
        return brute_force_alerts

    def run_brute_force_detection(self) -> int:
        total_alerts = 0
        log_files = list(Path(self.log_dir).glob("*.log"))
        
        for log_file in log_files:
            alerts = self.detect_brute_force(str(log_file))
            for alert in alerts:
                self.alert_store.insert_alert(alert)
                total_alerts += 1
        
        return total_alerts

    def close(self):
        self.alert_store.close()

if __name__ == "__main__":
    engine = DetectionEngine()
    print("Running detection on log files...")
    alerts = engine.run_detection()
    print(f"Generated {alerts} alerts")
    engine.close()
