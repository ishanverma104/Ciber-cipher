#!/usr/bin/env python3
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db.alert_store import AlertStore
from utils.detection_engine import DetectionEngine
from utils.threat_intel import ThreatIntel
import json
from datetime import datetime, timezone

def main():
    print(f"[{datetime.now(timezone.utc).isoformat()}] Starting SIEM detection run...")
    
    alert_store = AlertStore()
    alert_store.connect()
    
    engine = DetectionEngine(alert_store=alert_store)
    
    print("Running rule-based detection...")
    count = engine.run_detection()
    print(f"Generated {count} alerts from rule detection")
    
    print("Running brute force detection...")
    bf_count = engine.run_brute_force_detection()
    print(f"Generated {bf_count} alerts from brute force detection")
    
    total = count + bf_count
    print(f"Total alerts generated: {total}")
    
    stats = alert_store.get_alert_stats()
    print(f"Alert statistics: {json.dumps(stats, indent=2)}")
    
    open_alerts = alert_store.query_alerts(status='open')
    critical_high = [a for a in open_alerts if a['severity'] in ['CRITICAL', 'HIGH']]
    
    if critical_high:
        print(f"\nWARNING: {len(critical_high)} CRITICAL/HIGH alerts require attention!")
        for alert in critical_high[:5]:
            print(f"  - [{alert['severity']}] {alert['title']} from {alert.get('source_ip', 'unknown')}")
    
    engine.close()
    alert_store.close()
    
    print(f"[{datetime.now(timezone.utc).isoformat()}] Detection run complete.")
    return 0

if __name__ == "__main__":
    exit(main())
