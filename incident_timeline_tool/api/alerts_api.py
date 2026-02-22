#!/usr/bin/env python3
from flask import Flask, jsonify, request
from db.alert_store import AlertStore
from utils.detection_engine import DetectionEngine
from utils.threat_intel import ThreatIntel

app = Flask(__name__)
alert_store = AlertStore()
threat_intel = ThreatIntel()

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    severity = request.args.get('severity')
    status = request.args.get('status')
    limit = request.args.get('limit', 100, type=int)
    
    alerts = alert_store.query_alerts(
        severity=severity,
        status=status
    )
    
    for alert in alerts[:limit]:
        if alert.get('mitre_techniques'):
            try:
                alert['mitre_techniques'] = eval(alert['mitre_techniques'])
            except:
                pass
    
    return jsonify({
        'alerts': alerts[:limit],
        'total': len(alerts)
    })

@app.route('/api/alerts/<int:alert_id>', methods=['GET'])
def get_alert(alert_id):
    alerts = alert_store.query_alerts()
    for alert in alerts:
        if alert['id'] == alert_id:
            alert = threat_intel.enrich_alert(alert)
            return jsonify(alert)
    return jsonify({'error': 'Alert not found'}), 404

@app.route('/api/alerts/<int:alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert(alert_id):
    data = request.get_json() or {}
    acknowledged_by = data.get('acknowledged_by', 'analyst')
    alert_store.update_status(alert_id, 'acknowledged', acknowledged_by)
    return jsonify({'status': 'success'})

@app.route('/api/alerts/<int:alert_id>/close', methods=['POST'])
def close_alert(alert_id):
    alert_store.update_status(alert_id, 'closed')
    return jsonify({'status': 'success'})

@app.route('/api/alerts/stats', methods=['GET'])
def get_alert_stats():
    stats = alert_store.get_alert_stats()
    alerts = alert_store.query_alerts()
    stats['total_open'] = len([a for a in alerts if a['status'] == 'open'])
    stats['total_alerts'] = len(alerts)
    return jsonify(stats)

@app.route('/api/detect', methods=['POST'])
def run_detection():
    engine = DetectionEngine(alert_store=alert_store)
    count = engine.run_detection()
    count += engine.run_brute_force_detection()
    engine.close()
    return jsonify({'alerts_generated': count})

@app.route('/api/threat-intel/check', methods=['POST'])
def check_threat():
    data = request.get_json() or {}
    ip = data.get('ip')
    domain = data.get('domain')
    
    results = {}
    if ip:
        results['ip'] = threat_intel.check_ip(ip)
    if domain:
        results['domain'] = threat_intel.check_domain(domain)
    
    return jsonify(results)

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    print(f"Starting SIEM API on port {port}")
    app.run(host='0.0.0.0', port=port, debug=True)
