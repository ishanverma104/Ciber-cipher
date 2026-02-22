import sqlite3
from typing import List, Dict, Optional
from datetime import datetime, timezone

DB_PATH = 'db/incident_events.db'

class AlertStore:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.conn = None
        self.cursor = None

    def connect(self):
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        self._create_table()

    def _create_table(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                hostname TEXT,
                rule_id TEXT,
                mitre_techniques TEXT,
                status TEXT DEFAULT 'open',
                acknowledged_by TEXT,
                acknowledged_at TEXT
            )
        ''')
        self.conn.commit()

    def insert_alert(self, alert: Dict):
        self.cursor.execute('''
            INSERT INTO alerts (timestamp, severity, title, description, 
                             source_ip, destination_ip, hostname, rule_id, 
                             mitre_techniques, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert.get('timestamp', datetime.now(timezone.utc).isoformat()),
            alert.get('severity', 'MEDIUM'),
            alert.get('title', ''),
            alert.get('description', ''),
            alert.get('source_ip'),
            alert.get('destination_ip'),
            alert.get('hostname'),
            alert.get('rule_id'),
            alert.get('mitre_techniques'),
            alert.get('status', 'open')
        ))
        self.conn.commit()
        return self.cursor.lastrowid

    def query_alerts(self, severity: Optional[str] = None, 
                    status: Optional[str] = None,
                    start_time: Optional[str] = None,
                    end_time: Optional[str] = None) -> List[Dict]:
        query = 'SELECT * FROM alerts'
        params = []
        conditions = []

        if severity:
            conditions.append('severity = ?')
            params.append(severity)
        if status:
            conditions.append('status = ?')
            params.append(status)
        if start_time:
            conditions.append('timestamp >= ?')
            params.append(start_time)
        if end_time:
            conditions.append('timestamp <= ?')
            params.append(end_time)

        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)
        query += ' ORDER BY timestamp DESC'

        self.cursor.execute(query, params)
        rows = self.cursor.fetchall()
        
        columns = [desc[0] for desc in self.cursor.description]
        return [dict(zip(columns, row)) for row in rows]

    def update_status(self, alert_id: int, status: str, acknowledged_by: str = None):
        ack_time = datetime.now(timezone.utc).isoformat() if acknowledged_by else None
        self.cursor.execute('''
            UPDATE alerts 
            SET status = ?, acknowledged_by = ?, acknowledged_at = ?
            WHERE id = ?
        ''', (status, acknowledged_by, ack_time, alert_id))
        self.conn.commit()

    def get_alert_stats(self) -> Dict:
        self.cursor.execute('''
            SELECT severity, status, COUNT(*) as count 
            FROM alerts 
            GROUP BY severity, status
        ''')
        rows = self.cursor.fetchall()
        stats = {'by_severity': {}, 'by_status': {}}
        for row in rows:
            severity, status, count = row
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + count
            stats['by_status'][status] = stats['by_status'].get(status, 0) + count
        return stats

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None
            self.cursor = None

if __name__ == "__main__":
    store = AlertStore()
    store.connect()
    store.insert_alert({
        'severity': 'HIGH',
        'title': 'Brute Force Attack Detected',
        'description': 'Multiple failed login attempts from 192.168.1.100',
        'source_ip': '192.168.1.100',
        'hostname': 'fedora-server',
        'rule_id': 'BRUTE-001'
    })
    alerts = store.query_alerts(severity='HIGH')
    print(f"Found {len(alerts)} high severity alerts")
    store.close()
