import os
import json
from datetime import datetime
from pathlib import Path

LOG_DIR = "logs"
OUTPUT_FILE = "data/parsed_logs.json"
MITRE_FILE = "data/mitre_auth_rules.json"

def load_mitre_rules():
    with open(MITRE_FILE, "r") as f:
        return json.load(f)

def match_mitre_rules(message, rules):
    matched = []
    msg_lower = message.lower()
    for rule in rules:
        for keyword in rule["keywords"]:
            if keyword.lower() in msg_lower:
                matched.append({
                    "technique_id": rule["technique_id"],
                    "technique_name": rule["technique_name"],
                    "tactic": rule["tactic"],
                    "description": rule["description"]
                })
                break
    return matched

def parse_log_line(line, hostname, mitre_rules):
    try:
        # ISO 8601 format check (Fedora secure.log)
        if line[:4].isdigit() and 'T' in line:
            ts_str, rest = line.split(' ', 1)
            timestamp = datetime.fromisoformat(ts_str)
        else:
            # Normalize syslog timestamp with single-digit day
            ts_str = line[:15]
            ts_str = ' '.join(ts_str.split())  # Collapse multiple spaces
            timestamp = datetime.strptime(ts_str, "%b %d %H:%M:%S")
            timestamp = timestamp.replace(year=datetime.now().year)
            rest = line[16:]

        parts = rest.split(": ", 1)
        meta = parts[0]
        message = parts[1] if len(parts) > 1 else ""

        if "[" in meta and "]" in meta:
            process, pid = meta.split("[", 1)
            pid = pid.strip("]")
        else:
            process = meta.strip()
            pid = ""

        mitre_hits = match_mitre_rules(message, mitre_rules)

        return {
            "timestamp_utc": timestamp.isoformat(),
            "hostname": hostname,
            "process": process,
            "pid": pid,
            "message": message.strip(),
            "mitre": mitre_hits
        }
    except Exception:
        return None

def main():
    parsed_logs = []
    mitre_rules = load_mitre_rules()

    for filename in os.listdir(LOG_DIR):
        if filename.endswith(".log"):
            full_path = os.path.join(LOG_DIR, filename)
            hostname = Path(filename).stem
            with open(full_path, "r") as f:
                for line in f:
                    entry = parse_log_line(line, hostname, mitre_rules)
                    if entry:
                        parsed_logs.append(entry)

    parsed_logs.sort(key=lambda x: x["timestamp_utc"], reverse=True)

    os.makedirs("data", exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(parsed_logs, f, indent=2)

    print(f"Parsed {len(parsed_logs)} lines from logs.")

if __name__ == "__main__":
    main()

