import os
import json
import yaml
from datetime import datetime
from pathlib import Path

# Get the directory where this script is located
SCRIPT_DIR = Path(__file__).parent.resolve()
ENGINE_DIR = SCRIPT_DIR.parent

# Define absolute paths
LOG_DIR = ENGINE_DIR / "incoming-logs"
OUTPUT_FILE = ENGINE_DIR / "processed-data" / "events-security-processed.json"
MITRE_FILE = ENGINE_DIR / "processed-data" / "detection-rules-mitre-auth.json"
COMPLIANCE_FILE = ENGINE_DIR / "config" / "compliance-mapping.yaml"

# Convert to strings for compatibility
LOG_DIR = str(LOG_DIR)
OUTPUT_FILE = str(OUTPUT_FILE)
MITRE_FILE = str(MITRE_FILE)
COMPLIANCE_FILE = str(COMPLIANCE_FILE)


def load_mitre_rules():
    with open(MITRE_FILE, "r") as f:
        return json.load(f)


def load_compliance_mapping():
    """Load compliance mapping from YAML config"""
    try:
        with open(COMPLIANCE_FILE, "r") as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Warning: Could not load compliance mapping: {e}")
        return {}


def get_compliance_violations(mitre_hits, compliance_mapping):
    """Map MITRE techniques to compliance frameworks"""
    violations = set()

    for mitre_hit in mitre_hits:
        technique_id = mitre_hit.get("technique_id", "")

        # Check each compliance framework
        for framework, techniques in compliance_mapping.items():
            if technique_id in techniques:
                violations.add(framework.upper())

    return sorted(list(violations))


def match_mitre_rules(message, rules):
    matched = []
    msg_lower = message.lower()
    for rule in rules:
        for keyword in rule["keywords"]:
            if keyword.lower() in msg_lower:
                matched.append(
                    {
                        "technique_id": rule["technique_id"],
                        "technique_name": rule["technique_name"],
                        "tactic": rule["tactic"],
                        "description": rule["description"],
                    }
                )
                break
    return matched


def parse_log_line(line, hostname, mitre_rules, compliance_mapping):
    try:
        # ISO 8601 format check (Fedora secure.log)
        if line[:4].isdigit() and "T" in line:
            ts_str, rest = line.split(" ", 1)
            timestamp = datetime.fromisoformat(ts_str)
        else:
            # Normalize syslog timestamp with single-digit day
            ts_str = line[:15]
            ts_str = " ".join(ts_str.split())  # Collapse multiple spaces
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
        compliance_violations = get_compliance_violations(
            mitre_hits, compliance_mapping
        )

        return {
            "timestamp_utc": timestamp.isoformat(),
            "hostname": hostname,
            "process": process,
            "pid": pid,
            "message": message.strip(),
            "mitre": mitre_hits,
            "compliance": compliance_violations,
        }
    except Exception:
        return None


def is_windows_event_log_file(filename):
    lower_name = filename.lower()
    windows_markers = ("windows", "winlog", "eventlog", "evtx")
    return filename.endswith(".json") and any(marker in lower_name for marker in windows_markers)


def extract_windows_timestamp(event):
    candidates = [
        event.get("TimeCreated"),
        event.get("@timestamp"),
        event.get("timestamp"),
        event.get("Timestamp"),
        event.get("EventTime"),
        event.get("System", {}).get("TimeCreated", {}).get("SystemTime"),
    ]

    for value in candidates:
        if not value:
            continue
        if isinstance(value, dict):
            value = value.get("SystemTime")
        if not value:
            continue

        normalized = str(value).strip()
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"

        try:
            return datetime.fromisoformat(normalized).isoformat()
        except ValueError:
            continue

    return datetime.now().isoformat()


def extract_windows_message(event):
    message = (
        event.get("Message")
        or event.get("message")
        or event.get("RenderingInfo", {}).get("Message")
    )
    if message:
        return str(message).strip()

    event_data = event.get("EventData")
    if isinstance(event_data, dict):
        if "Data" in event_data:
            data = event_data["Data"]
            if isinstance(data, list):
                parts = []
                for item in data:
                    if isinstance(item, dict):
                        name = item.get("Name") or item.get("@Name") or "value"
                        value = item.get("value") or item.get("#text") or item.get("Value")
                        if value not in (None, ""):
                            parts.append(f"{name}={value}")
                    elif item not in (None, ""):
                        parts.append(str(item))
                if parts:
                    return "; ".join(parts)
            elif data not in (None, ""):
                return str(data).strip()

        parts = []
        for key, value in event_data.items():
            if value not in (None, "", []):
                parts.append(f"{key}={value}")
        if parts:
            return "; ".join(parts)

    event_id = (
        event.get("EventID")
        or event.get("Id")
        or event.get("System", {}).get("EventID")
        or "unknown"
    )
    channel = (
        event.get("LogName")
        or event.get("Channel")
        or event.get("System", {}).get("Channel")
        or "Windows"
    )
    return f"Windows Event ID {event_id} on {channel}"


def normalize_windows_event(event, hostname, mitre_rules, compliance_mapping):
    if not isinstance(event, dict):
        return None

    resolved_hostname = (
        event.get("MachineName")
        or event.get("Computer")
        or event.get("Hostname")
        or event.get("System", {}).get("Computer")
        or hostname
    )
    process = (
        event.get("ProviderName")
        or event.get("SourceName")
        or event.get("LogName")
        or event.get("Channel")
        or event.get("System", {}).get("Provider", {}).get("Name")
        or "Windows Event Log"
    )
    pid = (
        event.get("ProcessId")
        or event.get("Execution", {}).get("ProcessID")
        or event.get("System", {}).get("Execution", {}).get("ProcessID")
        or ""
    )
    message = extract_windows_message(event)
    mitre_hits = match_mitre_rules(message, mitre_rules)
    compliance_violations = get_compliance_violations(mitre_hits, compliance_mapping)

    return {
        "timestamp_utc": extract_windows_timestamp(event),
        "hostname": resolved_hostname,
        "process": process,
        "pid": str(pid),
        "message": message,
        "mitre": mitre_hits,
        "compliance": compliance_violations,
        "event_id": event.get("EventID")
        or event.get("Id")
        or event.get("System", {}).get("EventID", ""),
        "channel": event.get("LogName")
        or event.get("Channel")
        or event.get("System", {}).get("Channel", ""),
    }


def parse_windows_event_file(full_path, hostname, mitre_rules, compliance_mapping):
    entries = []

    with open(full_path, "r") as f:
        content = f.read().strip()

    if not content:
        return entries

    payload = None
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        payload = None

    if isinstance(payload, list):
        iterable = payload
    elif isinstance(payload, dict):
        if isinstance(payload.get("events"), list):
            iterable = payload["events"]
        else:
            iterable = [payload]
    else:
        iterable = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                iterable.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    for event in iterable:
        entry = normalize_windows_event(
            event, hostname, mitre_rules, compliance_mapping
        )
        if entry:
            entries.append(entry)

    return entries


def main():
    parsed_logs = []
    mitre_rules = load_mitre_rules()
    compliance_mapping = load_compliance_mapping()

    for filename in os.listdir(LOG_DIR):
        if filename.endswith(".log") or filename.endswith(".json"):
            full_path = os.path.join(LOG_DIR, filename)
            # Extract agent name from filename (everything before first underscore)
            # e.g., "debian-vm_auth.log" -> "debian-vm"
            stem = Path(filename).stem
            hostname = stem.split("_")[0] if "_" in stem else stem

            if is_windows_event_log_file(filename):
                parsed_logs.extend(
                    parse_windows_event_file(
                        full_path, hostname, mitre_rules, compliance_mapping
                    )
                )
                continue

            with open(full_path, "r") as f:
                for line in f:
                    entry = parse_log_line(
                        line, hostname, mitre_rules, compliance_mapping
                    )
                    if entry:
                        parsed_logs.append(entry)

    parsed_logs.sort(key=lambda x: x["timestamp_utc"], reverse=True)

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(parsed_logs, f, indent=2)

    print(f"Parsed {len(parsed_logs)} lines from logs.")


if __name__ == "__main__":
    main()
