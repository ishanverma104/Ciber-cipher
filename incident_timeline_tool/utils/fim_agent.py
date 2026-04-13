import os
import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone

# Directories to monitor
WATCHED_DIRS = ["/etc", "/var/www", "/home"]
BASELINE_FILE = "fim_baseline.json"
CHANGE_LOG = "logs/ubuntu_fim.log"  # write to logs dir

def compute_hash(file_path):
    try:
        with open(file_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None

def get_file_metadata(path):
    try:
        stat = os.stat(path)
        return {
            "hash": compute_hash(path),
            "size": stat.st_size,
            "mtime": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
            "mode": oct(stat.st_mode & 0o777),
            "owner": f"{stat.st_uid}:{stat.st_gid}"
        }
    except Exception:
        return None

def scan_all_files():
    file_info = {}
    for root_dir in WATCHED_DIRS:
        for root, _, files in os.walk(root_dir):
            for file in files:
                full_path = os.path.join(root, file)
                meta = get_file_metadata(full_path)
                if meta:
                    file_info[full_path] = meta
    return file_info

def load_baseline():
    if os.path.exists(BASELINE_FILE):
        with open(BASELINE_FILE, "r") as f:
            return json.load(f)
    return {}

def save_baseline(baseline):
    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=2)

def write_log(change_type, path, old, new):
    entry = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "hostname": os.uname().nodename,
        "path": path,
        "change": change_type,
        "old": old,
        "new": new
    }
    os.makedirs("logs", exist_ok=True)
    with open(CHANGE_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")

def main():
    old_state = load_baseline()
    new_state = scan_all_files()

    old_paths = set(old_state.keys())
    new_paths = set(new_state.keys())

    for path in old_paths - new_paths:
        write_log("deleted", path, old_state[path], None)

    for path in new_paths - old_paths:
        write_log("created", path, None, new_state[path])

    for path in old_paths & new_paths:
        if old_state[path] != new_state[path]:
            write_log("modified", path, old_state[path], new_state[path])

    save_baseline(new_state)

if __name__ == "__main__":
    main()
