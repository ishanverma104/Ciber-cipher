import os
import json

FIM_LOG_DIR = "logs"
OUTPUT_JSON = "data/parsed_fim_logs.json"

def parse_fim_logs():
    parsed_entries = []
    for fname in os.listdir(FIM_LOG_DIR):
        if fname.endswith("_fim.log"):
            full_path = os.path.join(FIM_LOG_DIR, fname)
            with open(full_path, "r") as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        parsed_entries.append(entry)
                    except json.JSONDecodeError:
                        continue

    parsed_entries.sort(key=lambda x: x["timestamp_utc"], reverse=True)

    os.makedirs("data", exist_ok=True)
    with open(OUTPUT_JSON, "w") as f:
        json.dump(parsed_entries, f, indent=2)

    print(f"Parsed {len(parsed_entries)} FIM entries.")

if __name__ == "__main__":
    parse_fim_logs()
