#!/usr/bin/env python3
"""
Configuration reader for Cyber-Cipher Windows relay settings.

Usage:
  read_windows_config.py <relay_name>           - Get full config as JSON
  read_windows_config.py <relay_name> <key>     - Get specific value
  read_windows_config.py --list                 - List all relay names
"""

import json
import sys
from pathlib import Path

import yaml

SCRIPT_DIR = Path(__file__).parent.resolve()
CONFIG_FILE = SCRIPT_DIR / "windows-agents.yaml"


def load_config():
    try:
        with open(CONFIG_FILE, "r") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Error: Config file not found at {CONFIG_FILE}", file=sys.stderr)
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error: Invalid YAML format: {e}", file=sys.stderr)
        sys.exit(1)


def get_relay_config(relay_name):
    config = load_config()
    relays = config.get("relays", {})

    if relay_name not in relays:
        print(
            f"Error: Relay '{relay_name}' not found in configuration",
            file=sys.stderr,
        )
        print(f"Available relays: {', '.join(relays.keys())}", file=sys.stderr)
        sys.exit(1)

    relay_config = relays[relay_name].copy()
    settings = config.get("settings", {})
    relay_config["protocol"] = settings.get("protocol", "http")
    relay_config["default_port"] = settings.get("default_port", 8091)
    relay_config["timeout"] = settings.get("timeout", 30)
    relay_config["incoming_dir"] = settings.get("incoming_dir", "incoming-logs")
    relay_config["export_path"] = settings.get("export_path", "cc-winrelay/latest")
    return relay_config


def get_all_relays():
    config = load_config()
    return list(config.get("relays", {}).keys())


def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        sys.exit(1)

    if sys.argv[1] == "--list":
        print("\n".join(get_all_relays()))
        sys.exit(0)

    if sys.argv[1] in ["--help", "-h"]:
        print(__doc__)
        sys.exit(0)

    relay_name = sys.argv[1]
    relay_config = get_relay_config(relay_name)

    if len(sys.argv) >= 3:
        key = sys.argv[2]
        if key in relay_config:
            print(relay_config[key])
        else:
            print(
                f"Error: Key '{key}' not found for relay '{relay_name}'",
                file=sys.stderr,
            )
            print(
                f"Available keys: {', '.join(relay_config.keys())}",
                file=sys.stderr,
            )
            sys.exit(1)
    else:
        print(json.dumps(relay_config, indent=2))


if __name__ == "__main__":
    main()
