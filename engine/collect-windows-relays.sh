#!/bin/bash

# Cyber-Cipher Windows Relay Collector
# ====================================
# Collects Windows event-log exports from Windows-only relay endpoints.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config/windows-agents.yaml"
CONFIG_READER="$SCRIPT_DIR/config/read_windows_config.py"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_info() {
    echo -e "${YELLOW}[*]${NC} $1"
}

print_relay() {
    echo -e "${BLUE}[Relay]${NC} $1"
}

check_dependencies() {
    if ! python3 -c "import yaml" 2>/dev/null; then
        print_error "Python PyYAML module not installed"
        echo "Install with: pip3 install pyyaml"
        exit 1
    fi

    if ! command -v curl &> /dev/null; then
        print_error "curl is not installed"
        exit 1
    fi

    if ! command -v jq &> /dev/null; then
        print_error "jq is not installed"
        exit 1
    fi
}

get_global_setting() {
    local key="$1"
    python3 -c "
import yaml
with open('$CONFIG_FILE', 'r') as f:
    config = yaml.safe_load(f)
    print(config.get('settings', {}).get('$key', ''))
"
}

get_all_relays() {
    python3 "$CONFIG_READER" --list
}

get_relay_config() {
    local relay_name="$1"
    python3 "$CONFIG_READER" "$relay_name"
}

collect_from_relay() {
    local relay_name="$1"

    print_relay "Collecting from: $relay_name"

    local relay_config
    relay_config=$(get_relay_config "$relay_name")

    local relay_ip
    relay_ip=$(echo "$relay_config" | python3 -c "import sys, json; print(json.load(sys.stdin)['ip'])")

    local description
    description=$(echo "$relay_config" | python3 -c "import sys, json; print(json.load(sys.stdin).get('description', 'No description'))")

    local protocol
    protocol=$(get_global_setting "protocol")

    local port
    port=$(get_global_setting "default_port")

    local timeout
    timeout=$(get_global_setting "timeout")

    local export_path
    export_path=$(get_global_setting "export_path")

    local incoming_dir
    incoming_dir=$(get_global_setting "incoming_dir")

    mkdir -p "$SCRIPT_DIR/$incoming_dir"

    local relay_url="$protocol://$relay_ip:$port"

    print_info "Relay IP: $relay_ip"
    print_info "Description: $description"
    print_info "URL: $relay_url/$export_path/"

    local manifest_url="$relay_url/$export_path/manifest.json"
    local manifest_file="/tmp/cyber-cipher-windows-manifest-$relay_name.json"

    print_info "Fetching manifest..."
    if ! curl -s --max-time "$timeout" "$manifest_url" -o "$manifest_file" 2>/dev/null; then
        print_error "Failed to fetch manifest from $relay_name"
        print_error "URL: $manifest_url"
        return 1
    fi

    if ! jq empty "$manifest_file" 2>/dev/null; then
        print_error "Invalid manifest JSON from $relay_name"
        rm -f "$manifest_file"
        return 1
    fi

    local sources_count
    sources_count=$(jq '.sources | length' "$manifest_file")
    print_success "Manifest received - Found $sources_count source(s)"

    jq -c '.sources[]' "$manifest_file" | while read -r source; do
        local filename
        filename=$(echo "$source" | jq -r '.filename')

        local present
        present=$(echo "$source" | jq -r '.present')

        if [ "$present" != "true" ]; then
            print_info "Skipping $filename (not present)"
            continue
        fi

        local source_url="$relay_url/$export_path/$filename"
        local local_filename="${relay_name}_${filename}"
        local dest_file="$SCRIPT_DIR/$incoming_dir/$local_filename"

        print_info "Downloading: $filename"
        if curl -s --max-time "$timeout" "$source_url" -o "$dest_file" 2>/dev/null; then
            if [ -s "$dest_file" ]; then
                local filesize
                filesize=$(du -h "$dest_file" | cut -f1)
                print_success "Downloaded: $local_filename ($filesize)"
            else
                print_error "Downloaded file is empty: $filename"
                rm -f "$dest_file"
            fi
        else
            print_error "Failed to download: $filename"
        fi
    done

    rm -f "$manifest_file"
    print_success "Collection complete for $relay_name"
    echo ""
}

main() {
    echo "========================================"
    echo "Cyber-Cipher Windows Relay Collector"
    echo "========================================"
    echo ""

    check_dependencies

    local relays_to_collect=()

    if [ $# -eq 0 ]; then
        print_info "No relay specified, collecting from all configured Windows relays..."
        while IFS= read -r relay; do
            relays_to_collect+=("$relay")
        done < <(get_all_relays)
    else
        relays_to_collect=("$@")
    fi

    if [ ${#relays_to_collect[@]} -eq 0 ]; then
        print_error "No Windows relays configured in $CONFIG_FILE"
        exit 1
    fi

    print_info "Windows relays to collect: ${relays_to_collect[*]}"
    echo ""

    local success_count=0
    local fail_count=0

    for relay in "${relays_to_collect[@]}"; do
        if collect_from_relay "$relay"; then
            ((success_count++))
        else
            ((fail_count++))
        fi
    done

    echo "========================================"
    echo "Windows Relay Collection Summary"
    echo "========================================"
    print_success "Successful: $success_count"
    if [ $fail_count -gt 0 ]; then
        print_error "Failed: $fail_count"
    fi
    echo "========================================"

    if [ $fail_count -gt 0 ]; then
        exit 1
    fi
}

main "$@"
