#!/bin/bash
set -euo pipefail

STATE_DIR="/var/lib/astro-siem"
EXPORT_BASE_DIR="$STATE_DIR/exports"
LAST_RUN_FILE="$STATE_DIR/last_export"

export_syslog() {
    local output_dir="$1"
    local count=0
    
    echo "[*] Checking syslog files..."
    
    for logfile in /var/log/messages /var/log/authlog; do
        if [ -f "$logfile" ] && [ -r "$logfile" ]; then
            basename=$(basename "$logfile")
            if cp "$logfile" "$output_dir/$basename" 2>/dev/null; then
                chmod 644 "$output_dir/$basename"
                echo "[+] Exported $logfile"
                count=$((count + 1))
            fi
        fi
    done
    
    if [ $count -eq 0 ]; then
        echo "[!] No syslog files found"
    fi
}

export_fim() {
    local output_dir="$1"
    
    echo "[*] Running FIM scan..."
    
    local fim_script="/opt/astro-siem/agent/opensuse/fim-agent.py"
    
    if [ -f "$fim_script" ]; then
        if python3 "$fim_script" > /dev/null 2>&1; then
            local fim_log="/var/lib/astro-siem/fim-changes.log"
            if [ -f "$fim_log" ] && [ -s "$fim_log" ]; then
                cp "$fim_log" "$output_dir/fim.json"
                chmod 644 "$output_dir/fim.json"
                echo "[+] Exported FIM changes"
                : > "$fim_log"
            else
                echo "[*] No FIM changes"
            fi
        fi
    fi
}

export_manifest() {
    local output_dir="$1"
    local timestamp="$2"
    
    echo "[*] Generating manifest..."
    
    sources="["
    first=true
    
    for f in messages authlog fim.json; do
        if [ -f "$output_dir/$f" ]; then
            if [ "$first" = true ]; then
                first=false
            else
                sources="${sources},"
            fi
            sources="${sources}{\"filename\":\"$f\",\"present\":true}"
        fi
    done
    sources="${sources}]"
    
    cat > "$output_dir/manifest.json" << EOFMANIFEST
{
    "export_timestamp": "$timestamp",
    "distro": "opensuse",
    "sources": $sources
}
EOFMANIFEST
    echo "[+] Manifest generated"
}

main() {
    echo "======================================"
    echo "AstroSIEM Agent - openSUSE"
    echo "======================================"
    
    mkdir -p "$STATE_DIR"
    
    timestamp=$(date -Iseconds)
    timestamp_dir=$(date +%Y%m%d_%H%M%S)
    export_dir="$EXPORT_BASE_DIR/$timestamp_dir"
    
    mkdir -p "$export_dir"
    echo "[*] Export directory: $export_dir"
    
    export_syslog "$export_dir"
    export_fim "$export_dir"
    export_manifest "$export_dir" "$timestamp"
    
    echo "$timestamp" > "$LAST_RUN_FILE"
    
    web_export_dir="/srv/www/htdocs/log_export"
    mkdir -p "$web_export_dir"
    ln -sfn "$export_dir" "$EXPORT_BASE_DIR/latest"
    ln -sfn "$EXPORT_BASE_DIR/latest" "$web_export_dir/latest"
    echo "[+] Updated export symlinks"
    
    chmod -R 644 "$export_dir"/* 2>/dev/null || true
    chmod 755 "$export_dir"
    
    ip=$(hostname -I | awk '{print $1}')
    
    echo ""
    echo "======================================"
    echo "Export Complete!"
    echo "======================================"
    echo "Agent URL: http://$ip/log_export/latest/"
    ls -la "$export_dir/"
}

main "$@"
