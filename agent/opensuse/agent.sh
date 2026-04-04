#!/bin/bash
set -euo pipefail

STATE_DIR="/var/lib/astro-siem"
EXPORT_BASE_DIR="$STATE_DIR/exports"
LAST_RUN_FILE="$STATE_DIR/last_export"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${YELLOW}[*]${NC} $1"; }
log_success() { echo -e "${GREEN}[+]${NC} $1"; }
log_error() { echo -e "${RED}[!]${NC} $1"; }

check_commands() {
    log_info "Checking required commands..."
    
    if ! command -v python3 &> /dev/null; then
        log_error "python3 not found. Install with: zypper install python3"
        return 1
    fi
    
    if ! command -v apache2 &> /dev/null; then
        log_error "Apache not installed. Run install.sh first."
        return 1
    fi
    
    log_success "All required commands available"
    return 0
}

get_apache_webroot() {
    if [ -d /srv/www/htdocs ]; then
        echo "/srv/www/htdocs"
    elif [ -d /var/www/html ]; then
        echo "/var/www/html"
    else
        echo "/var/www/html"
    fi
}

export_syslog() {
    local output_dir="$1"
    local count=0
    
    log_info "Checking syslog files..."
    
    local -a log_files
    log_files=()
    
    if [ -f /var/log/messages ] && [ -r /var/log/messages ]; then
        log_files+=("/var/log/messages")
    fi
    
    if [ -f /var/log/secure ] && [ -r /var/log/secure ]; then
        log_files+=("/var/log/secure")
    fi
    
    if [ -f /var/log/authlog ] && [ -r /var/log/authlog ]; then
        log_files+=("/var/log/authlog")
    fi
    
    if [ ${#log_files[@]} -eq 0 ]; then
        if command -v journalctl &> /dev/null; then
            log_info "Using systemd-journal instead of traditional syslog"
        else
            log_error "No syslog files found"
        fi
        return 0
    fi

    for logfile in "${log_files[@]}"; do
        basename=$(basename "$logfile")
        if cp "$logfile" "$output_dir/$basename" 2>/dev/null; then
            chmod 644 "$output_dir/$basename"
            log_success "Exported $logfile"
            count=$((count + 1))
        else
            log_error "Failed to export $logfile"
        fi
    done

    if [ $count -eq 0 ]; then
        log_error "No syslog files could be exported"
    fi
}

export_fim() {
    local output_dir="$1"
    
    log_info "Running FIM scan..."
    
    local fim_script="/opt/astro-siem/agent/opensuse/fim-agent.py"
    local fim_log="/var/lib/astro-siem/fim-changes.log"
    
    if [ ! -f "$fim_script" ]; then
        log_info "FIM script not found at $fim_script"
        return 0
    fi
    
    if python3 "$fim_script" > /dev/null 2>&1; then
        if [ -f "$fim_log" ] && [ -s "$fim_log" ]; then
            cp "$fim_log" "$output_dir/fim.json"
            chmod 644 "$output_dir/fim.json"
            log_success "Exported FIM changes"
            : > "$fim_log"
        else
            log_info "No FIM changes detected"
        fi
    else
        log_error "FIM scan failed"
    fi
}

export_manifest() {
    local output_dir="$1"
    local timestamp="$2"
    
    log_info "Generating manifest..."
    
    sources="["
    first=true
    
    for f in messages secure authlog fim.json; do
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
    log_success "Manifest generated"
}

main() {
    echo "======================================"
    echo "AstroSIEM Agent - openSUSE"
    echo "======================================"
    
    if ! check_commands; then
        exit 1
    fi
    
    mkdir -p "$STATE_DIR"
    
    timestamp=$(date -Iseconds)
    timestamp_dir=$(date +%Y%m%d_%H%M%S)
    export_dir="$EXPORT_BASE_DIR/$timestamp_dir"
    
    mkdir -p "$export_dir"
    log_info "Export directory: $export_dir"
    
    export_syslog "$export_dir"
    export_fim "$export_dir"
    export_manifest "$export_dir" "$timestamp"
    
    echo "$timestamp" > "$LAST_RUN_FILE"
    
    local web_export_dir
    web_export_dir="$(get_apache_webroot)/log_export"
    mkdir -p "$web_export_dir"
    ln -sfn "$export_dir" "$EXPORT_BASE_DIR/latest"
    ln -sfn "$EXPORT_BASE_DIR/latest" "$web_export_dir/latest"
    log_success "Updated export symlinks"
    
    chmod -R 644 "$export_dir"/* 2>/dev/null || true
    chmod 755 "$export_dir"
    
    local ip
    ip=$(hostname -I | awk '{print $1}')
    
    echo ""
    echo "======================================"
    echo "Export Complete!"
    echo "======================================"
    echo "Agent URL: http://$ip/log_export/latest/"
    ls -la "$export_dir/"
}

main "$@"
