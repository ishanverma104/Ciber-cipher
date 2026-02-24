#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_INSTALL_DIR="/opt/astro-siem/agent/opensuse"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_error() { echo -e "${RED}[!]${NC} $1"; }
log_success() { echo -e "${GREEN}[+]${NC} $1"; }
log_info() { echo -e "${YELLOW}[*]${NC} $1"; }

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "${ID:-unknown}"
    else
        echo "unknown"
    fi
}

install_dependencies() {
    local distro
    distro=$(detect_distro)
    
    log_info "Detected: $distro"
    log_info "Installing Apache and dependencies..."
    
    if ! command -v zypper &> /dev/null; then
        log_error "zypper not found. This script is for openSUSE."
        exit 1
    fi
    
    zypper --non-interactive --gpg-auto-import-keys install --no-recommends --auto-agree-with-licenses apache2 python3
    
    systemctl enable apache2
    systemctl start apache2
    
    if systemctl is-active --quiet apache2; then
        log_success "Apache installed and running"
    else
        log_error "Apache failed to start"
        exit 1
    fi
}

configure_apache() {
    log_info "Configuring Apache..."
    
    local apache_conf_dir="/etc/apache2/conf.d"
    if [ -d /etc/apache2/conf-available ]; then
        apache_conf_dir="/etc/apache2/conf-available"
    fi
    
    cat > "$apache_conf_dir/astro-siem.conf" << 'EOF'
Alias /log_export /var/lib/astro-siem/exports

<Directory /var/lib/astro-siem/exports>
    Options Indexes FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>
EOF
    
    if [ -d /etc/apache2/conf-enabled ]; then
        ln -sf "$apache_conf_dir/astro-siem.conf" /etc/apache2/conf-enabled/astro-siem.conf 2>/dev/null || true
    fi
    
    systemctl restart apache2
    log_success "Apache configured"
}

install_agent_files() {
    log_info "Installing agent files..."
    
    mkdir -p "$AGENT_INSTALL_DIR"
    
    cp "$SCRIPT_DIR/agent.sh" "$AGENT_INSTALL_DIR/"
    chmod +x "$AGENT_INSTALL_DIR/agent.sh"
    
    cp "$SCRIPT_DIR/fim-agent.py" "$AGENT_INSTALL_DIR/"
    chmod +x "$AGENT_INSTALL_DIR/fim-agent.py"
    
    log_success "Agent files installed to $AGENT_INSTALL_DIR"
}

install_systemd() {
    log_info "Installing systemd service and timer..."
    
    cat > /etc/systemd/system/astro-siem-agent.service << 'EOF'
[Unit]
Description=AstroSIEM Agent - Log Exporter (openSUSE)
After=network.target apache2.service

[Service]
Type=oneshot
ExecStart=/opt/astro-siem/agent/opensuse/agent.sh
User=root
StandardOutput=journal
StandardError=journal
EOF

    cat > /etc/systemd/system/astro-siem-agent.timer << 'EOF'
[Unit]
Description=AstroSIEM Agent - Daily log export
Requires=astro-siem-agent.service

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
EOF
    
    systemctl daemon-reload
    systemctl enable astro-siem-agent.timer
    
    log_success "Systemd service and timer installed"
}

main() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        exit 1
    fi
    
    local distro
    distro=$(detect_distro)
    
    if [[ ! "$distro" =~ ^opensuse* ]]; then
        log_error "This installer is for openSUSE. Detected: $distro"
        exit 1
    fi
    
    log_info "Installing AstroSIEM Agent for openSUSE..."
    
    install_dependencies
    configure_apache
    install_agent_files
    install_systemd
    
    mkdir -p /var/lib/astro-siem/exports
    
    log_info "Running initial log export..."
    if "$AGENT_INSTALL_DIR/agent.sh"; then
        log_success "Initial export completed"
    else
        log_error "Initial export failed"
    fi
    
    systemctl start astro-siem-agent.timer
    
    local ip
    ip=$(hostname -I | awk '{print $1}')
    
    echo ""
    echo "========================================"
    log_success "Installation Complete!"
    echo "========================================"
    echo "Agent URL: http://$ip/log_export/latest/"
    echo "Timer: systemctl list-timers | grep astro-siem"
    echo "Manual run: systemctl start astro-siem-agent"
}

main "$@"
