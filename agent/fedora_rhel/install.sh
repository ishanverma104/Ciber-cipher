#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_INSTALL_DIR="/opt/astro-siem/agent/fedora_rhel"
ENABLE_FIREWALL_CONFIG=false

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_error() { echo -e "${RED}[!]${NC} $1"; }
log_success() { echo -e "${GREEN}[+]${NC} $1"; }
log_info() { echo -e "${YELLOW}[*]${NC} $1"; }

detect_package_manager() {
    if command -v dnf &> /dev/null; then
        echo "dnf"
    elif command -v yum &> /dev/null; then
        echo "yum"
    else
        echo "none"
    fi
}

get_apache_service() {
    if [ -f /etc/fedora-release ] || command -v httpd &> /dev/null; then
        echo "httpd"
    else
        echo "httpd"
    fi
}

install_dependencies() {
    local pkg_manager
    pkg_manager=$(detect_package_manager)
    local apache_svc
    apache_svc=$(get_apache_service)
    
    if [ "$pkg_manager" = "none" ]; then
        log_error "No supported package manager found (dnf/yum)"
        exit 1
    fi
    
    log_info "Detected package manager: $pkg_manager"
    log_info "Installing Apache and dependencies..."
    
    case "$pkg_manager" in
        dnf)
            $pkg_manager install -y httpd python3
            ;;
        yum)
            $pkg_manager install -y httpd python3
            ;;
    esac
    
    systemctl enable "$apache_svc"
    systemctl start "$apache_svc"
    
    if systemctl is-active --quiet "$apache_svc"; then
        log_success "Apache installed and running"
    else
        log_error "Apache failed to start"
        exit 1
    fi
}

configure_apache() {
    local apache_svc
    apache_svc=$(get_apache_service)
    
    log_info "Configuring Apache..."
    
    if [ -d /etc/httpd/conf.d ]; then
        cat > /etc/httpd/conf.d/astro-siem.conf << 'EOF'
Alias /log_export /var/lib/astro-siem/exports

<Directory /var/lib/astro-siem/exports>
    Options Indexes FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>
EOF
    elif [ -d /etc/apache2/conf-available ]; then
        mkdir -p /etc/apache2/conf-available
        cat > /etc/apache2/conf-available/astro-siem.conf << 'EOF'
Alias /log_export /var/lib/astro-siem/exports

<Directory /var/lib/astro-siem/exports>
    Options Indexes FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>
EOF
        a2enconf astro-siem
    fi
    
    systemctl restart "$apache_svc"
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
    
    local apache_svc
    apache_svc=$(get_apache_service)
    
    cat > /etc/systemd/system/astro-siem-agent.service << EOF
[Unit]
Description=AstroSIEM Agent - Log Exporter (Fedora/RHEL)
After=network.target $apache_svc.service

[Service]
Type=oneshot
ExecStart=$AGENT_INSTALL_DIR/agent.sh
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
    
    log_info "Installing AstroSIEM Agent for Fedora/RHEL..."
    
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
