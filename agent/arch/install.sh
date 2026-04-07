#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_INSTALL_DIR="/opt/astro-siem/agent/arch"
SKIP_SERVICE_INSTALL=false

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
    
    if ! command -v pacman &> /dev/null; then
        log_error "pacman not found. This script is for Arch Linux."
        exit 1
    fi
    
    local -a packages
    packages=("apache" "python")
    
    for pkg in "${packages[@]}"; do
        if pacman -Q "$pkg" &> /dev/null; then
            log_info "$pkg already installed"
        else
            pacman -S --noconfirm "$pkg"
        fi
    done
    
    local apache_svc
    apache_svc=$(get_apache_service)
    
    systemctl enable "$apache_svc"
    systemctl start "$apache_svc"
    
    if systemctl is-active --quiet "$apache_svc"; then
        log_success "Apache installed and running"
    else
        log_error "Apache failed to start"
        exit 1
    fi
}

get_apache_service() {
    if command -v httpd &> /dev/null; then
        echo "httpd"
    elif command -v apache2 &> /dev/null; then
        echo "apache2"
    else
        echo "httpd"
    fi
}

configure_apache() {
    log_info "Configuring Apache..."
    
    local apache_svc
    apache_svc=$(get_apache_service)
    
    local conf_dir="/etc/httpd/conf/extra"
    if [ -d /etc/apache2 ]; then
        conf_dir="/etc/apache2/conf/extra"
    fi
    
    mkdir -p "$conf_dir"
    
    cat > "$conf_dir/astro-siem.conf" << 'EOF'
Alias /log_export /var/lib/astro-siem/exports

<Directory /var/lib/astro-siem/exports>
    Options Indexes FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>
EOF
    
    if [ -f /etc/httpd/conf/httpd.conf ]; then
        if ! grep -q "Include conf/extra/astro-siem.conf" /etc/httpd/conf/httpd.conf; then
            echo "Include conf/extra/astro-siem.conf" >> /etc/httpd/conf/httpd.conf
        fi
    elif [ -f /etc/apache2/apache2.conf ]; then
        if ! grep -q "Include conf/extra/astro-siem.conf" /etc/apache2/apache2.conf; then
            echo "Include conf/extra/astro-siem.conf" >> /etc/apache2/apache2.conf
        fi
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
Description=AstroSIEM Agent - Log Exporter (Arch Linux)
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
    
    local distro
    distro=$(detect_distro)
    
    if [ "$distro" != "arch" ]; then
        log_error "This installer is for Arch Linux. Detected: $distro"
        exit 1
    fi
    
    log_info "Installing AstroSIEM Agent for Arch Linux..."
    
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
