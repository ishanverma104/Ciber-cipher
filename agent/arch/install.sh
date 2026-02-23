#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_INSTALL_DIR="/opt/astro-siem/agent/arch"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_error() { echo -e "${RED}[!]${NC} $1"; }
print_success() { echo -e "${GREEN}[+]${NC} $1"; }
print_info() { echo -e "${YELLOW}[*]${NC} $1"; }

install_apache() {
    print_info "Installing Apache..."
    pacman -S --noconfirm apache
    systemctl enable httpd
    systemctl start httpd
    print_success "Apache installed and started"
}

configure_apache() {
    print_info "Configuring Apache..."
    
    cat > /etc/httpd/conf/extra/astro-siem.conf << 'EOF'
Alias /log_export /var/lib/astro-siem/exports

<Directory /var/lib/astro-siem/exports>
    Options Indexes FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>
EOF
    
    if ! grep -q "Include conf/extra/astro-siem.conf" /etc/httpd/conf/httpd.conf; then
        echo "Include conf/extra/astro-siem.conf" >> /etc/httpd/conf/httpd.conf
    fi
    
    systemctl restart httpd
    print_success "Apache configured"
}

install_agent_files() {
    print_info "Installing agent files..."
    
    mkdir -p "$AGENT_INSTALL_DIR"
    
    cp "$SCRIPT_DIR/agent.sh" "$AGENT_INSTALL_DIR/"
    chmod +x "$AGENT_INSTALL_DIR/agent.sh"
    
    cp "$SCRIPT_DIR/fim-agent.py" "$AGENT_INSTALL_DIR/"
    chmod +x "$AGENT_INSTALL_DIR/fim-agent.py"
    
    print_success "Agent files installed to $AGENT_INSTALL_DIR"
}

install_systemd() {
    print_info "Installing systemd service and timer..."
    
    cat > /etc/systemd/system/astro-siem-agent.service << 'EOF'
[Unit]
Description=AstroSIEM Agent - Log Exporter
After=network.target

[Service]
Type=oneshot
ExecStart=/opt/astro-siem/agent/arch/agent.sh
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
    
    print_success "Systemd service and timer installed"
}

main() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root"
        exit 1
    fi
    
    install_apache
    configure_apache
    install_agent_files
    install_systemd
    
    mkdir -p /var/lib/astro-siem/exports
    
    print_info "Running initial log export..."
    if "$AGENT_INSTALL_DIR/agent.sh"; then
        print_success "Initial export completed"
    else
        print_error "Initial export failed"
    fi
    
    systemctl start astro-siem-agent.timer
    
    ip=$(hostname -I | awk '{print $1}')
    
    echo ""
    echo "========================================"
    print_success "Installation Complete!"
    echo "========================================"
    echo "Agent URL: http://$ip/log_export/latest/"
    echo "Timer: systemctl list-timers | grep astro-siem"
}

main "$@"
