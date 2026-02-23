#!/bin/bash
set -euo pipefail

# AstroSIEM Unified Agent Installer
# ==================================
# One-command installer for all Linux distributions

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_error() { echo -e "${RED}[!]${NC} $1"; }
print_success() { echo -e "${GREEN}[+]${NC} $1"; }
print_info() { echo -e "${YELLOW}[*]${NC} $1"; }

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    else
        echo "unknown"
    fi
}

main() {
    echo "========================================"
    echo "AstroSIEM Unified Agent Installer"
    echo "========================================"
    echo ""
    
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root"
        print_info "Please run: sudo $0"
        exit 1
    fi
    
    distro=$(detect_distro)
    print_info "Detected distribution: $distro"
    
    case "$distro" in
        fedora|rhel|centos)
            print_info "Installing Fedora/RHEL agent..."
            bash "$SCRIPT_DIR/fedora_rhel/install.sh"
            ;;
        opensuse*|suse*)
            print_info "Installing openSUSE agent..."
            bash "$SCRIPT_DIR/opensuse/install.sh"
            ;;
        debian|ubuntu)
            print_info "Installing Debian/Ubuntu agent..."
            bash "$SCRIPT_DIR/debian/install.sh"
            ;;
        arch)
            print_info "Installing Arch Linux agent..."
            bash "$SCRIPT_DIR/arch/install.sh"
            ;;
        *)
            print_error "Unknown distribution: $distro"
            echo "Supported: fedora, rhel, centos, opensuse, suse, debian, ubuntu, arch"
            exit 1
            ;;
    esac
    
    echo ""
    echo "========================================"
    print_success "Installation Complete!"
    echo "========================================"
}

main "$@"
