#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKIP_DEPENDENCY_CHECK=false

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
    elif [ -f /etc/arch-release ]; then
        echo "arch"
    elif [ -f /etc/fedora-release ]; then
        echo "fedora"
    elif [ -f /etc/redhat-release ]; then
        echo "rhel"
    elif [ -f /etc/debian_version ]; then
        echo "debian"
    else
        echo "unknown"
    fi
}

check_installer_exists() {
    local distro="$1"
    local installer="$SCRIPT_DIR/$distro/install.sh"
    
    if [ ! -f "$installer" ]; then
        log_error "Installer not found for $distro at $installer"
        return 1
    fi
    
    if [ ! -x "$installer" ]; then
        chmod +x "$installer"
    fi
    
    return 0
}

main() {
    echo "========================================"
    echo "AstroSIEM Unified Agent Installer"
    echo "========================================"
    echo ""
    
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        log_info "Please run: sudo $0"
        exit 1
    fi
    
    local distro
    distro=$(detect_distro)
    
    log_info "Detected distribution: $distro"
    
    case "$distro" in
        fedora|rhel|centos)
            log_info "Installing Fedora/RHEL agent..."
            if check_installer_exists "fedora_rhel"; then
                bash "$SCRIPT_DIR/fedora_rhel/install.sh"
            else
                log_error "Fedora/RHEL installer not found"
                exit 1
            fi
            ;;
        opensuse*|suse*)
            log_info "Installing openSUSE agent..."
            if check_installer_exists "opensuse"; then
                bash "$SCRIPT_DIR/opensuse/install.sh"
            else
                log_error "openSUSE installer not found"
                exit 1
            fi
            ;;
        debian|ubuntu)
            log_info "Installing Debian/Ubuntu agent..."
            if check_installer_exists "debian"; then
                bash "$SCRIPT_DIR/debian/install.sh"
            else
                log_error "Debian installer not found"
                exit 1
            fi
            ;;
        arch)
            log_info "Installing Arch Linux agent..."
            if check_installer_exists "arch"; then
                bash "$SCRIPT_DIR/arch/install.sh"
            else
                log_error "Arch installer not found"
                exit 1
            fi
            ;;
        *)
            log_error "Unknown or unsupported distribution: $distro"
            echo ""
            echo "Supported distributions:"
            echo "  - Fedora/RHEL/CentOS (fedora, rhel, centos)"
            echo "  - openSUSE (opensuse, suse)"
            echo "  - Debian/Ubuntu (debian, ubuntu)"
            echo "  - Arch Linux (arch)"
            echo ""
            echo "Alternatively, run the distro-specific installer directly:"
            echo "  sudo ./agent/fedora_rhel/install.sh"
            echo "  sudo ./agent/opensuse/install.sh"
            echo "  sudo ./agent/debian/install.sh"
            echo "  sudo ./agent/arch/install.sh"
            exit 1
            ;;
    esac
    
    echo ""
    echo "========================================"
    log_success "All Done!"
    echo "========================================"
}

main "$@"
