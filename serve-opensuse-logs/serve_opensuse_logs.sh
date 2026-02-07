#!/bin/bash
set -euo pipefail

# Define where to temporarily export the messages log
EXPORT_FILE="$HOME/log_export/messages.log"

# Apache's public directory (default in openSUSE)
APACHE_DIR="/srv/www/htdocs/log_export"

# Base zypper options: non-interactive + auto-import repo keys
ZYPPER="zypper --non-interactive --gpg-auto-import-keys"

echo "[*] Checking for apache2 installation..."
if ! rpm -q apache2 >/dev/null 2>&1; then
  echo "[*] Apache not found. Installing apache2..."
  sudo $ZYPPER install --no-recommends --auto-agree-with-licenses apache2
else
  echo "[+] Apache already installed."
fi

echo "[*] Enabling and starting apache2 service..."
sudo systemctl enable apache2
sudo systemctl restart apache2

# Create local export directory (just for copying first)
mkdir -p "$(dirname "$EXPORT_FILE")"

# Copy the log using sudo
sudo cp /var/log/messages "$EXPORT_FILE"

# Fix permissions so user can work with it
sudo chown "$USER":"$USER" "$EXPORT_FILE"
chmod +r "$EXPORT_FILE"

# Move or copy it to Apache's serving directory
sudo mkdir -p "$APACHE_DIR"
sudo cp "$EXPORT_FILE" "$APACHE_DIR/messages.log"
sudo chmod +r "$APACHE_DIR/messages.log"

# Detect local IP address for message
IP="$(hostname -I | awk '{print $1}')"

echo "\E2\9C\85 messages.log is now available at: http://$IP/log_export/messages.log"

# This script is used for sending logs from openSUSE Tumbleweed systems
# to the Incident Timeline Reconstruction Tool's server for visualization.


