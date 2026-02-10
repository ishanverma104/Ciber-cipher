#!/bin/bash
# Define where to temporarily export the secure log
EXPORT_FILE="$HOME/log_export/secure.log"

# Apache's public directory (default in many distros)
APACHE_DIR="/var/www/html/log_export"

# Create local export dir (just for copying first)
mkdir -p "$(dirname "$EXPORT_FILE")"

# Copy the log using sudo
sudo cp /var/log/secure "$EXPORT_FILE"

# Fix permissions so user can work with it
sudo chown "$USER":"$USER" "$EXPORT_FILE"
chmod +r "$EXPORT_FILE"

# Move or copy it to Apache's serving directory
sudo mkdir -p "$APACHE_DIR"
sudo cp "$EXPORT_FILE" "$APACHE_DIR/secure.log"
sudo chmod +r "$APACHE_DIR/secure.log"

echo "✅ secure.log is now available at: http://<Fedora-VM-IP>/log_export/secure.log"


#This script is used for sending logs from Fedora/RHEL systems to the Incident Timeline Reconstruction Tool's Server where the logs will be visualized
