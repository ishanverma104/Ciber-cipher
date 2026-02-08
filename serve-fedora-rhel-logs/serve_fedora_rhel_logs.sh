set -euo pipefail

# Define where to temporarily export the secure log
EXPORT_FILE="$HOME/log_export/secure.log"

# Apache's public directory (default on Fedora/RHEL)
APACHE_DIR="/var/www/html/log_export"

echo "[*] Checking for httpd installation..."
if ! rpm -q httpd > /dev/null 2>&1; then
  echo "[*] httpd not found. Installing..."
  sudo dnf -y install httpd
else
  echo "[+] httpd already installed."
fi

echo "[*] Enabling and starting httpd service..."
sudo systemctl enable httpd
sudo systemctl restart httpd

# Create local export directory (for copying)
mkdir -p "$(dirname "$EXPORT_FILE")"

# Copy the secure log using sudo
sudo cp /var/log/secure "$EXPORT_FILE"

# Fix permissions so user can work with it
sudo chown "$USER":"$USER" "$EXPORT_FILE"
chmod +r "$EXPORT_FILE"

# Move or copy it to Apache's serving directory
sudo mkdir -p "$APACHE_DIR"
sudo cp "$EXPORT_FILE" "$APACHE_DIR/secure.log"
sudo chmod +r "$APACHE_DIR/secure.log"

# Detect local IP address for message
IP="$(hostname -I | awk '{print $1}')"

echo -e "\u2705 secure.log is now available at: http://$IP/log_export/secure.log"

# This script is used for sending logs from Fedora/RHEL systems
# to the Incident Timeline Reconstruction Tool's Server where the logs will be visualized


