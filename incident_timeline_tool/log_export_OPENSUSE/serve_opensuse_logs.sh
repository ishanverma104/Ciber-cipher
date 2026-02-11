# Define where to temporarily export the messages log
EXPORT_FILE="$HOME/log_export/messages.log"

# Apache's public directory (default in openSUSE)
APACHE_DIR="/srv/www/htdocs/log_export"

# Create local export dir (just for copying first)
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

echo "\E2\9C\85 messages.log is now available at: http://<OpenSUSE-VM-IP>/log_export/messages.log"

# This script is used for sending logs from openSUSE Tumbleweed systems
# to the Incident Timeline Reconstruction Tool's server for visualization.



