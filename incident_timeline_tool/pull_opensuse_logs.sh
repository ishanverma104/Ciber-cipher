#!/bin/bash

# Define endpoint IP (replace with your openSUSE VM IP)
OPENSUSE_IP="192.168.122.105" #Change this 
REMOTE_FILE="log_export/messages.log"
DEST_FILE="logs/opensuse_messages.log"

# Create logs directory if it doesn't exist
mkdir -p logs

# Fetch the log file via Apache
curl -s "http://$OPENSUSE_IP/$REMOTE_FILE" -o "$DEST_FILE"

# Check if download succeeded
if [[ $? -eq 0 ]]; then
    echo "Log fetched and saved to $DEST_FILE"
else
    echo "Failed to fetch log from openSUSE endpoint"
    exit 1
fi

# OPTIONAL: Automatically parse the logs
# python3 utils/parse_logs.py
# This script facilitates the pulling of logs from openSUSE systems
# to the server of the Incident Timeline Reconstruction Tool.
