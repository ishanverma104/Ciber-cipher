#!/bin/bash

# Define endpoint IP
FEDORA_IP="192.168.122.63"
REMOTE_FILE="log_export/secure.log"
DEST_FILE="logs/fedora_secure.log"

# Create logs directory if it doesn't exist
mkdir -p logs

# Fetch the log file via Apache
curl -s "http://$FEDORA_IP/$REMOTE_FILE" -o "$DEST_FILE"

# Check if download succeeded
if [[ $? -eq 0 ]]; then
    echo "Log fetched and saved to $DEST_FILE"
else
    echo "Failed to fetch log from Fedora endpoint"
    exit 1
fi

# OPTIONAL: Automatically parse the logs
# python3 utils/parse_logs.py
# This script facilitates the pulling of logs from Fedora/RHEL systems to the server of the Incident Timeline Reconstruction Tool 
