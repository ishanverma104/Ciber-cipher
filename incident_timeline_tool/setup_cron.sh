#!/bin/bash

# Absolute path to project directory
PROJECT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Paths
SRC_LOG="/var/log/auth.log"
DEST_LOG="$PROJECT_DIR/logs/auth.log"
PARSER_SCRIPT="$PROJECT_DIR/utils/parse_logs.py"

# Cron command: copy + parse
CRON_JOB="*/2 * * * * cp $SRC_LOG $DEST_LOG && python3 $PARSER_SCRIPT"

# Check if the cronjob already exists
crontab -l 2>/dev/null | grep -F "$PARSER_SCRIPT" >/dev/null
if [ $? -eq 0 ]; then
  echo "[✓] Cron job already exists."
else
  # Add new cron job
  (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
  echo "[+] Cron job added to run every 2 minutes."
fi

