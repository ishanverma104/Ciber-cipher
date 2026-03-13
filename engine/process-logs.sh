#!/bin/bash

# Cyber-Cipher Log Processor
# =======================
# Runs all log parsers to process incoming logs

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "========================================"
echo "Cyber-Cipher Log Processor"
echo "========================================"
echo ""

# Run all parsers
echo "[*] Running parsers..."
echo ""

echo "[*] Parsing network logs..."
python3 "$SCRIPT_DIR/parsers/parse-network-logs.py"

echo ""
echo "[*] Parsing Apache logs..."
python3 "$SCRIPT_DIR/parsers/parse-apache-logs.py"

echo ""
echo "[*] Parsing Nginx logs..."
python3 "$SCRIPT_DIR/parsers/parse-nginx-logs.py"

echo ""
echo "[*] Parsing Docker logs..."
python3 "$SCRIPT_DIR/parsers/parse-docker-logs.py"

echo ""
echo "[*] Parsing Kubernetes logs..."
python3 "$SCRIPT_DIR/parsers/parse-kubernetes-logs.py"

echo ""
echo "========================================"
echo "Log Processing Complete"
echo "========================================"
