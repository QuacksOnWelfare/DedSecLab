#!/bin/bash

BASE="/opt/secure-scripts/dedsec-labNEW"
APPUSER="dedsecuser"

LOG_DIR="$BASE/logs"
SSH_SECURITY_LOG="$LOG_DIR/ssh_security.log"

echo "[+] Setting up SSH security logging..."

mkdir -p "$LOG_DIR"
touch "$SSH_SECURITY_LOG"

chown $APPUSER:$APPUSER "$SSH_SECURITY_LOG"
chmod 600 "$SSH_SECURITY_LOG"

echo "[+] SSH security log ready: $SSH_SECURITY_LOG"

# Fix OpenVPN status log permissions (for real IP tracking)
if [ -f /var/log/openvpn-status.log ]; then
    echo "[+] Fixing OpenVPN status log permissions..."
    chmod 644 /var/log/openvpn-status.log
fi

echo "[+] Security setup complete."
