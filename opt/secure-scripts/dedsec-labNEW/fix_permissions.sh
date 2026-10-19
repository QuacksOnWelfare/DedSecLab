#!/bin/bash
set -e

BASE="/opt/secure-scripts/dedsec-labNEW"
APPUSER="dedsecuser"

echo "[+] Fixing ownership..."
chown -R "$APPUSER:$APPUSER" "$BASE"

echo "[+] Directory permissions..."
find "$BASE" -type d -exec chmod 750 {} \;

echo "[+] Python/shell scripts executable..."
find "$BASE" -type f -name "*.py" -exec chmod 750 {} \;
find "$BASE" -type f -name "*.sh" -exec chmod 750 {} \;

echo "[+] Data/config files readable+writable by app user..."
find "$BASE" -maxdepth 1 -type f \( -name "*.json" -o -name "*.txt" -o -name "*.save" \) -exec chmod 640 {} \;
find "$BASE/data" -type f -exec chmod 640 {} \;
find "$BASE/backups" -type f -exec chmod 640 {} \;

echo "[+] Logs..."
mkdir -p "$BASE/logs"
touch "$BASE/logs/ssh_security.log"
find "$BASE/logs" -type d -exec chmod 750 {} \;
find "$BASE/logs" -type f -exec chmod 640 {} \;

echo "[+] Sensitive VPN config downloads..."
find "$BASE/etc/www" -type f -name "*.ovpn" -exec chmod 600 {} \;

echo "[+] Core wrapper/menu..."
chmod 750 "$BASE/access_wrapper.py" "$BASE/menu.py"

echo "[+] OpenVPN status log readable for real-IP lookup..."
if [ -f /var/log/openvpn-status.log ]; then
    chmod 644 /var/log/openvpn-status.log
fi

echo "[+] Done."
