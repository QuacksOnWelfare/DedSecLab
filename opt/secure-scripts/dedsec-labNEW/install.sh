#!/usr/bin/env bash
set -euo pipefail

BASE="/opt/secure-scripts/dedsec-labNEW"
LAB_USER="dedsecuser"
VENV="$BASE/venv"

echo "[+] Updating system..."
apt update

echo "[+] Installing required packages..."
apt install -y \
  python3 python3-pip python3-venv python3-full python3-scapy \
  curl wget git nano unzip zip tar jq \
  whois geoip-bin dnsutils net-tools iproute2 \
  tcpdump tshark nmap nikto traceroute iputils-ping \
  ufw iptables \
  openssh-server sudo cron rsyslog \
  openvpn easy-rsa

echo "[+] Setting up Python virtual environment..."
if [ ! -d "$VENV" ]; then
  python3 -m venv "$VENV"
fi

echo "[+] Installing Python requirements into venv..."
"$VENV/bin/python" -m pip install --upgrade pip
"$VENV/bin/pip" install -r "$BASE/requirements.txt"

echo "[+] Ensuring user exists..."
if ! id "$LAB_USER" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$LAB_USER"
fi

echo "[+] Ensuring external system folders exist..."
mkdir -p /var/log/ddos-watch

echo "[+] Setting ownership..."
chown -R "$LAB_USER:$LAB_USER" "$BASE"
chown -R root:root "$BASE/root_owner" 2>/dev/null || true

echo "[+] Setting permissions..."
chmod -R 750 "$BASE"
chmod -R 700 "$BASE/root_owner" 2>/dev/null || true

echo "[+] Fixing writable lab data/log paths for dedsecuser..."
mkdir -p "$BASE/logs" "$BASE/data"

chown -R "$LAB_USER:$LAB_USER" "$BASE/logs" "$BASE/data" 2>/dev/null || true
chown "$LAB_USER:$LAB_USER" \
  "$BASE/tickets.json" \
  "$BASE/user_sessions.json" \
  "$BASE/user_themes.json" \
  "$BASE/general_chat.json" \
  "$BASE/ssh_connections.json" 2>/dev/null || true

chmod -R 770 "$BASE/logs" "$BASE/data" 2>/dev/null || true
chmod 660 \
  "$BASE/tickets.json" \
  "$BASE/user_sessions.json" \
  "$BASE/user_themes.json" \
  "$BASE/general_chat.json" \
  "$BASE/ssh_connections.json" 2>/dev/null || true

chmod 700 "$BASE/access_wrapper.py" 2>/dev/null || true
chmod 700 "$BASE/menu.py" 2>/dev/null || true
chmod 700 "$BASE/root_owner/root_owner_wrapper.py" 2>/dev/null || true
chmod 700 "$BASE/root_owner/root_owner_menu.py" 2>/dev/null || true

find "$BASE/scripts" -type f -name "*.py" -exec chmod 750 {} \; 2>/dev/null || true
find "$BASE/root_owner/misc_tools" -type f -exec chmod 700 {} \; 2>/dev/null || true

echo "[+] Giving dedsecuser limited tool permissions..."
usermod -aG sudo "$LAB_USER"

cat >/etc/sudoers.d/dedsec-lab <<EOF
# DEDSEC lab controlled sudo permissions

$LAB_USER ALL=(root) NOPASSWD: $VENV/bin/python $BASE/menu.py
$LAB_USER ALL=(root) NOPASSWD: $VENV/bin/python $BASE/access_wrapper.py
$LAB_USER ALL=(root) NOPASSWD: $VENV/bin/python $BASE/scripts/*
$LAB_USER ALL=(root) NOPASSWD: $VENV/bin/python $BASE/scripts/*/*
$LAB_USER ALL=(root) NOPASSWD: $VENV/bin/python $BASE/scripts/*/*/*

$LAB_USER ALL=(root) NOPASSWD: /usr/bin/python3 $BASE/menu.py
$LAB_USER ALL=(root) NOPASSWD: /usr/bin/python3 $BASE/access_wrapper.py
$LAB_USER ALL=(root) NOPASSWD: /usr/bin/python3 $BASE/scripts/*
$LAB_USER ALL=(root) NOPASSWD: /usr/bin/python3 $BASE/scripts/*/*
$LAB_USER ALL=(root) NOPASSWD: /usr/bin/python3 $BASE/scripts/*/*/*

$LAB_USER ALL=(root) NOPASSWD: /bin/bash $BASE/scripts/*
$LAB_USER ALL=(root) NOPASSWD: /bin/bash $BASE/scripts/*/*
$LAB_USER ALL=(root) NOPASSWD: /bin/bash $BASE/scripts/*/*/*

# Network / traffic tools
$LAB_USER ALL=(root) NOPASSWD: /usr/bin/tcpdump
$LAB_USER ALL=(root) NOPASSWD: /usr/bin/tshark
$LAB_USER ALL=(root) NOPASSWD: /usr/bin/nmap
$LAB_USER ALL=(root) NOPASSWD: /usr/bin/nikto
$LAB_USER ALL=(root) NOPASSWD: /usr/bin/ping
$LAB_USER ALL=(root) NOPASSWD: /usr/bin/traceroute
$LAB_USER ALL=(root) NOPASSWD: /usr/bin/curl
$LAB_USER ALL=(root) NOPASSWD: /usr/bin/wget
$LAB_USER ALL=(root) NOPASSWD: /usr/bin/whois
$LAB_USER ALL=(root) NOPASSWD: /usr/bin/geoiplookup
$LAB_USER ALL=(root) NOPASSWD: /usr/bin/dig
$LAB_USER ALL=(root) NOPASSWD: /usr/bin/nslookup
$LAB_USER ALL=(root) NOPASSWD: /usr/bin/ss
$LAB_USER ALL=(root) NOPASSWD: /usr/sbin/ss
$LAB_USER ALL=(root) NOPASSWD: /usr/sbin/iptables
$LAB_USER ALL=(root) NOPASSWD: /usr/sbin/ufw

# OpenVPN service controls
$LAB_USER ALL=(root) NOPASSWD: /usr/bin/systemctl status openvpn-server@server
$LAB_USER ALL=(root) NOPASSWD: /usr/bin/systemctl restart openvpn-server@server
$LAB_USER ALL=(root) NOPASSWD: /usr/bin/systemctl is-active openvpn-server@server
$LAB_USER ALL=(root) NOPASSWD: /usr/bin/journalctl -u openvpn-server@server *
EOF

chmod 440 /etc/sudoers.d/dedsec-lab
visudo -cf /etc/sudoers.d/dedsec-lab

echo "[+] Enabling SSH..."
systemctl enable ssh
sshd -t
systemctl restart ssh

echo "[+] Enabling IP forwarding..."
sed -i 's/^#\?net.ipv4.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sysctl -p || true

echo "[+] Setting log permissions..."
touch /var/log/ddos-watch/latest_summary.json 2>/dev/null || true
chown -R root:root /var/log/ddos-watch
chmod -R 755 /var/log/ddos-watch

echo "[+] Checking Python files..."
"$VENV/bin/python" -m py_compile "$BASE/access_wrapper.py" 2>/dev/null || true
"$VENV/bin/python" -m py_compile "$BASE/menu.py" 2>/dev/null || true
"$VENV/bin/python" -m py_compile "$BASE/root_owner/root_owner_wrapper.py" 2>/dev/null || true
"$VENV/bin/python" -m py_compile "$BASE/root_owner/root_owner_menu.py" 2>/dev/null || true

echo
echo "[+] Install complete."
echo "[!] Notes:"
echo "    - Python requirements installed inside: $VENV"
echo "    - Do NOT install iptables-persistent with ufw on this VPS."
echo "    - Run your app with: source $VENV/bin/activate"

