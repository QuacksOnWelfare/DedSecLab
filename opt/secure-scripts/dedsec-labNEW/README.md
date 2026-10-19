# DEDSEC Lab - Quick Restore Guide

## 1. Connect to new VPS

```bash
ssh root@YOUR_VPS_IP
```

---

## 2. Upload lab files from Kali

```bash
scp -r /path/to/dedsec-labNEW root@YOUR_VPS_IP:/opt/secure-scripts/
```

---

## 3. SSH into VPS and prepare

```bash
ssh root@YOUR_VPS_IP
cd /opt/secure-scripts/dedsec-labNEW
chmod +x install.sh
```

---

## 4. Run installer

```bash
bash install.sh
```

This will:

* install all required system packages
* install Python requirements
* fix permissions
* configure sudo for `dedsecuser`
* create required system paths (`/var/log/ddos-watch`)

---

## 5. Verify Python dependencies

```bash
pip3 install --break-system-packages -r requirements.txt
```

---

## 6. Restore OpenVPN (if using backup)

### Copy configs (if not already included):

```bash
cp -r /root/backup/etc/openvpn /etc/
```

### Start OpenVPN:

```bash
systemctl enable openvpn-server@server
systemctl start openvpn-server@server
```

### Check status:

```bash
systemctl status openvpn-server@server
```

---

## 7. Verify SSH config (IMPORTANT)

```bash
sshd -t
```

Only restart if no errors:

```bash
systemctl restart ssh
```

---

## 8. Test permissions (VERY IMPORTANT)

Switch to user:

```bash
su - dedsecuser
```

Test:

```bash
sudo python3 /opt/secure-scripts/dedsec-labNEW/menu.py
```

---

## 9. Verify DDoS logs working

```bash
ls -lh /var/log/ddos-watch
```

---

## 10. Launch system

```bash
python3 /opt/secure-scripts/dedsec-labNEW/access_wrapper.py
```

---

# Notes

* Do NOT overwrite SSH config blindly (can lock you out)
* Do NOT expose unnecessary ports
* `/opt/secure-scripts` is restored from backup
* `/var/log/ddos-watch` must exist (handled by install.sh)

---

# Optional (recommended)

Reboot once after setup:

```bash
reboot
```

---

# Done

System should now be fully restored.
