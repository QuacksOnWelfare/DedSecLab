#!/usr/bin/env python3
import os
import json
import socket
import urllib.request
from datetime import datetime

BASE_DIR = "/opt/secure-scripts/dedsec-labNEW"
CONFIG_FILE = os.path.join(BASE_DIR, "discord_alerts.json")

def load_config():
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def send_discord_alert(title, message, color=3447003, event_type="general"):
    config = load_config()

    if not config.get("enabled", False):
        return False

    alerts = config.get("alerts", {})
    if event_type in alerts and not alerts.get(event_type, False):
        return False

    webhooks = config.get("webhooks", {})
    webhook_url = webhooks.get(event_type) or webhooks.get("default", "")

    webhook_url = webhook_url.strip()

    if not webhook_url or "PASTE" in webhook_url:
        return False

    payload = {
        "username": "DEDSEC Lab Alerts",
        "embeds": [
            {
                "title": title,
                "description": message,
                "color": color,
                "footer": {
                    "text": f"{socket.gethostname()} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                }
            }
        ]
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "curl/8.0"
        },
        method="POST"
    )

    try:
        response = urllib.request.urlopen(req, timeout=10)
        return response.status in (200, 204)
    except Exception as e:
        print("Discord send error:", repr(e))
        return False
