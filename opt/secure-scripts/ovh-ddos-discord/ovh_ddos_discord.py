#!/usr/bin/env python3
"""OVH Game DDoS alert -> Discord.

Fill config.json from config.example.json. Shows the control flow
without embedding any private OVH or Discord credentials.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONFIG_PATH = HERE / "config.json"


def load_config():
    if not CONFIG_PATH.is_file():
        print("Missing config.json - copy config.example.json and fill placeholders.")
        sys.exit(1)
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def send_discord(webhook_url: str, title: str, body: str) -> bool:
    if not webhook_url or "YOUR_WEBHOOK" in webhook_url:
        print("Discord webhook not configured.")
        return False
    payload = {
        "username": "DedSec DDoS Alerts",
        "embeds": [{"title": title, "description": body, "color": 15158332}],
    }
    req = urllib.request.Request(
        webhook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "DedSecLab/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status in (200, 204)
    except Exception as e:
        print("Discord error:", e)
        return False


def poll_ovh_once(cfg: dict):
    """Call the OVH API here with cfg['ovh_*'] keys.
    Return a human-readable status string (or None if quiet).
    """
    # Integrate the ovh SDK / REST against YOUR service_name here.
    _ = cfg.get("service_name") or "YOUR_OVH_IP_OR_SERVICE"
    return None


def main():
    cfg = load_config()
    if not cfg.get("enabled"):
        print("disabled in config.json (set enabled=true after filling secrets)")
        return
    interval = int(cfg.get("poll_seconds") or 60)
    print("OVH DDoS watch started. Ctrl+C to stop.")
    while True:
        try:
            status = poll_ovh_once(cfg)
            if status:
                send_discord(cfg.get("discord_webhook_url", ""), "OVH DDoS event", status)
        except KeyboardInterrupt:
            print("stopped")
            break
        except Exception as e:
            print("poll error:", e)
        time.sleep(interval)


if __name__ == "__main__":
    main()
