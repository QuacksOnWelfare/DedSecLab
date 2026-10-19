#!/usr/bin/env python3
"""United Kingdom / Linode - hourly Discord VPN status."""
from vpn_status_common import loop, report_once

REGION = "United Kingdom"
EXPECTED_IP = "YOUR_VPN_EXIT_UK"
WEBHOOK = "https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN"

if __name__ == "__main__":
    import sys
    if "--once" in sys.argv:
        raise SystemExit(report_once(REGION, WEBHOOK, EXPECTED_IP))
    loop(REGION, WEBHOOK, EXPECTED_IP, 3600)
