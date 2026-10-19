#!/usr/bin/env python3
"""
DEDSEC LAB · Owner tools
VPN Access allow-list requests - cooldown + webhook + services
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
DIM = "\033[2m"

BASE = Path("/opt/secure-scripts/dedsec-labNEW")
STATE_FILE = BASE / "vpn_access" / "vpn_access_state.json"
WEBHOOK_FILE = BASE / "vpn_access_webhook.json"
COOLDOWN = timedelta(hours=24)

SITE_UNIT = "dedsecsite.service"
DDOS_UNIT = "ovh-ddos-discord.service"

BANNER = r"""
██████╗ ███████╗██████╗ ███████╗███████╗ ██████╗
██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝
██║  ██║█████╗  ██║  ██║███████╗█████╗  ██║
██║  ██║██╔══╝  ██║  ██║╚════██║██╔══╝  ██║
██████╔╝███████╗██████╔╝███████║███████╗╚██████╗
╚═════╝ ╚══════╝╚═════╝ ╚══════╝╚══════╝ ╚═════╝
"""


def color(text, c):
    return f"{c}{text}{RESET}"


def _ignore_signal(signum, frame):
    print(color("\n  Ctrl+C / Ctrl+Z disabled. Use the menu to exit.", YELLOW))


def install_signal_guards():
    for sig in (signal.SIGINT, signal.SIGTSTP, signal.SIGQUIT):
        try:
            signal.signal(sig, _ignore_signal)
        except Exception:
            pass


def clear_screen():
    os.system("clear" if os.name != "nt" else "cls")


def pause(msg="Press Enter to return to menu..."):
    try:
        input(color(msg, DIM))
    except Exception:
        pass


def recover_terminal():
    print(color("Resetting terminal (stty sane + reset)...", YELLOW))
    os.system("stty sane 2>/dev/null || true")
    os.system("reset || true")
    print(color("Done. If the screen is still messy, close this SSH tab and open a new one.", GREEN))
    pause()


def ensure_state():
    BASE.mkdir(parents=True, exist_ok=True)
    if not STATE_FILE.exists():
        STATE_FILE.write_text(json.dumps({"users": {}}, indent=2), encoding="utf-8")
    try:
        os.chmod(STATE_FILE, 0o660)
        subprocess.run(["chgrp", "dedsecweb", str(STATE_FILE)], capture_output=True)
    except Exception:
        pass


def load_state():
    ensure_state()
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {"users": {}}
        data.setdefault("users", {})
        if not isinstance(data["users"], dict):
            data["users"] = {}
        return data
    except Exception:
        return {"users": {}}


def save_state(data):
    ensure_state()
    STATE_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    try:
        os.chmod(STATE_FILE, 0o660)
        subprocess.run(["chgrp", "dedsecweb", str(STATE_FILE)], capture_output=True)
    except Exception:
        pass


def parse_iso(value):
    raw = (value or "").strip()
    if not raw:
        return None
    try:
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def human_left(seconds):
    seconds = max(0, int(seconds))
    h, rem = divmod(seconds, 3600)
    m, _ = divmod(rem, 60)
    if h:
        return f"{h}h {m}m"
    return f"{m}m"


def unit_state(unit):
    try:
        r = subprocess.run(
            ["systemctl", "is-active", unit],
            capture_output=True, text=True, timeout=4,
        )
        return (r.stdout or "unknown").strip()
    except Exception:
        return "?"


def service_cmd(unit, action):
    try:
        if action == "status":
            r = subprocess.run(
                ["systemctl", "status", unit, "--no-pager", "-l"],
                capture_output=True, text=True, timeout=8,
            )
            print((r.stdout or r.stderr or "")[:1800])
            return
        r = subprocess.run(
            ["systemctl", action, unit],
            capture_output=True, text=True, timeout=20,
        )
        if r.returncode == 0:
            print(color(f"✓ systemctl {action} {unit}", GREEN))
        else:
            print(color((r.stderr or r.stdout or "failed").strip(), RED))
        print(f"State: {unit_state(unit)}")
    except Exception as e:
        print(color(str(e), RED))
    pause()


def banner(page=1):
    clear_screen()
    print(color(BANNER, CYAN))
    print(color("  DEDSEC LAB  ·  OWNER TOOLS", BOLD + CYAN))
    print(color("  VPN Access  ·  cooldown + Discord notify", DIM))
    print(color("=" * 56, CYAN))
    site = unit_state(SITE_UNIT)
    ddos = unit_state(DDOS_UNIT)
    print(color(f"  Website : {site}", GREEN if site == "active" else YELLOW))
    print(color(f"  DDoS mon: {ddos}", GREEN if ddos == "active" else YELLOW))
    print(color(f"  Cooldown file: {STATE_FILE}", DIM))
    print(color("-" * 56, DIM))
    if page == 1:
        print(color("  PAGE 1 · COOLDOWN + REQUESTS", BOLD + MAGENTA))
    else:
        print(color("  PAGE 2 · SERVICES + RECOVERY", BOLD + YELLOW))
    print()


def list_cooldowns():
    banner(1)
    state = load_state()
    users = state.get("users") or {}
    if not users:
        print(color("  No submissions yet.", DIM))
        pause()
        return
    now = datetime.now(timezone.utc)
    print(f"  {'USER':<24} {'IP':<16} {'TYPE':<10} {'STATUS'}")
    print(color("  " + "-" * 70, DIM))
    for key, entry in sorted(users.items()):
        name = entry.get("username") or key
        ip = entry.get("ip") or "-"
        typ = entry.get("ip_type") or "-"
        last = parse_iso(str(entry.get("last_submit") or ""))
        if last:
            nxt = last + COOLDOWN
            if now < nxt:
                status = color("LOCKED " + human_left((nxt - now).total_seconds()), YELLOW)
            else:
                status = color("ready", GREEN)
        else:
            status = color("ready", GREEN)
        print(f"  {name:<24} {ip:<16} {typ:<10} {status}")
    pause()


def reset_one():
    banner(1)
    state = load_state()
    users = state.get("users") or {}
    if not users:
        print(color("  No users in cooldown file.", DIM))
        pause()
        return
    print("  Known users:")
    names = sorted(users.keys())
    for i, n in enumerate(names, 1):
        print(f"   {i}. {users[n].get('username') or n}")
    print()
    raw = input(color("  Username or number: ", CYAN)).strip()
    if not raw:
        return
    chosen = None
    if raw.isdigit() and 1 <= int(raw) <= len(names):
        chosen = names[int(raw) - 1]
    else:
        low = raw.lower()
        if low in users:
            chosen = low
        else:
            for n, e in users.items():
                if (e.get("username") or "").lower() == low:
                    chosen = n
                    break
    if not chosen:
        print(color("  User not found.", RED))
        pause()
        return
    users.pop(chosen, None)
    save_state(state)
    print(color(f"  ✓ Cooldown cleared for {chosen}", GREEN))
    pause()


def reset_all():
    banner(1)
    confirm = input(color("  Type RESET to clear ALL cooldowns: ", YELLOW)).strip()
    if confirm != "RESET":
        print("  Cancelled.")
        pause()
        return
    save_state({"users": {}})
    print(color("  ✓ All cooldowns cleared.", GREEN))
    pause()


def test_webhook():
    banner(2)
    try:
        data = json.loads(WEBHOOK_FILE.read_text(encoding="utf-8"))
        url = str(data.get("webhook") or data.get("url") or data.get("webhook_url") or "").strip()
    except Exception as e:
        print(color(f"  Cannot read webhook file: {e}", RED))
        pause()
        return
    if not url.startswith("https://discord.com/api/webhooks/"):
        print(color("  Webhook URL missing or invalid.", RED))
        pause()
        return
    payload = json.dumps({
        "username": "DedSecEye",
        "embeds": [{
            "title": "VPN Access - owner test",
            "description": "Owner menu webhook test. Private channel only.",
            "color": 0x00FFFF,
            "footer": {"text": "DEDSCAN • owner"},
        }],
    }).encode()
    import urllib.request
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "DedSecEye/1.0 (OWNER; +https://discord.com)",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            print(color(f"  ✓ Discord HTTP {resp.status} - check your private channel.", GREEN))
    except Exception as e:
        print(color(f"  ✗ {e}", RED))
    pause()


def menu():
    install_signal_guards()
    ensure_state()
    page = 1
    while True:
        banner(page)
        if page == 1:
            print("   1. List cooldowns / last requests")
            print("   2. Reset ONE user cooldown")
            print("   3. Reset ALL cooldowns")
            print("   4. Next page")
            print("   0. Exit")
        else:
            print("   1. Website status / restart (dedsecsite)")
            print("   2. DDoS Discord monitor start")
            print("   3. DDoS Discord monitor stop")
            print("   4. DDoS Discord monitor restart")
            print("   5. DDoS Discord monitor status")
            print("   6. Test VPN-access webhook")
            print("   7. Recover stuck terminal (Ctrl+C lock)")
            print("   8. Previous page")
            print("   0. Exit")
        print()
        print(color("  Ctrl+C / Ctrl+Z are ignored. Exit with 0.", DIM))
        choice = input(color("Select option: ", CYAN)).strip()
        if page == 1:
            if choice == "1":
                list_cooldowns()
            elif choice == "2":
                reset_one()
            elif choice == "3":
                reset_all()
            elif choice == "4":
                page = 2
            elif choice == "0":
                print(color("Goodbye.", DIM))
                return
        else:
            if choice == "1":
                banner(2)
                print(f"  {SITE_UNIT}: {unit_state(SITE_UNIT)}")
                go = input("  Restart website now? [y/N]: ").strip().lower()
                if go == "y":
                    service_cmd(SITE_UNIT, "restart")
                else:
                    pause()
            elif choice == "2":
                service_cmd(DDOS_UNIT, "start")
            elif choice == "3":
                service_cmd(DDOS_UNIT, "stop")
            elif choice == "4":
                service_cmd(DDOS_UNIT, "restart")
            elif choice == "5":
                banner(2)
                service_cmd(DDOS_UNIT, "status")
            elif choice == "6":
                test_webhook()
            elif choice == "7":
                recover_terminal()
            elif choice == "8":
                page = 1
            elif choice == "0":
                print(color("Goodbye.", DIM))
                return


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Run as root.")
        sys.exit(1)
    menu()
