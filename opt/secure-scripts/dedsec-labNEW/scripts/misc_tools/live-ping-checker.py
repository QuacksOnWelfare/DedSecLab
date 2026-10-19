#!/usr/bin/env python3
"""
DEDSEC Live Ping / IP Surveillance Checker (v3.4 - Ctrl+C returns to menu, cancel on all prompts)

Path (typical):
  /opt/secure-scripts/dedsec-labNEW/scripts/misc_tools/live-ping-checker.py

Identity (in order):
  SECURE_VPN_IP -> DEDSEC_SOURCE_IP -> VPN_IP -> CLIENT_VPN_IP
  Never treat YOUR_LAB_VPN_IP (server tun) as a client.
  No silent tun0 fallback for normal users.

Env from access_wrapper -> menu:
  DEDSEC_SOURCE_IP, DEDSEC_USER, DEDSEC_ROLE, DEDSEC_SSH_USER
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


# ============================================================
# PATHS
# ============================================================

BASE_DIR = "/opt/secure-scripts/dedsec-labNEW"
WEBHOOK_DIR = os.path.join(BASE_DIR, "discord_webhooks")
IP_SAVE_DIR = os.path.join(BASE_DIR, "ip_saves")
MONITOR_DIR = os.path.join(BASE_DIR, "monitor_state")
LOG_DIR = os.path.join(BASE_DIR, "logs")
RULES_FILE = os.path.join(BASE_DIR, "access_rules.json")

# Server-side VPN address - never a client identity
SERVER_VPN_IPS = {"YOUR_LAB_VPN_IP"}

DEFAULT_INTERVAL_HOURS = 3
MIN_INTERVAL_HOURS = 1
MAX_INTERVAL_HOURS = 24
PING_TIMEOUT = 6
IP_INFO_TIMEOUT = 10
DISCORD_TIMEOUT = 10
TCP_TIMEOUT = 3
MAX_IPS_PER_CLIENT = 40
DEFAULT_MULTI_FAIL = 2
DEFAULT_ALERT_COOLDOWN_SEC = 300
TRACE_MAX_HOPS = 20

# Live tracking (seconds) - independent of hourly monitor interval
DEFAULT_LIVE_INTERVAL_SEC = 30
MIN_LIVE_INTERVAL_SEC = 5
MAX_LIVE_INTERVAL_SEC = 600
LIVE_MAX_RUNTIME_HOURS = 72  # safety stop for background live


# ============================================================
# COLOURS
# ============================================================

RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
WHITE = "\033[97m"
MAGENTA = "\033[95m"

DISCORD_GREEN = 0x00FF00
DISCORD_RED = 0xFF0000
DISCORD_CYAN = 0x00FFFF
DISCORD_ORANGE = 0xFFAA00


def color(text: str, colour: str) -> str:
    return f"{colour}{text}{RESET}"


def clear_screen() -> None:
    os.system("clear" if os.name != "nt" else "cls")


class MenuBack(Exception):
    """Raised to abandon a submenu and return to the main tool menu."""


def install_signal_guards() -> None:
    """
    Ctrl+Z is ignored (would suspend and freeze the session).
    Ctrl+C is left as default KeyboardInterrupt so safe_input can catch it
    and return to the menu - never leave the user locked with no way out.
    """
    def _ignore_tstp(signum, frame):
        print(
            color("\n[!] Ctrl+Z disabled - type 0 or B to go back, or Ctrl+C for menu.", YELLOW),
            flush=True,
        )
    try:
        signal.signal(signal.SIGTSTP, _ignore_tstp)
    except Exception:
        pass
    # Do NOT override SIGINT - KeyboardInterrupt must work


def safe_input(prompt: str = "") -> str:
    """
    input() wrapper: Ctrl+C / EOF -> MenuBack (return to tool menu).
    Empty is allowed (caller decides).
    """
    try:
        return input(prompt)
    except (KeyboardInterrupt, EOFError):
        print()
        print(color("[*] Cancelled - back to menu.", YELLOW))
        raise MenuBack()


def pause(msg: str = "\nPress ENTER to continue...") -> None:
    try:
        input(msg)
    except (KeyboardInterrupt, EOFError):
        print()
        raise MenuBack()


def wait_interruptible(seconds: float) -> bool:
    """
    Sleep up to seconds.
    True if user typed q/quit/stop/back/0 OR pressed Ctrl+C (stop watching).
    """
    import select
    end = time.time() + max(0.1, float(seconds))
    while time.time() < end:
        remaining = end - time.time()
        if remaining <= 0:
            break
        try:
            ready, _, _ = select.select([sys.stdin], [], [], min(1.0, remaining))
        except (ValueError, OSError):
            time.sleep(min(1.0, remaining))
            continue
        if ready:
            try:
                line = sys.stdin.readline()
            except KeyboardInterrupt:
                return True
            except Exception:
                continue
            if not line:
                continue
            if line.strip().lower() in ("q", "quit", "stop", "exit", "back", "0", "b"):
                return True
    return False


BANNER = r"""
██████╗ ███████╗██████╗ ███████╗███████╗ ██████╗
██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝
██║  ██║█████╗  ██║  ██║███████╗█████╗  ██║
██║  ██║██╔══╝  ██║  ██║╚════██║██╔══╝  ██║
██████╔╝███████╗██████╔╝███████║███████╗╚██████╗
╚═════╝ ╚══════╝╚═════╝ ╚══════╝╚══════╝ ╚═════╝

               ⚠️  SURVEILLANCE  ⚠️

Secure Terminal Access Launcher
════════════════════════════════════════════════════════
"""


# ============================================================
# DIRS
# ============================================================

def initialize_directories() -> None:
    for directory in (WEBHOOK_DIR, IP_SAVE_DIR, MONITOR_DIR, LOG_DIR):
        os.makedirs(directory, mode=0o700, exist_ok=True)
        try:
            os.chmod(directory, 0o700)
        except PermissionError:
            pass


# ============================================================
# VALIDATION
# ============================================================

def is_valid_ipv4(ip: str) -> bool:
    pattern = (
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    )
    return bool(re.match(pattern, ip or ""))


def is_client_vpn_ip(ip: str) -> bool:
    if not is_valid_ipv4(ip):
        return False
    if ip in SERVER_VPN_IPS:
        return False
    # Prefer 10.8.0.0/24 lab range (not .1)
    parts = ip.split(".")
    if parts[0] == "10" and parts[1] == "8" and parts[2] == "0":
        return parts[3] != "1"
    # Allow other private IPs only if explicitly set via env (non-tun fallback)
    return True


# ============================================================
# IDENTITY
# ============================================================

def get_vpn_ip() -> Tuple[Optional[str], Optional[str]]:
    """
    Prefer wrapper env. Never use tun0 / YOUR_LAB_VPN_IP as the client.
    """
    for variable in (
        "SECURE_VPN_IP",
        "DEDSEC_SOURCE_IP",
        "VPN_IP",
        "CLIENT_VPN_IP",
    ):
        value = (os.environ.get(variable) or "").strip()
        if is_client_vpn_ip(value):
            return value, f"environment:{variable}"
        if is_valid_ipv4(value) and value in SERVER_VPN_IPS:
            # Explicitly ignore server address if someone exported it by mistake
            continue

    # Admin/root only: optional pick later; no silent tun0 hijack
    return None, None


def get_display_user() -> str:
    return (
        (os.environ.get("DEDSEC_USER") or "").strip()
        or (os.environ.get("DEDSEC_SSH_USER") or "").strip()
        or "unknown"
    )


def client_identifier(vpn_ip: str) -> str:
    return hashlib.sha256(vpn_ip.encode("utf-8")).hexdigest()[:32]


def webhook_file(vpn_ip: str) -> str:
    return os.path.join(WEBHOOK_DIR, client_identifier(vpn_ip) + ".json")


def database_file(vpn_ip: str) -> str:
    return os.path.join(IP_SAVE_DIR, client_identifier(vpn_ip) + ".json")


def settings_file(vpn_ip: str) -> str:
    return os.path.join(MONITOR_DIR, client_identifier(vpn_ip) + ".json")


def pid_file(vpn_ip: str) -> str:
    return os.path.join(MONITOR_DIR, client_identifier(vpn_ip) + ".pid")


def live_pid_file(vpn_ip: str) -> str:
    return os.path.join(MONITOR_DIR, client_identifier(vpn_ip) + ".live.pid")


def log_file(vpn_ip: str) -> str:
    return os.path.join(LOG_DIR, client_identifier(vpn_ip) + ".log")


# ============================================================
# JSON
# ============================================================

def load_json(path: str, default: Any) -> Any:
    try:
        if not os.path.exists(path):
            return default
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as error:
        print(color(f"[!] Could not load: {error}", RED))
        return default


def save_json(path: str, data: Any) -> bool:
    temporary = path + ".tmp"
    try:
        with open(temporary, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=4)
        os.replace(temporary, path)
        try:
            os.chmod(path, 0o600)
        except PermissionError:
            pass
        return True
    except Exception as error:
        print(color(f"[!] Could not save: {error}", RED))
        try:
            if os.path.exists(temporary):
                os.remove(temporary)
        except Exception:
            pass
        return False


def load_webhook(vpn_ip: str) -> str:
    data = load_json(webhook_file(vpn_ip), {})
    return data.get("webhook", "") if isinstance(data, dict) else ""


def save_webhook(vpn_ip: str, webhook: str) -> bool:
    return save_json(
        webhook_file(vpn_ip),
        {
            "version": 2,
            "vpn_client": vpn_ip,
            "owner": get_display_user(),
            "webhook": webhook,
            "updated": datetime.now(timezone.utc).isoformat(),
        },
    )


def load_database(vpn_ip: str) -> List[dict]:
    data = load_json(database_file(vpn_ip), [])
    return data if isinstance(data, list) else []


def save_database(vpn_ip: str, database: List[dict]) -> bool:
    return save_json(database_file(vpn_ip), database)


def default_settings() -> dict:
    return {
        "interval_hours": DEFAULT_INTERVAL_HOURS,
        "change_only": True,
        "multi_fail": DEFAULT_MULTI_FAIL,
        "alert_cooldown_sec": DEFAULT_ALERT_COOLDOWN_SEC,
        "default_tcp_ports": "",
        "live_interval_sec": DEFAULT_LIVE_INTERVAL_SEC,
    }


def load_settings(vpn_ip: str) -> dict:
    data = load_json(settings_file(vpn_ip), {})
    if not isinstance(data, dict):
        data = {}
    base = default_settings()
    base.update({k: v for k, v in data.items() if k in base or k in ("version", "vpn_client", "updated")})
    try:
        interval = int(base.get("interval_hours", DEFAULT_INTERVAL_HOURS))
    except (TypeError, ValueError):
        interval = DEFAULT_INTERVAL_HOURS
    if interval < MIN_INTERVAL_HOURS or interval > MAX_INTERVAL_HOURS:
        interval = DEFAULT_INTERVAL_HOURS
    base["interval_hours"] = interval
    try:
        base["multi_fail"] = max(1, min(5, int(base.get("multi_fail", DEFAULT_MULTI_FAIL))))
    except (TypeError, ValueError):
        base["multi_fail"] = DEFAULT_MULTI_FAIL
    try:
        base["alert_cooldown_sec"] = max(0, int(base.get("alert_cooldown_sec", DEFAULT_ALERT_COOLDOWN_SEC)))
    except (TypeError, ValueError):
        base["alert_cooldown_sec"] = DEFAULT_ALERT_COOLDOWN_SEC
    base["change_only"] = bool(base.get("change_only", True))
    base["default_tcp_ports"] = str(base.get("default_tcp_ports") or "")
    try:
        live_iv = int(base.get("live_interval_sec", DEFAULT_LIVE_INTERVAL_SEC))
    except (TypeError, ValueError):
        live_iv = DEFAULT_LIVE_INTERVAL_SEC
    if live_iv < MIN_LIVE_INTERVAL_SEC or live_iv > MAX_LIVE_INTERVAL_SEC:
        live_iv = DEFAULT_LIVE_INTERVAL_SEC
    base["live_interval_sec"] = live_iv
    return base


def save_settings(vpn_ip: str, settings: dict) -> bool:
    payload = {
        "version": 2,
        "vpn_client": vpn_ip,
        "owner": get_display_user(),
        "interval_hours": settings.get("interval_hours", DEFAULT_INTERVAL_HOURS),
        "change_only": bool(settings.get("change_only", True)),
        "multi_fail": int(settings.get("multi_fail", DEFAULT_MULTI_FAIL)),
        "alert_cooldown_sec": int(settings.get("alert_cooldown_sec", DEFAULT_ALERT_COOLDOWN_SEC)),
        "default_tcp_ports": str(settings.get("default_tcp_ports") or ""),
        "live_interval_sec": int(settings.get("live_interval_sec", DEFAULT_LIVE_INTERVAL_SEC)),
        "updated": datetime.now(timezone.utc).isoformat(),
    }
    return save_json(settings_file(vpn_ip), payload)


# ============================================================
# NETWORK HELPERS
# ============================================================

def get_ip_info(ip: str) -> Optional[dict]:
    try:
        url = "https://ipwho.is/" + urllib.parse.quote(ip)
        request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 DedSec-Monitor/2.0"})
        with urllib.request.urlopen(request, timeout=IP_INFO_TIMEOUT) as response:
            data = json.loads(response.read().decode())
        if not data.get("success", False):
            return None
        connection = data.get("connection") or {}
        return {
            "ip": data.get("ip", ip),
            "country": data.get("country", "Unknown"),
            "country_code": data.get("country_code", "Unknown"),
            "region": data.get("region", "Unknown"),
            "city": data.get("city", "Unknown"),
            "isp": connection.get("isp", "Unknown"),
            "org": connection.get("org", "Unknown"),
            "asn": connection.get("asn", "Unknown"),
        }
    except Exception as error:
        print(color(f"[!] IP information unavailable: {error}", YELLOW))
        return None


def reverse_dns(ip: str) -> str:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host or "None"
    except Exception:
        return "None"


def ping_ip(ip: str) -> bool:
    system = platform.system().lower()
    if system == "windows":
        command = ["ping", "-n", "1", "-w", "3000", ip]
    else:
        command = ["ping", "-c", "1", "-W", "3", ip]
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=PING_TIMEOUT,
        )
        return result.returncode == 0
    except Exception:
        return False


def tcp_check(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=TCP_TIMEOUT):
            return True
    except Exception:
        return False


def parse_ports(text: str) -> List[int]:
    ports: List[int] = []
    for part in re.split(r"[\s,]+", (text or "").strip()):
        if not part:
            continue
        try:
            p = int(part)
            if 1 <= p <= 65535:
                ports.append(p)
        except ValueError:
            continue
    return sorted(set(ports))


def traceroute_ip(ip: str) -> str:
    """Best-effort traceroute; returns text output."""
    commands = [
        ["traceroute", "-n", "-w", "2", "-q", "1", "-m", str(TRACE_MAX_HOPS), ip],
        ["tracepath", "-n", ip],
    ]
    for cmd in commands:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=45,
            )
            out = (result.stdout or "") + (result.stderr or "")
            if out.strip():
                return out.strip()[:4000]
        except FileNotFoundError:
            continue
        except Exception as error:
            return f"Traceroute error: {error}"
    return "traceroute/tracepath not available on this host."


# ============================================================
# DISCORD
# ============================================================

def send_discord(webhook: str, title: str, message: str, colour: int) -> bool:
    if not webhook:
        return False
    payload = {
        "username": "DedSecEye",
        "embeds": [
            {
                "title": title,
                "description": message,
                "color": colour,
                "footer": {"text": f"DEDSCAN • {get_display_user()}"},
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ],
    }
    try:
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            webhook,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Live-Ping-Checker/2.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=DISCORD_TIMEOUT) as response:
            return 200 <= response.status < 300
    except Exception as error:
        print(color(f"[!] Discord webhook error: {error}", RED))
        return False


def info_values(info: Optional[dict]) -> dict:
    if not info:
        return {
            "isp": "Unknown",
            "org": "Unknown",
            "asn": "Unknown",
            "country": "Unknown",
            "region": "Unknown",
            "city": "Unknown",
        }
    return {
        "isp": info.get("isp", "Unknown"),
        "org": info.get("org", "Unknown"),
        "asn": info.get("asn", "Unknown"),
        "country": info.get("country", "Unknown"),
        "region": info.get("region", "Unknown"),
        "city": info.get("city", "Unknown"),
    }


def format_status_line(status: str) -> str:
    if status == "online":
        return color("ONLINE", GREEN)
    if status == "no_icmp":
        return color("OFFLINE", RED)
    return color(status.upper(), WHITE)


# ============================================================
# DISPLAY
# ============================================================

def display_target(
    ip: str,
    info: Optional[dict] = None,
    status: Optional[str] = None,
    label: str = "",
    ports: Optional[Dict[int, bool]] = None,
    ptr: str = "",
) -> None:
    details = info_values(info)
    print()
    print(color("╔══════════════════════════════════════════════╗", CYAN))
    print(color("║              TARGET INFORMATION             ║", CYAN))
    print(color("╠══════════════════════════════════════════════╣", CYAN))
    if label:
        print(f"║ Label       : {label}")
    print(f"║ IP Address  : {ip}")
    if ptr:
        print(f"║ rDNS        : {ptr}")
    print(f"║ ISP         : {details['isp']}")
    print(f"║ Organization: {details['org']}")
    print(f"║ ASN         : {details['asn']}")
    print(f"║ Country     : {details['country']}")
    print(f"║ Region      : {details['region']}")
    print(f"║ City        : {details['city']}")
    if status in ("online", "no_icmp"):
        print(f"║ Status      : {format_status_line(status)}")
    if ports:
        port_bits = []
        for p, ok in sorted(ports.items()):
            port_bits.append(f"{p}:{'open' if ok else 'closed'}")
        print(f"║ Ports       : {', '.join(port_bits)}")
    print(color("╚══════════════════════════════════════════════╝", CYAN))


def count_statuses(database: List[dict]) -> Tuple[int, int, int]:
    online = offline = unknown = 0
    for entry in database:
        st = entry.get("last_status")
        if st == "online":
            online += 1
        elif st == "no_icmp":
            offline += 1
        else:
            unknown += 1
    return online, offline, unknown


# ============================================================
# CHECK LOGIC
# ============================================================

def evaluate_reachability(
    ip: str,
    tcp_ports: List[int],
) -> Tuple[str, Dict[int, bool]]:
    """
    online  = ICMP ok OR any configured TCP port open
    no_icmp = nothing responded (name kept for compatibility)
    """
    icmp_ok = ping_ip(ip)
    port_results: Dict[int, bool] = {}
    any_tcp = False
    for port in tcp_ports:
        ok = tcp_check(ip, port)
        port_results[port] = ok
        if ok:
            any_tcp = True
    if icmp_ok or any_tcp:
        return "online", port_results
    return "no_icmp", port_results


def should_send_alert(
    entry: dict,
    new_status: str,
    settings: dict,
    force: bool = False,
) -> bool:
    if force:
        return True
    if not settings.get("change_only", True):
        # still respect cooldown for repeated same-status spam
        pass
    else:
        old = entry.get("last_status")
        if old and old == new_status:
            return False
        if not old:
            # first observation: only alert if offline (optional) - alert both
            pass

    cooldown = int(settings.get("alert_cooldown_sec", DEFAULT_ALERT_COOLDOWN_SEC))
    if cooldown > 0:
        last_alert = entry.get("last_alert_ts")
        if last_alert:
            try:
                if time.time() - float(last_alert) < cooldown:
                    # allow status *change* through cooldown
                    old = entry.get("last_status")
                    if old == new_status:
                        return False
            except (TypeError, ValueError):
                pass
    return True


def check_ip(
    ip: str,
    webhook: str = "",
    send_notification: bool = False,
    label: str = "",
    tcp_ports: Optional[List[int]] = None,
    do_ptr: bool = False,
    force_notify: bool = False,
    entry: Optional[dict] = None,
    settings: Optional[dict] = None,
    quiet: bool = False,
    skip_geo: bool = False,
) -> dict:
    tcp_ports = tcp_ports or []
    settings = settings or default_settings()
    entry = entry or {}

    info = None if skip_geo else get_ip_info(ip)
    status, port_results = evaluate_reachability(ip, tcp_ports)
    ptr = reverse_dns(ip) if do_ptr else ""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if not quiet:
        display_target(ip, info, status, label=label, ports=port_results or None, ptr=ptr)
    else:
        st = format_status_line(status)
        lab = f" ({label})" if label else ""
        print(f"  [{now}] {ip}{lab} -> {st}", flush=True)

    if send_notification and webhook:
        if should_send_alert(entry, status, settings, force=force_notify):
            details = info_values(info)
            if status == "online":
                status_text = "🟢 ONLINE"
                discord_colour = DISCORD_GREEN
                title = "Surveillance - ONLINE"
            else:
                status_text = "🔴 OFFLINE"
                discord_colour = DISCORD_RED
                title = "Surveillance - OFFLINE"

            label_line = f"**Label:** `{label}`\n" if label else ""
            ports_line = ""
            if port_results:
                ports_line = "**Ports:** " + ", ".join(
                    f"`{p} {'open' if ok else 'closed'}`" for p, ok in sorted(port_results.items())
                ) + "\n"

            message = (
                f"{label_line}"
                f"**Target:** `{ip}`\n"
                f"**Status:** {status_text}\n"
                f"**Time:** `{now}`\n"
                f"**Owner:** `{get_display_user()}`\n\n"
                f"{ports_line}"
                f"**ISP:** `{details['isp']}`\n"
                f"**Organization:** `{details['org']}`\n"
                f"**ASN:** `{details['asn']}`\n"
                f"**Country:** `{details['country']}`\n"
                f"**Region:** `{details['region']}`\n"
                f"**City:** `{details['city']}`"
            )
            if send_discord(webhook, title, message, discord_colour):
                print(color("[+] Discord notification sent.", GREEN))
                entry["last_alert_ts"] = time.time()

    return {
        "status": status,
        "info": info,
        "timestamp": now,
        "ports": port_results,
        "ptr": ptr,
    }


def apply_multi_fail(entry: dict, observed: str, multi_fail: int) -> str:
    """
    Require N consecutive offline observations before reporting offline.
    Online always wins immediately.
    """
    if observed == "online":
        entry["fail_streak"] = 0
        return "online"
    streak = int(entry.get("fail_streak") or 0) + 1
    entry["fail_streak"] = streak
    if streak >= multi_fail:
        return "no_icmp"
    # stay at previous stable status if we had online
    prev = entry.get("last_status")
    if prev == "online":
        return "online"
    return "no_icmp" if streak >= multi_fail else (prev or "no_icmp")


def geo_changed(old_info: dict, new_info: Optional[dict]) -> bool:
    if not new_info or not old_info:
        return False
    for key in ("asn", "isp", "country", "org"):
        a = str(old_info.get(key) or "").strip().lower()
        b = str(new_info.get(key) or "").strip().lower()
        if a and b and a != "unknown" and b != "unknown" and a != b:
            return True
    return False


# ============================================================
# MONITOR CYCLE
# ============================================================

def run_monitoring_cycle(vpn_ip: str, database: List[dict], webhook: str) -> List[dict]:
    settings = load_settings(vpn_ip)
    multi_fail = int(settings.get("multi_fail", DEFAULT_MULTI_FAIL))
    default_ports = parse_ports(settings.get("default_tcp_ports") or "")

    print()
    print(color("════════════════════════════════════════════════════════", CYAN))
    print(color("                 MONITORING CYCLE", CYAN))
    print(color("════════════════════════════════════════════════════════", CYAN))

    for entry in database:
        ip = entry.get("ip")
        if not ip:
            continue

        label = entry.get("label") or ""
        ports = parse_ports(entry.get("tcp_ports") or "") or default_ports

        print()
        print(color(f"[*] Checking {ip}" + (f" ({label})" if label else ""), CYAN))

        result = check_ip(
            ip,
            webhook=webhook,
            send_notification=False,
            label=label,
            tcp_ports=ports,
            entry=entry,
            settings=settings,
        )

        observed = result["status"]
        new_status = apply_multi_fail(entry, observed, multi_fail)
        old_status = entry.get("last_status")
        old_info = entry.get("last_info") or {}

        # Status change Discord
        if webhook and old_status and old_status != new_status:
            if should_send_alert(entry, new_status, settings, force=True):
                if new_status == "online":
                    d = info_values(result.get("info") or entry.get("last_info") or {})
                    lab = f"**Label:** `{label}`\n" if label else ""
                    send_discord(
                        webhook,
                        "Surveillance - ONLINE",
                        (
                            f"{lab}"
                            f"**Target:** `{ip}`\n"
                            f"**Status:** 🟢 ONLINE\n"
                            f"**Time:** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`\n"
                            f"**Owner:** `{get_display_user()}`\n\n"
                            f"**ISP:** `{d['isp']}`\n"
                            f"**Organization:** `{d.get('org', d['isp'])}`\n"
                            f"**ASN:** `{d['asn']}`\n"
                            f"**Country:** `{d['country']}`\n"
                            f"**Region:** `{d.get('region', 'Unknown')}`\n"
                            f"**City:** `{d['city']}`"
                        ),
                        DISCORD_GREEN,
                    )
                else:
                    d = info_values(result.get("info") or entry.get("last_info") or {})
                    lab = f"**Label:** `{label}`\n" if label else ""
                    send_discord(
                        webhook,
                        "Surveillance - OFFLINE",
                        (
                            f"{lab}"
                            f"**Target:** `{ip}`\n"
                            f"**Status:** 🔴 OFFLINE\n"
                            f"**Time:** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`\n"
                            f"**Owner:** `{get_display_user()}`\n\n"
                            f"**ISP:** `{d['isp']}`\n"
                            f"**Organization:** `{d.get('org', d['isp'])}`\n"
                            f"**ASN:** `{d['asn']}`\n"
                            f"**Country:** `{d['country']}`\n"
                            f"**Region:** `{d.get('region', 'Unknown')}`\n"
                            f"**City:** `{d['city']}`"
                        ),
                        DISCORD_RED,
                    )
                entry["last_alert_ts"] = time.time()

        # ASN / geo change
        if webhook and result["info"] and geo_changed(old_info, result["info"]):
            d = info_values(result["info"])
            send_discord(
                webhook,
                "🟠 Network identity changed",
                f"Target `{ip}` geo/ASN/ISP changed.\n"
                f"**ISP:** `{d['isp']}`\n**ASN:** `{d['asn']}`\n"
                f"**Country:** `{d['country']}`\n"
                f"**Owner:** `{get_display_user()}`",
                DISCORD_ORANGE,
            )

        entry["last_status"] = new_status
        entry["last_check"] = result["timestamp"]
        entry["last_info"] = result["info"] if result["info"] else {}
        entry["last_ports"] = result.get("ports") or {}
        hist = entry.get("history") or []
        hist.append({"ts": result["timestamp"], "status": new_status})
        entry["history"] = hist[-30:]

        save_database(vpn_ip, database)

    print()
    print(color("[+] Monitoring cycle complete.", GREEN))
    return database


# ============================================================
# PID / BACKGROUND
# ============================================================

def read_pid(vpn_ip: str) -> Optional[int]:
    path = pid_file(vpn_ip)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            pid = int(fh.read().strip())
        return pid if pid > 0 else None
    except Exception:
        return None


def write_pid(vpn_ip: str, pid: int) -> bool:
    try:
        with open(pid_file(vpn_ip), "w", encoding="utf-8") as fh:
            fh.write(str(pid))
        try:
            os.chmod(pid_file(vpn_ip), 0o600)
        except PermissionError:
            pass
        return True
    except Exception:
        return False


def remove_pid(vpn_ip: str) -> None:
    try:
        if os.path.exists(pid_file(vpn_ip)):
            os.remove(pid_file(vpn_ip))
    except Exception:
        pass


def process_exists(pid: Optional[int]) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except Exception:
        return False


def background_running(vpn_ip: str) -> bool:
    pid = read_pid(vpn_ip)
    if not pid:
        return False
    if process_exists(pid):
        return True
    remove_pid(vpn_ip)
    return False


def write_background_log(vpn_ip: str, message: str) -> None:
    try:
        with open(log_file(vpn_ip), "a", encoding="utf-8") as fh:
            fh.write(f"[{datetime.now(timezone.utc).isoformat()}] {message}\n")
    except Exception:
        pass


def background_worker(vpn_ip: str) -> None:
    write_background_log(vpn_ip, "Background monitor started.")
    write_pid(vpn_ip, os.getpid())
    try:
        while True:
            database = load_database(vpn_ip)
            webhook = load_webhook(vpn_ip)
            settings = load_settings(vpn_ip)
            interval_hours = settings["interval_hours"]
            write_background_log(vpn_ip, f"Cycle start ({len(database)} targets).")
            try:
                run_monitoring_cycle(vpn_ip, database, webhook)
            except Exception as error:
                write_background_log(vpn_ip, f"Cycle error: {error}")
            write_background_log(vpn_ip, f"Sleeping {interval_hours}h.")
            time.sleep(interval_hours * 3600)
    finally:
        remove_pid(vpn_ip)
        write_background_log(vpn_ip, "Background monitor stopped.")


def start_background_monitor(vpn_ip: str) -> Optional[int]:
    if background_running(vpn_ip):
        print(color("[!] Background monitor already running.", YELLOW))
        return read_pid(vpn_ip)
    try:
        proc = subprocess.Popen(
            [sys.executable, os.path.abspath(__file__), "--background"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env=os.environ.copy(),
        )
        return proc.pid
    except Exception as error:
        print(color(f"[!] Failed to start background: {error}", RED))
        return None


def stop_background_monitor(vpn_ip: str) -> None:
    pid = read_pid(vpn_ip)
    if not pid or not process_exists(pid):
        remove_pid(vpn_ip)
        print(color("[*] No background monitor running.", YELLOW))
        return
    try:
        os.kill(pid, signal.SIGTERM)
        time.sleep(0.5)
        if process_exists(pid):
            os.kill(pid, signal.SIGKILL)
        remove_pid(vpn_ip)
        print(color(f"[+] Stopped background monitor (PID {pid}).", GREEN))
    except Exception as error:
        print(color(f"[!] Stop failed: {error}", RED))



# ============================================================
# LIVE TRACKING (fast poll until online/offline flip)
# ============================================================

def read_live_pid(vpn_ip: str) -> Optional[int]:
    path = live_pid_file(vpn_ip)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            pid = int(fh.read().strip())
        return pid if pid > 0 else None
    except Exception:
        return None


def write_live_pid(vpn_ip: str, pid: int) -> bool:
    try:
        with open(live_pid_file(vpn_ip), "w", encoding="utf-8") as fh:
            fh.write(str(pid))
        try:
            os.chmod(live_pid_file(vpn_ip), 0o600)
        except PermissionError:
            pass
        return True
    except Exception:
        return False


def remove_live_pid(vpn_ip: str) -> None:
    try:
        p = live_pid_file(vpn_ip)
        if os.path.exists(p):
            os.remove(p)
    except Exception:
        pass


def live_background_running(vpn_ip: str) -> bool:
    pid = read_live_pid(vpn_ip)
    if not pid:
        return False
    if process_exists(pid):
        return True
    remove_live_pid(vpn_ip)
    return False


def notify_live_flip(
    webhook: str,
    ip: str,
    label: str,
    old_status: str,
    new_status: str,
    info: Optional[dict],
) -> None:
    if not webhook:
        return
    details = info_values(info)
    lab = f"**Label:** `{label}`\n" if label else ""
    if new_status == "online":
        title = "Surveillance - ONLINE"
        colour = DISCORD_GREEN
        status_text = "🟢 ONLINE"
    else:
        title = "Surveillance - OFFLINE"
        colour = DISCORD_RED
        status_text = "🔴 OFFLINE"
    message = (
        f"{lab}"
        f"**Target:** `{ip}`\n"
        f"**Status:** {status_text}\n"
        f"**Time:** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`\n"
        f"**Owner:** `{get_display_user()}`\n\n"
        f"**ISP:** `{details['isp']}`\n"
        f"**Organization:** `{details.get('org', details['isp'])}`\n"
        f"**ASN:** `{details['asn']}`\n"
        f"**Country:** `{details['country']}`\n"
        f"**Region:** `{details.get('region', 'Unknown')}`\n"
        f"**City:** `{details['city']}`"
    )
    if send_discord(webhook, title, message, colour):
        print(color("[+] Live-track Discord alert sent.", GREEN))


def live_track_one(
    vpn_ip: str,
    entry: dict,
    webhook: str,
    settings: dict,
    watch: str = "flip",
) -> dict:
    """
    watch:
      flip         - alert on any status change then stop
      until_online - keep polling while offline until online
      until_offline- keep polling while online until offline
    """
    ip = entry.get("ip")
    if not ip:
        return entry
    label = entry.get("label") or ""
    ports = parse_ports(entry.get("tcp_ports") or "") or parse_ports(
        settings.get("default_tcp_ports") or ""
    )
    interval = int(settings.get("live_interval_sec", DEFAULT_LIVE_INTERVAL_SEC))
    multi_fail = int(settings.get("multi_fail", DEFAULT_MULTI_FAIL))

    print()
    print(color("════════════════════════════════════════════════════════", MAGENTA))
    print(color("                   LIVE TRACKING", MAGENTA))
    print(color("════════════════════════════════════════════════════════", MAGENTA))
    print(f"Target   : {ip}" + (f" ({label})" if label else ""))
    if watch == "until_online":
        print(color("Waiting  : until ONLINE  ->  Discord alert", GREEN))
    elif watch == "until_offline":
        print(color("Waiting  : until OFFLINE  ->  Discord alert", YELLOW))
    else:
        print(f"Mode     : {watch}")
    print(f"Interval : every {interval}s")
    print(f"Discord  : {'yes' if webhook else 'not configured'}")
    print(color("Type q + ENTER to stop and return to menu", YELLOW))
    print()

    # Baseline
    baseline = check_ip(
        ip,
        webhook="",
        send_notification=False,
        label=label,
        tcp_ports=ports,
        do_ptr=False,
        entry=entry,
        settings=settings,
        quiet=False,
        skip_geo=False,
    )
    observed = baseline["status"]
    current = apply_multi_fail(entry, observed, multi_fail)
    entry["last_status"] = current
    entry["last_check"] = baseline["timestamp"]
    if baseline.get("info"):
        entry["last_info"] = baseline["info"]
    entry["last_ports"] = baseline.get("ports") or {}

    if watch == "until_online" and current == "online":
        print(color("[*] Already ONLINE - nothing to wait for.", GREEN))
        if webhook:
            notify_live_flip(webhook, ip, label, "no_icmp", "online", baseline.get("info"))
        return entry
    if watch == "until_offline" and current == "no_icmp":
        print(color("[*] Already OFFLINE - nothing to wait for.", YELLOW))
        if webhook:
            notify_live_flip(webhook, ip, label, "online", "no_icmp", baseline.get("info"))
        return entry

    print(color(f"[*] Watching... (poll every {interval}s)", CYAN))
    while True:
        if wait_interruptible(interval):
            print()
            print(color("[*] Live track stopped - back to menu.", YELLOW))
            break
        result = check_ip(
            ip,
            webhook="",
            send_notification=False,
            label=label,
            tcp_ports=ports,
            entry=entry,
            settings=settings,
            quiet=True,
            skip_geo=True,
        )
        observed = result["status"]
        new_status = apply_multi_fail(entry, observed, multi_fail)
        old_status = entry.get("last_status")

        if new_status != old_status:
            info = get_ip_info(ip)
            result["info"] = info
            print()
            print(color(f"[!] Status change: {old_status} -> {new_status}", YELLOW))
            display_target(ip, info, new_status, label=label, ports=result.get("ports"))
            if webhook:
                notify_live_flip(webhook, ip, label, old_status or "unknown", new_status, info)
            entry["last_status"] = new_status
            entry["last_check"] = result["timestamp"]
            entry["last_info"] = info or {}
            entry["last_ports"] = result.get("ports") or {}
            entry["last_alert_ts"] = time.time()
            hist = entry.get("history") or []
            hist.append({"ts": result["timestamp"], "status": new_status, "live": True})
            entry["history"] = hist[-30:]

            stop = False
            if watch == "flip":
                stop = True
            elif watch == "until_online" and new_status == "online":
                stop = True
            elif watch == "until_offline" and new_status == "no_icmp":
                stop = True
            if stop:
                print(color("[+] Live track goal reached.", GREEN))
                break
        else:
            entry["last_check"] = result["timestamp"]

    return entry


def live_cycle_tracked(vpn_ip: str, database: List[dict], webhook: str) -> List[dict]:
    """One pass over entries with live_enabled=True (used by live background)."""
    settings = load_settings(vpn_ip)
    multi_fail = int(settings.get("multi_fail", DEFAULT_MULTI_FAIL))
    default_ports = parse_ports(settings.get("default_tcp_ports") or "")

    for entry in database:
        if not entry.get("live_enabled"):
            continue
        ip = entry.get("ip")
        if not ip:
            continue
        label = entry.get("label") or ""
        ports = parse_ports(entry.get("tcp_ports") or "") or default_ports
        watch = (entry.get("live_mode") or "flip").strip().lower()

        result = check_ip(
            ip,
            webhook="",
            send_notification=False,
            label=label,
            tcp_ports=ports,
            entry=entry,
            settings=settings,
            quiet=True,
            skip_geo=True,
        )
        observed = result["status"]
        new_status = apply_multi_fail(entry, observed, multi_fail)
        old_status = entry.get("last_status")

        if old_status and new_status != old_status:
            info = get_ip_info(ip)
            write_background_log(
                vpn_ip,
                f"LIVE flip {ip}: {old_status} -> {new_status}",
            )
            if webhook:
                notify_live_flip(webhook, ip, label, old_status, new_status, info)
            entry["last_alert_ts"] = time.time()
            entry["last_info"] = info or {}
            # auto-disable one-shot modes after goal
            if watch == "until_online" and new_status == "online":
                entry["live_enabled"] = False
            elif watch == "until_offline" and new_status == "no_icmp":
                entry["live_enabled"] = False
            elif watch == "flip":
                entry["live_enabled"] = False

        entry["last_status"] = new_status
        entry["last_check"] = result["timestamp"]
        entry["last_ports"] = result.get("ports") or {}
        save_database(vpn_ip, database)

    return database


def live_background_worker(vpn_ip: str) -> None:
    write_background_log(vpn_ip, "LIVE background started.")
    write_live_pid(vpn_ip, os.getpid())
    started = time.time()
    try:
        while True:
            if time.time() - started > LIVE_MAX_RUNTIME_HOURS * 3600:
                write_background_log(vpn_ip, "LIVE background hit max runtime - stopping.")
                break
            database = load_database(vpn_ip)
            webhook = load_webhook(vpn_ip)
            settings = load_settings(vpn_ip)
            tracked = [e for e in database if e.get("live_enabled")]
            if not tracked:
                write_background_log(vpn_ip, "No live_enabled targets - stopping.")
                break
            try:
                live_cycle_tracked(vpn_ip, database, webhook)
            except Exception as error:
                write_background_log(vpn_ip, f"LIVE cycle error: {error}")
            interval = int(settings.get("live_interval_sec", DEFAULT_LIVE_INTERVAL_SEC))
            time.sleep(max(MIN_LIVE_INTERVAL_SEC, interval))
    finally:
        remove_live_pid(vpn_ip)
        write_background_log(vpn_ip, "LIVE background stopped.")


def start_live_background(vpn_ip: str) -> Optional[int]:
    if live_background_running(vpn_ip):
        print(color("[!] Live background already running.", YELLOW))
        return read_live_pid(vpn_ip)
    try:
        proc = subprocess.Popen(
            [sys.executable, os.path.abspath(__file__), "--live-background"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env=os.environ.copy(),
        )
        # child rewrites live pid; store parent as hint until child starts
        write_live_pid(vpn_ip, proc.pid)
        return proc.pid
    except Exception as error:
        print(color(f"[!] Failed to start live background: {error}", RED))
        return None


def stop_live_background(vpn_ip: str) -> None:
    pid = read_live_pid(vpn_ip)
    if not pid or not process_exists(pid):
        remove_live_pid(vpn_ip)
        print(color("[*] No live background running.", YELLOW))
        return
    try:
        os.kill(pid, signal.SIGTERM)
        time.sleep(0.5)
        if process_exists(pid):
            os.kill(pid, signal.SIGKILL)
        remove_live_pid(vpn_ip)
        print(color(f"[+] Stopped live background (PID {pid}).", GREEN))
    except Exception as error:
        print(color(f"[!] Stop live failed: {error}", RED))


def toggle_live_on_ip(vpn_ip: str, database: List[dict]) -> List[dict]:
    entry = select_ip(database)
    if not entry:
        return database
    print()
    print(f"IP: {entry.get('ip')}  live_enabled={entry.get('live_enabled', False)}  mode={entry.get('live_mode', 'flip')}")
    print("[1] Enable live track - alert on any flip (then auto-off)")
    print("[2] Enable - keep watching until ONLINE")
    print("[3] Enable - keep watching until OFFLINE")
    print("[4] Disable live track on this IP")
    print("[0] Cancel")
    choice = input("Select: ").strip()
    if choice == "1":
        entry["live_enabled"] = True
        entry["live_mode"] = "flip"
        print(color("[+] Live enabled (flip once).", GREEN))
    elif choice == "2":
        entry["live_enabled"] = True
        entry["live_mode"] = "until_online"
        print(color("[+] Live enabled (until ONLINE).", GREEN))
    elif choice == "3":
        entry["live_enabled"] = True
        entry["live_mode"] = "until_offline"
        print(color("[+] Live enabled (until OFFLINE).", GREEN))
    elif choice == "4":
        entry["live_enabled"] = False
        print(color("[*] Live disabled for this IP.", YELLOW))
    else:
        print(color("[*] Cancelled.", YELLOW))
        pause()
        return database
    save_database(vpn_ip, database)
    pause()
    return database


def menu_live_track_one(vpn_ip: str, database: List[dict], webhook: str) -> List[dict]:
    """Smart live track: offline->online or online->offline. Foreground or background."""
    entry = select_ip(database)
    if not entry:
        return database
    settings = load_settings(vpn_ip)
    ip = entry.get("ip")
    label = entry.get("label") or ""
    ports = parse_ports(entry.get("tcp_ports") or "") or parse_ports(
        settings.get("default_tcp_ports") or ""
    )
    interval = int(settings.get("live_interval_sec", DEFAULT_LIVE_INTERVAL_SEC))

    clear_screen()
    print(BANNER)
    print(color("LIVE TRACK", CYAN))
    print(color("════════════════════════════════════════════════════════", CYAN))
    print(color("[*] Checking current status...", CYAN))
    result = check_ip(
        ip,
        webhook="",
        send_notification=False,
        label=label,
        tcp_ports=ports,
        do_ptr=False,
        entry=entry,
        settings=settings,
        quiet=False,
        skip_geo=False,
    )
    status = result["status"]
    entry["last_status"] = status
    entry["last_check"] = result["timestamp"]
    if result.get("info"):
        entry["last_info"] = result["info"]
    entry["last_ports"] = result.get("ports") or {}

    if status == "online":
        watch = "until_offline"
        print()
        print(color("[+] Target is ONLINE right now.", GREEN))
        print(color("[*] Will Discord you when it goes OFFLINE.", YELLOW))
    else:
        watch = "until_online"
        print()
        print(color("[!] Target is OFFLINE right now.", RED))
        print(color("[*] Will Discord you when it comes back ONLINE.", YELLOW))

    print()
    print(f"Poll interval : every {interval}s")
    print(f"Discord       : {'yes' if webhook else 'not configured - set on page 1'}")
    print()
    print(color("[1]", GREEN) + "  Keep watching in this terminal")
    print(color("[2]", CYAN) + "  Run in background (return to menu)")
    print(color("[3]", YELLOW) + "  Cancel")
    print()
    choice = input("Select > ").strip()

    if choice == "3" or choice.lower() in ("n", "no", "c", "cancel"):
        print(color("[*] Cancelled.", YELLOW))
        pause()
        return database

    if choice == "2":
        # Tag this IP only and start live background worker
        for e in database:
            if e.get("ip") == ip:
                e["live_enabled"] = True
                e["live_mode"] = watch
                e["last_status"] = status
                e["last_check"] = entry.get("last_check")
                e["last_info"] = entry.get("last_info") or {}
                e["last_ports"] = entry.get("last_ports") or {}
            # optional: only one active live target at a time
            elif e.get("live_enabled"):
                e["live_enabled"] = False
        save_database(vpn_ip, database)
        if live_background_running(vpn_ip):
            print(color("[*] Live background already running - updated target list.", YELLOW))
        else:
            pid = start_live_background(vpn_ip)
            if pid:
                print(color(f"[+] Live track running in background (PID {pid})", GREEN))
                print(color("[*] You can leave this tool / lab menu; Discord will alert on change.", CYAN))
            else:
                print(color("[!] Could not start background process.", RED))
        pause()
        return database

    # Default / [1]: foreground
    entry = live_track_one(vpn_ip, entry, webhook, settings, watch=watch)
    for i, e in enumerate(database):
        if e.get("ip") == entry.get("ip"):
            database[i] = entry
            # clear live tag if foreground finished
            database[i]["live_enabled"] = False
            break
    save_database(vpn_ip, database)
    pause()
    return database





# ============================================================
# MENU ACTIONS
# ============================================================

def add_ip(vpn_ip: str, database: List[dict]) -> List[dict]:
    if len(database) >= MAX_IPS_PER_CLIENT:
        print()
        print(color(f"[!] Max {MAX_IPS_PER_CLIENT} IPs per client.", RED))
        pause()
        return database

    print()
    ip = safe_input("IP address: ").strip()
    if not is_valid_ipv4(ip):
        print(color("[!] Invalid IPv4.", RED))
        pause()
        return database

    for entry in database:
        if entry.get("ip") == ip:
            print(color("[!] Already saved.", YELLOW))
            pause()
            return database

    label = safe_input("Label (optional): ").strip()[:64]
    ports_raw = safe_input("TCP ports to check (optional, e.g. 80,443,22): ").strip()
    ports = parse_ports(ports_raw)

    print(color("[*] Looking up IP information...", CYAN))
    info = get_ip_info(ip)
    ptr = reverse_dns(ip)
    display_target(ip, info, label=label, ptr=ptr)

    print(color("[*] Testing reachability...", CYAN))
    status, port_results = evaluate_reachability(ip, ports)
    print(
        color("[+] ONLINE", GREEN)
        if status == "online"
        else color("[!] OFFLINE / no response", YELLOW)
    )

    entry = {
        "ip": ip,
        "label": label,
        "tcp_ports": ",".join(str(p) for p in ports),
        "added": datetime.now(timezone.utc).isoformat(),
        "last_status": status,
        "last_check": datetime.now(timezone.utc).isoformat(),
        "last_info": info or {},
        "last_ports": port_results,
        "fail_streak": 0 if status == "online" else 1,
        "history": [],
    }
    database.append(entry)
    if save_database(vpn_ip, database):
        print(color("[+] IP saved.", GREEN))
    pause()
    return database


def bulk_add_ips(vpn_ip: str, database: List[dict]) -> List[dict]:
    print()
    print("Paste IPs (space or comma separated), then ENTER:")
    raw = safe_input("> ").strip()
    candidates = re.split(r"[\s,;]+", raw)
    added = 0
    for ip in candidates:
        if len(database) >= MAX_IPS_PER_CLIENT:
            print(color(f"[!] Hit max {MAX_IPS_PER_CLIENT}.", YELLOW))
            break
        if not is_valid_ipv4(ip):
            continue
        if any(e.get("ip") == ip for e in database):
            continue
        database.append(
            {
                "ip": ip,
                "label": "",
                "tcp_ports": "",
                "added": datetime.now(timezone.utc).isoformat(),
                "last_status": "unknown",
                "last_check": "",
                "last_info": {},
                "fail_streak": 0,
                "history": [],
            }
        )
        added += 1
    if added and save_database(vpn_ip, database):
        print(color(f"[+] Added {added} IP(s).", GREEN))
    else:
        print(color("[*] Nothing new added.", YELLOW))
    pause()
    return database


def remove_ip(vpn_ip: str, database: List[dict]) -> List[dict]:
    if not database:
        print(color("[!] No saved IPs.", YELLOW))
        pause()
        return database
    print()
    for index, entry in enumerate(database, start=1):
        lab = entry.get("label") or ""
        print(f"[{index}] {entry.get('ip', '?')}" + (f"  ({lab})" if lab else ""))
    selection = safe_input("\nNumber to remove: ").strip()
    try:
        number = int(selection)
        if number < 1 or number > len(database):
            raise ValueError
    except ValueError:
        print(color("[!] Invalid selection.", RED))
        pause()
        return database
    removed = database.pop(number - 1)
    if save_database(vpn_ip, database):
        print(color(f"[+] Removed {removed.get('ip')}.", GREEN))
    pause()
    return database


def list_ips(database: List[dict]) -> None:
    print()
    if not database:
        print(color("No IP addresses have been saved.", YELLOW))
        pause()
        return
    online, offline, unknown = count_statuses(database)
    print(color("════════════════════════════════════════════════════════", CYAN))
    print(color("                    SAVED IPS", CYAN))
    print(color(f"  online={online}  offline={offline}  unknown={unknown}", WHITE))
    print(color("════════════════════════════════════════════════════════", CYAN))
    for index, entry in enumerate(database, start=1):
        ip = entry.get("ip", "Unknown")
        label = entry.get("label") or ""
        status = entry.get("last_status", "unknown")
        live = " ⚡LIVE" if entry.get("live_enabled") else ""
        mode = entry.get("live_mode") or ""
        extra = f"  {label}" if label else ""
        if live:
            extra += live + (f"({mode})" if mode else "")
        print(f"[{index}] {ip:<18} {format_status_line(status)}{extra}")
    pause()


def select_ip(database: List[dict]) -> Optional[dict]:
    if not database:
        print(color("[!] No saved IPs.", YELLOW))
        pause()
        return None
    print()
    for index, entry in enumerate(database, start=1):
        lab = entry.get("label") or ""
        print(f"[{index}] {entry.get('ip', '?')}" + (f"  ({lab})" if lab else ""))
    print("[0] Cancel")
    selection = safe_input("\nSelect IP: ").strip()
    if selection in ("0", "b", "B", "q", ""):
        return None
    try:
        number = int(selection)
        if number < 1 or number > len(database):
            raise ValueError
        return database[number - 1]
    except ValueError:
        print(color("[!] Invalid selection.", RED))
        pause()
        return None


def check_saved_ip(vpn_ip: str, database: List[dict], webhook: str) -> List[dict]:
    entry = select_ip(database)
    if not entry:
        return database
    settings = load_settings(vpn_ip)
    ports = parse_ports(entry.get("tcp_ports") or "") or parse_ports(
        settings.get("default_tcp_ports") or ""
    )
    result = check_ip(
        entry["ip"],
        webhook=webhook,
        send_notification=True,
        label=entry.get("label") or "",
        tcp_ports=ports,
        do_ptr=True,
        force_notify=True,
        entry=entry,
        settings=settings,
    )
    old_status = entry.get("last_status")
    new_status = result["status"]
    if webhook and old_status and old_status != new_status:
        d = info_values(result.get("info") or {})
        lab = entry.get("label") or ""
        lab_line = f"**Label:** `{lab}`\n" if lab else ""
        if new_status == "online":
            send_discord(
                webhook,
                "Surveillance - ONLINE",
                (
                    f"{lab_line}"
                    f"**Target:** `{entry['ip']}`\n"
                    f"**Status:** 🟢 ONLINE\n"
                    f"**Time:** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`\n"
                    f"**Owner:** `{get_display_user()}`\n\n"
                    f"**ISP:** `{d['isp']}`\n"
                    f"**Organization:** `{d.get('org', d['isp'])}`\n"
                    f"**ASN:** `{d['asn']}`\n"
                    f"**Country:** `{d['country']}`\n"
                    f"**Region:** `{d.get('region', 'Unknown')}`\n"
                    f"**City:** `{d['city']}`"
                ),
                DISCORD_GREEN,
            )
        else:
            send_discord(
                webhook,
                "Surveillance - OFFLINE",
                (
                    f"{lab_line}"
                    f"**Target:** `{entry['ip']}`\n"
                    f"**Status:** 🔴 OFFLINE\n"
                    f"**Time:** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`\n"
                    f"**Owner:** `{get_display_user()}`\n\n"
                    f"**ISP:** `{d['isp']}`\n"
                    f"**Organization:** `{d.get('org', d['isp'])}`\n"
                    f"**ASN:** `{d['asn']}`\n"
                    f"**Country:** `{d['country']}`\n"
                    f"**Region:** `{d.get('region', 'Unknown')}`\n"
                    f"**City:** `{d['city']}`"
                ),
                DISCORD_RED,
            )
    entry["last_status"] = new_status
    entry["last_check"] = result["timestamp"]
    entry["last_info"] = result["info"] or {}
    entry["last_ports"] = result.get("ports") or {}
    save_database(vpn_ip, database)
    pause()
    return database


def edit_label_ports(vpn_ip: str, database: List[dict]) -> List[dict]:
    entry = select_ip(database)
    if not entry:
        return database
    print(f"Current label: {entry.get('label') or '(none)'}")
    label = safe_input("New label (ENTER keep): ").strip()
    if label:
        entry["label"] = label[:64]
    print(f"Current TCP ports: {entry.get('tcp_ports') or '(none)'}")
    ports = safe_input("New TCP ports (ENTER keep, '-' clear): ").strip()
    if ports == "-":
        entry["tcp_ports"] = ""
    elif ports:
        entry["tcp_ports"] = ",".join(str(p) for p in parse_ports(ports))
    save_database(vpn_ip, database)
    print(color("[+] Updated.", GREEN))
    pause()
    return database


def lookup_ip_tool(database: List[dict]) -> None:
    print()
    print("[1] Type an IP")
    print("[2] Pick saved IP")
    print("[0] Cancel")
    choice = safe_input("Select: ").strip()
    if choice in ("0", "b", "B", "q", ""):
        return
    ip = ""
    label = ""
    if choice == "2":
        entry = select_ip(database)
        if not entry:
            return
        ip = entry["ip"]
        label = entry.get("label") or ""
    elif choice == "1":
        ip = safe_input("IP: ").strip()
        if not is_valid_ipv4(ip):
            print(color("[!] Invalid IP.", RED))
            pause()
            return
    else:
        print(color("[!] Invalid option.", RED))
        pause()
        return
    info = get_ip_info(ip)
    ptr = reverse_dns(ip)
    status, _ = evaluate_reachability(ip, [])
    display_target(ip, info, status, label=label, ptr=ptr)
    pause()


def traceroute_tool(database: List[dict]) -> None:
    print()
    print("[1] Type an IP")
    print("[2] Pick saved IP")
    print("[0] Cancel")
    choice = safe_input("Select: ").strip()
    if choice in ("0", "b", "B", "q", ""):
        return
    if choice == "2":
        entry = select_ip(database)
        if not entry:
            return
        ip = entry["ip"]
    elif choice == "1":
        ip = safe_input("IP: ").strip()
        if not is_valid_ipv4(ip):
            print(color("[!] Invalid IP.", RED))
            pause()
            return
    else:
        print(color("[!] Invalid option.", RED))
        pause()
        return
    print(color(f"[*] Traceroute to {ip} ...", CYAN))
    print(traceroute_ip(ip))
    pause()


def configure_discord(vpn_ip: str) -> None:
    current = load_webhook(vpn_ip)
    print()
    if current:
        print(color("[+] Discord webhook is configured.", GREEN))
        print("The webhook itself is hidden.")
        if safe_input("\nReplace it? [y/N]: ").strip().lower() != "y":
            return
    print()
    webhook = safe_input("Enter Discord webhook: ").strip()
    if not webhook.startswith("https://discord.com/api/webhooks/"):
        print(color("[!] Invalid Discord webhook URL.", RED))
        pause()
        return
    if save_webhook(vpn_ip, webhook):
        print(color("[+] Webhook saved for this VPN client.", GREEN))
        if safe_input("Send test notification? [y/N]: ").strip().lower() == "y":
            ok = send_discord(
                webhook,
                "⚠️ SURVEILLANCE",
                "🟢 Discord webhook configured successfully.\n"
                f"**Owner:** `{get_display_user()}`\n"
                f"**VPN client:** `{vpn_ip}`",
                DISCORD_CYAN,
            )
            print(color("[+] Test sent.", GREEN) if ok else color("[!] Test failed.", RED))
    pause()


def configure_settings(vpn_ip: str) -> None:
    settings = load_settings(vpn_ip)
    print()
    print(color("MONITOR SETTINGS", CYAN))
    print(f"Interval hours     : {settings['interval_hours']}")
    print(f"Change-only alerts : {settings['change_only']}")
    print(f"Multi-fail         : {settings['multi_fail']}")
    print(f"Alert cooldown sec : {settings['alert_cooldown_sec']}")
    print(f"Default TCP ports  : {settings.get('default_tcp_ports') or '(none)'}")
    print(f"Live poll seconds  : {settings.get('live_interval_sec', DEFAULT_LIVE_INTERVAL_SEC)}")
    print()
    raw = safe_input(f"Interval hours [{MIN_INTERVAL_HOURS}-{MAX_INTERVAL_HOURS}] ENTER=keep: ").strip()
    if raw:
        try:
            val = int(raw)
            if MIN_INTERVAL_HOURS <= val <= MAX_INTERVAL_HOURS:
                settings["interval_hours"] = val
        except ValueError:
            pass
    raw = safe_input("Change-only alerts y/n ENTER=keep: ").strip().lower()
    if raw in ("y", "n"):
        settings["change_only"] = raw == "y"
    raw = safe_input("Multi-fail count 1-5 ENTER=keep: ").strip()
    if raw:
        try:
            settings["multi_fail"] = max(1, min(5, int(raw)))
        except ValueError:
            pass
    raw = safe_input("Alert cooldown seconds ENTER=keep: ").strip()
    if raw:
        try:
            settings["alert_cooldown_sec"] = max(0, int(raw))
        except ValueError:
            pass
    raw = safe_input("Default TCP ports (e.g. 80,443) ENTER=keep '-'=clear: ").strip()
    if raw == "-":
        settings["default_tcp_ports"] = ""
    elif raw:
        settings["default_tcp_ports"] = ",".join(str(p) for p in parse_ports(raw))
    raw = safe_input(
        f"Live track poll seconds [{MIN_LIVE_INTERVAL_SEC}-{MAX_LIVE_INTERVAL_SEC}] ENTER=keep: "
    ).strip()
    if raw:
        try:
            val = int(raw)
            if MIN_LIVE_INTERVAL_SEC <= val <= MAX_LIVE_INTERVAL_SEC:
                settings["live_interval_sec"] = val
        except ValueError:
            pass
    if save_settings(vpn_ip, settings):
        print(color("[+] Settings saved.", GREEN))
    pause()


def show_monitor_status(vpn_ip: str) -> None:
    settings = load_settings(vpn_ip)
    running = background_running(vpn_ip)
    pid = read_pid(vpn_ip)
    print()
    print(color("════════════════════════════════════════════════════════", CYAN))
    print(color("                 MONITOR STATUS", CYAN))
    print(color("════════════════════════════════════════════════════════", CYAN))
    print(f"VPN Client : {vpn_ip}")
    print(f"Owner      : {get_display_user()}")
    print(f"Interval   : {settings['interval_hours']} hour(s)")
    print(f"Change-only: {settings['change_only']}")
    print(f"Multi-fail : {settings['multi_fail']}")
    if running:
        print(f"Status     : {color('RUNNING IN BACKGROUND', GREEN)}")
        print(f"PID        : {pid}")
    else:
        print(f"Status     : {color('NOT RUNNING', YELLOW)}")
    live_run = live_background_running(vpn_ip)
    live_pid = read_live_pid(vpn_ip)
    print(f"Live poll  : every {settings.get('live_interval_sec', DEFAULT_LIVE_INTERVAL_SEC)}s")
    if live_run:
        print(f"Live track : {color('BACKGROUND RUNNING', GREEN)}  PID {live_pid}")
    else:
        print(f"Live track : {color('NOT RUNNING', YELLOW)}")
    print(f"Log file   : {log_file(vpn_ip)}")
    pause()


def foreground_monitor(vpn_ip: str, database: List[dict], webhook: str) -> List[dict]:
    while True:
        settings = load_settings(vpn_ip)
        seconds = settings["interval_hours"] * 3600
        print(
            color(
                f"[*] Next check in {settings['interval_hours']} hour(s). "
                f"Type q+ENTER to stop.",
                YELLOW,
            )
        )
        if wait_interruptible(seconds):
            print()
            print(color("[*] Foreground monitoring stopped - back to menu.", YELLOW))
            break
        print()
        database = run_monitoring_cycle(vpn_ip, database, webhook)
    return database


def start_monitoring(vpn_ip: str, database: List[dict], webhook: str) -> List[dict]:
    if not database:
        print(color("[!] You have no saved IPs.", YELLOW))
        pause()
        return database
    settings = load_settings(vpn_ip)
    print()
    print(color("MONITORING STARTED", GREEN))
    print(f"Saved targets : {len(database)}")
    print(f"Interval      : {settings['interval_hours']} hour(s)")
    database = run_monitoring_cycle(vpn_ip, database, webhook)
    print()
    print("[1] Keep monitoring in this terminal")
    print("[2] Run monitoring in background")
    print("[3] Stop and return to menu")
    choice = safe_input("\nSelect > ").strip()
    if choice == "1":
        return foreground_monitor(vpn_ip, database, webhook)
    if choice == "2":
        pid = start_background_monitor(vpn_ip)
        if pid:
            print(color(f"[+] Background monitor started PID {pid}", GREEN))
        pause("\nPress ENTER to return to menu...")
        return database
    print(color("[*] Monitoring stopped.", YELLOW))
    pause("\nPress ENTER to return to menu...")
    return database


def admin_pick_vpn_ip() -> Optional[str]:
    """Root/owner: pick a client IP from access_rules when env identity is missing."""
    rules = load_json(RULES_FILE, {})
    users = rules.get("users") if isinstance(rules, dict) else None
    if not isinstance(users, dict) or not users:
        print(color("[!] No access_rules users found.", RED))
        return None
    rows = []
    for vpn_ip, rule in users.items():
        if not is_client_vpn_ip(vpn_ip):
            continue
        name = (rule or {}).get("display_name") or (rule or {}).get("app_username") or "?"
        rows.append((vpn_ip, name))
    if not rows:
        print(color("[!] No client VPN IPs in rules.", RED))
        return None
    print()
    print(color("ADMIN - select client identity", MAGENTA))
    for i, (vip, name) in enumerate(rows, start=1):
        print(f"[{i}] {vip}  ({name})")
    sel = safe_input("\nSelect: ").strip()
    try:
        idx = int(sel)
        if 1 <= idx <= len(rows):
            return rows[idx - 1][0]
    except ValueError:
        pass
    print(color("[!] Invalid.", RED))
    return None


# ============================================================
# MAIN
# ============================================================

def print_status_header(vpn_ip: str, vpn_source: str, database: List[dict], webhook: str) -> None:
    settings = load_settings(vpn_ip)
    running = background_running(vpn_ip)
    online, offline, unknown = count_statuses(database)
    print(BANNER)
    print(f"VPN Client IP : {color(vpn_ip, GREEN)}")
    print(f"Detection     : {vpn_source}")
    print(f"Owner         : {get_display_user()}")
    print(
        f"Saved IPs     : {len(database)}  "
        f"({color(str(online), GREEN)} up / {color(str(offline), RED)} down / {unknown} ?)"
    )
    print(f"Check Interval: {settings['interval_hours']} hour(s)")
    live_run = live_background_running(vpn_ip)
    tracked = sum(1 for e in database if e.get("live_enabled"))
    print(
        "Monitor       : "
        + (color("RUNNING IN BACKGROUND", GREEN) if running else color("NOT RUNNING", YELLOW))
    )
    print(
        "Live track    : "
        + (
            color(f"BACKGROUND ON ({tracked} target)", GREEN)
            if live_run
            else color("NOT RUNNING", YELLOW)
        )
    )
    print(
        "Discord       : "
        + (color("Configured", GREEN) if webhook else color("Not configured", RED))
    )
    print(f"Change-only   : {settings['change_only']}  |  Multi-fail: {settings['multi_fail']}")
    print(color("════════════════════════════════════════════════════════", CYAN))


def show_menu_page1() -> None:
    print(color("PAGE 1 · TARGETS", CYAN))
    print()
    print(color("[1]", CYAN) + "  Add IP")
    print(color("[2]", CYAN) + "  Bulk add IPs")
    print(color("[3]", CYAN) + "  Saved IPs")
    print(color("[4]", CYAN) + "  Check saved IP")
    print(color("[5]", CYAN) + "  Edit label / TCP ports")
    print(color("[6]", CYAN) + "  Remove saved IP")
    print(color("[7]", CYAN) + "  IP lookup (geo + rDNS)")
    print(color("[8]", CYAN) + "  Traceroute")
    print(color("[9]", MAGENTA) + "  Configure Discord webhook")
    print()
    print(color("[0]", YELLOW) + "  Next page -> Monitor / Live")
    print(color("[B]", RED) + "  Back to lab menu")


def show_menu_page2(vpn_ip: str = "", database: Optional[List[dict]] = None) -> None:
    live_on = live_background_running(vpn_ip) if vpn_ip else False
    print(color("PAGE 2 · MONITOR & LIVE", CYAN))
    print()
    print(color("[1]", CYAN) + "  Monitor settings")
    print(color("[2]", GREEN) + "  Start monitoring (hourly)")
    print(color("[3]", CYAN) + "  Monitor status")
    print(color("[4]", YELLOW) + "  Stop background monitor")
    print()
    print(color("[5]", MAGENTA) + "  LIVE track IP  (auto online/offline + Discord)")
    if live_on:
        print(color("[6]", YELLOW) + "  Stop LIVE background  " + color("(RUNNING)", GREEN))
    else:
        print(color("[6]", YELLOW) + "  Stop LIVE background")
    print()
    print(color("[0]", YELLOW) + "  Previous page -> Targets")
    print(color("[B]", RED) + "  Back to lab menu")


def main() -> int:
    install_signal_guards()
    initialize_directories()

    vpn_ip, vpn_source = get_vpn_ip()
    if not vpn_ip:
        print(color("[!] Could not determine a valid VPN *client* IP.", RED))
        print()
        print("This tool must run from the lab menu so it inherits:")
        print("    DEDSEC_SOURCE_IP=<your 10.8.0.x client address>")
        print()
        print(color("YOUR_LAB_VPN_IP is the server and is never used as client ID.", YELLOW))
        print()
        if os.geteuid() == 0:
            print("Root/admin: pick a client from access_rules?")
            if safe_input("[y/N]: ").strip().lower() == "y":
                vpn_ip = admin_pick_vpn_ip()
                vpn_source = "admin:access_rules"
        if not vpn_ip:
            return 1

    database = load_database(vpn_ip)
    webhook = load_webhook(vpn_ip)
    page = 1

    while True:
        try:
            clear_screen()
            print_status_header(vpn_ip, vpn_source, database, webhook)
            if page == 1:
                show_menu_page1()
            else:
                show_menu_page2(vpn_ip, database)
            print()
            print(color("Tip: 0/B = back · Ctrl+C = cancel to this menu", YELLOW))
            choice = safe_input("Select an option > ").strip().lower()

            if choice in ("b", "back", "q", "quit"):
                save_database(vpn_ip, database)
                clear_screen()
                print(color("[+] Returning to lab menu.", CYAN))
                return 0

            if page == 1:
                if choice == "0":
                    page = 2
                    continue
                if choice == "1":
                    database = add_ip(vpn_ip, database)
                elif choice == "2":
                    database = bulk_add_ips(vpn_ip, database)
                elif choice == "3":
                    list_ips(database)
                elif choice == "4":
                    database = check_saved_ip(vpn_ip, database, webhook)
                elif choice == "5":
                    database = edit_label_ports(vpn_ip, database)
                elif choice == "6":
                    database = remove_ip(vpn_ip, database)
                elif choice == "7":
                    lookup_ip_tool(database)
                elif choice == "8":
                    traceroute_tool(database)
                elif choice == "9":
                    configure_discord(vpn_ip)
                    webhook = load_webhook(vpn_ip)
                else:
                    print(color("[!] Invalid option.", RED))
                    time.sleep(0.8)
            else:
                if choice == "0":
                    page = 1
                    continue
                if choice == "1":
                    configure_settings(vpn_ip)
                elif choice == "2":
                    database = start_monitoring(vpn_ip, database, webhook)
                elif choice == "3":
                    show_monitor_status(vpn_ip)
                elif choice == "4":
                    stop_background_monitor(vpn_ip)
                    pause()
                elif choice == "5":
                    database = menu_live_track_one(vpn_ip, database, webhook)
                elif choice == "6":
                    stop_live_background(vpn_ip)
                    for e in database:
                        e["live_enabled"] = False
                    save_database(vpn_ip, database)
                    pause()
                else:
                    print(color("[!] Invalid option.", RED))
                    time.sleep(0.8)
        except MenuBack:
            try:
                database = load_database(vpn_ip)
                webhook = load_webhook(vpn_ip)
            except Exception:
                pass
            continue


if __name__ == "__main__":
    install_signal_guards()
    initialize_directories()

    if len(sys.argv) >= 2 and sys.argv[1] == "--background":
        vpn_ip, _ = get_vpn_ip()
        if not vpn_ip:
            sys.exit(1)
        try:
            background_worker(vpn_ip)
        except Exception:
            remove_pid(vpn_ip)
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] == "--live-background":
        vpn_ip, _ = get_vpn_ip()
        if not vpn_ip:
            sys.exit(1)
        try:
            live_background_worker(vpn_ip)
        except Exception:
            remove_live_pid(vpn_ip)
        sys.exit(0)

    try:
        sys.exit(main())
    except Exception as error:
        print()
        print(color(f"[!] Fatal error: {error}", RED))
        sys.exit(1)


