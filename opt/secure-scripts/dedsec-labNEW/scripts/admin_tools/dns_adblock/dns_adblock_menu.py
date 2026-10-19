#!/usr/bin/env python3
"""
DEDSEC DNS Ad Blocker - user menu (lab tool)

Identity: DEDSEC_SOURCE_IP / SECURE_VPN_IP (10.8.0.2-254 only).
Does NOT bind port 53 - only toggles per-client state for the daemon.

Path:
  /opt/secure-scripts/dedsec-labNEW/scripts/misc_tools/dns_adblock_menu.py
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional, Set, Tuple

# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path("/opt/secure-scripts/dedsec-labNEW")
STATE_DIR = BASE_DIR / "adblock_state"
ENABLED_FILE = STATE_DIR / "enabled_clients.json"
CUSTOM_BLOCKS_DIR = STATE_DIR / "custom_blocks"
CUSTOM_ALLOWS_DIR = STATE_DIR / "custom_allows"
CLIENT_INDEX = STATE_DIR / "client_index.json"
STATS_FILE = STATE_DIR / "stats.json"
RECENT_FILE = STATE_DIR / "recent_blocks.json"
RULES_FILE = BASE_DIR / "access_rules.json"

SERVER_VPN_IP = "YOUR_LAB_VPN_IP"
DAEMON_SERVICE = "dedsec-dns-adblock.service"

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


def color(text: str, c: str) -> str:
    return f"{c}{text}{RESET}"


BANNER = r"""
██████╗ ███████╗██████╗ ███████╗███████╗ ██████╗
██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝
██║  ██║█████╗  ██║  ██║███████╗█████╗  ██║
██║  ██║██╔══╝  ██║  ██║╚════██║██╔══╝  ██║
██████╔╝███████╗██████╔╝███████║███████╗╚██████╗
╚═════╝ ╚══════╝╚═════╝ ╚══════╝╚══════╝ ╚═════╝

            DNS AD BLOCKER  •  VPN
════════════════════════════════════════════════════════
"""


# ============================================================
# IDENTITY
# ============================================================

def is_valid_ipv4(ip: str) -> bool:
    if not ip or not re.match(
        r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$",
        ip,
    ):
        return False
    return True


def is_client_vpn_ip(ip: str) -> bool:
    if not is_valid_ipv4(ip) or ip == SERVER_VPN_IP:
        return False
    a, b, c, d = (int(x) for x in ip.split("."))
    return a == 10 and b == 8 and c == 0 and 2 <= d <= 254


def get_vpn_ip() -> Tuple[Optional[str], Optional[str]]:
    for var in ("SECURE_VPN_IP", "DEDSEC_SOURCE_IP", "VPN_IP", "CLIENT_VPN_IP"):
        value = (os.environ.get(var) or "").strip()
        if is_client_vpn_ip(value):
            return value, f"environment:{var}"
    return None, None


def get_display_user() -> str:
    return (
        (os.environ.get("DEDSEC_USER") or "").strip()
        or (os.environ.get("DEDSEC_SSH_USER") or "").strip()
        or "unknown"
    )


def client_hash(vpn_ip: str) -> str:
    return hashlib.sha256(vpn_ip.encode("utf-8")).hexdigest()[:32]


# ============================================================
# STATE HELPERS
# ============================================================

def ensure_dirs() -> None:
    for d in (STATE_DIR, CUSTOM_BLOCKS_DIR, CUSTOM_ALLOWS_DIR):
        d.mkdir(parents=True, exist_ok=True)


def load_json(path: Path, default: Any) -> Any:
    try:
        if not path.exists():
            return default
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def save_json(path: Path, data: Any) -> bool:
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o660)
        except PermissionError:
            pass
        return True
    except Exception as e:
        print(color(f"[!] Save failed: {e}", RED))
        try:
            if tmp.exists():
                tmp.unlink()
        except Exception:
            pass
        return False


def update_client_index(vpn_ip: str) -> None:
    index = load_json(CLIENT_INDEX, {})
    if not isinstance(index, dict):
        index = {}
    index[client_hash(vpn_ip)] = vpn_ip
    save_json(CLIENT_INDEX, index)


def load_enabled_set() -> Set[str]:
    data = load_json(ENABLED_FILE, {"clients": []})
    if isinstance(data, dict):
        return set(data.get("clients") or [])
    if isinstance(data, list):
        return set(data)
    return set()


def save_enabled_set(clients: Set[str]) -> bool:
    return save_json(
        ENABLED_FILE,
        {
            "version": 1,
            "updated": datetime.now(timezone.utc).isoformat(),
            "clients": sorted(clients),
        },
    )


def is_enabled(vpn_ip: str) -> bool:
    return vpn_ip in load_enabled_set()


def set_enabled(vpn_ip: str, on: bool) -> bool:
    clients = load_enabled_set()
    if on:
        clients.add(vpn_ip)
    else:
        clients.discard(vpn_ip)
    update_client_index(vpn_ip)
    return save_enabled_set(clients)


def custom_path(kind: str, vpn_ip: str) -> Path:
    folder = CUSTOM_BLOCKS_DIR if kind == "block" else CUSTOM_ALLOWS_DIR
    return folder / f"{client_hash(vpn_ip)}.json"


def load_custom(kind: str, vpn_ip: str) -> List[str]:
    data = load_json(custom_path(kind, vpn_ip), {"domains": []})
    domains = data.get("domains") if isinstance(data, dict) else []
    return sorted(set(str(d).lower().rstrip(".") for d in (domains or []) if d))


def save_custom(kind: str, vpn_ip: str, domains: List[str]) -> bool:
    update_client_index(vpn_ip)
    return save_json(
        custom_path(kind, vpn_ip),
        {
            "vpn_ip": vpn_ip,
            "owner": get_display_user(),
            "domains": sorted(set(domains)),
            "updated": datetime.now(timezone.utc).isoformat(),
        },
    )


def daemon_running() -> bool:
    # Prefer systemd
    try:
        r = subprocess.run(
            ["systemctl", "is-active", "--quiet", DAEMON_SERVICE],
            capture_output=True,
        )
        if r.returncode == 0:
            return True
    except Exception:
        pass
    # Fallback: something listening on YOUR_LAB_VPN_IP:53
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.3)
        # connect doesn't send for UDP but checks route; use ss via subprocess
        s.close()
        r = subprocess.run(
            ["ss", "-ulnp"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        return "YOUR_LAB_VPN_IP:53" in (r.stdout or "")
    except Exception:
        return False


def load_stats() -> dict:
    return load_json(STATS_FILE, {})


def load_recent_for_client(vpn_ip: str, limit: int = 15) -> List[dict]:
    recent = load_json(RECENT_FILE, [])
    if not isinstance(recent, list):
        return []
    rows = [x for x in recent if isinstance(x, dict) and x.get("client") == vpn_ip]
    return rows[-limit:]


def normalize_domain(raw: str) -> Optional[str]:
    d = raw.strip().lower().rstrip(".")
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0].split(":")[0]
    if not d or "." not in d or len(d) > 253:
        return None
    if not re.match(r"^[a-z0-9.-]+$", d):
        return None
    return d


def test_domain_local(domain: str, vpn_ip: str) -> str:
    """Best-effort: ask daemon path by checking lists only (no live DNS required)."""
    # Whitelist
    if domain in load_custom("allow", vpn_ip) or any(
        domain.endswith("." + a) for a in load_custom("allow", vpn_ip)
    ):
        return "ALLOWED (your whitelist)"
    if domain in load_custom("block", vpn_ip) or any(
        domain.endswith("." + b) for b in load_custom("block", vpn_ip)
    ):
        return "BLOCKED (your custom list)"
    stats = load_stats()
    size = stats.get("blocklist_size")
    if not is_enabled(vpn_ip):
        return "WOULD FORWARD (adblock OFF for you)"
    # We cannot see full blocklist from menu without a shared dump;
    # tell user to use live DNS test if daemon is up.
    return f"Check live DNS (blocklist size on daemon: {size or '?'})"


def live_dns_test(domain: str) -> str:
    """Query YOUR_LAB_VPN_IP and show answer."""
    try:
        from dnslib import DNSRecord, QTYPE, DNSHeader, DNSQuestion
    except ImportError:
        return "dnslib not installed in this environment"
    try:
        q = DNSRecord(DNSHeader(q=1), q=DNSQuestion(domain, QTYPE.A))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(q.pack(), (SERVER_VPN_IP, 53))
        data, _ = sock.recvfrom(4096)
        sock.close()
        reply = DNSRecord.parse(data)
        answers = []
        for rr in reply.rr:
            answers.append(str(rr.rdata))
        if not answers:
            return "No A records (empty / blocked-style reply)"
        if answers == ["0.0.0.0"] or all(a == "0.0.0.0" for a in answers):
            return "BLOCKED -> 0.0.0.0"
        return "ALLOWED -> " + ", ".join(answers[:5])
    except Exception as e:
        return f"DNS test failed: {e}"


def admin_pick_vpn_ip() -> Optional[str]:
    rules = load_json(RULES_FILE, {})
    users = rules.get("users") if isinstance(rules, dict) else None
    if not isinstance(users, dict):
        print(color("[!] No access_rules users.", RED))
        return None
    rows = []
    for vip, rule in users.items():
        if is_client_vpn_ip(vip):
            name = (rule or {}).get("display_name") or (rule or {}).get("app_username") or "?"
            rows.append((vip, name))
    if not rows:
        return None
    print(color("ADMIN - select VPN client", MAGENTA))
    for i, (vip, name) in enumerate(rows, 1):
        print(f"[{i}] {vip}  ({name})")
    sel = input("Select: ").strip()
    try:
        idx = int(sel)
        if 1 <= idx <= len(rows):
            return rows[idx - 1][0]
    except ValueError:
        pass
    return None


# ============================================================
# MENU ACTIONS
# ============================================================

def show_status(vpn_ip: str) -> None:
    on = is_enabled(vpn_ip)
    svc = daemon_running()
    stats = load_stats()
    print()
    print(color("════════════════════════════════════════", CYAN))
    print(color("              STATUS", CYAN))
    print(color("════════════════════════════════════════", CYAN))
    print(f"VPN client     : {vpn_ip}")
    print(f"Owner          : {get_display_user()}")
    print(
        f"Adblock for you: "
        + (color("ON", GREEN) if on else color("OFF", YELLOW))
    )
    print(
        f"DNS daemon     : "
        + (color("RUNNING", GREEN) if svc else color("NOT RUNNING", RED))
    )
    print(f"Blocklist size : {stats.get('blocklist_size', '?')}")
    print(f"Global blocked : {stats.get('blocked', '?')}")
    print(f"Global allowed : {stats.get('allowed', '?')}")
    print(f"Custom blocks  : {len(load_custom('block', vpn_ip))}")
    print(f"Custom allows  : {len(load_custom('allow', vpn_ip))}")
    print()
    print(color("How to use on your devices:", YELLOW))
    print(f"  Set DNS to {SERVER_VPN_IP} (OpenVPN should push this).")
    print("  Windows: often needs reconnect after enable.")
    print("  Phone: use VPN app DNS = " + SERVER_VPN_IP)
    input("\nPress ENTER...")


def enable_adblock(vpn_ip: str) -> None:
    if set_enabled(vpn_ip, True):
        print(color("\n[+] Adblock ENABLED for your VPN IP.", GREEN))
        print(f"    Client: {vpn_ip}")
        print(f"    DNS:    {SERVER_VPN_IP}")
        if not daemon_running():
            print(color("[!] DNS daemon is not running - ask admin to start it.", RED))
        else:
            print("    Changes apply within a few seconds.")
    input("\nPress ENTER...")


def disable_adblock(vpn_ip: str) -> None:
    if set_enabled(vpn_ip, False):
        print(color("\n[+] Adblock DISABLED for your VPN IP.", YELLOW))
        print("    DNS still works; ads are no longer filtered.")
    input("\nPress ENTER...")


def add_custom(vpn_ip: str, kind: str) -> None:
    label = "block" if kind == "block" else "allow (whitelist)"
    print(f"\nAdd domain to {label} list")
    print("Examples: ads.example.com  doubleclick.net")
    raw = input("Domain: ").strip()
    domain = normalize_domain(raw)
    if not domain:
        print(color("[!] Invalid domain.", RED))
        input("\nPress ENTER...")
        return
    domains = load_custom(kind, vpn_ip)
    if domain in domains:
        print(color("[!] Already on list.", YELLOW))
    else:
        domains.append(domain)
        if save_custom(kind, vpn_ip, domains):
            print(color(f"[+] Added {domain}", GREEN))
    input("\nPress ENTER...")


def remove_custom(vpn_ip: str, kind: str) -> None:
    domains = load_custom(kind, vpn_ip)
    if not domains:
        print(color("\n[!] List empty.", YELLOW))
        input("\nPress ENTER...")
        return
    print()
    for i, d in enumerate(domains, 1):
        print(f"[{i}] {d}")
    sel = input("Number to remove: ").strip()
    try:
        idx = int(sel)
        if 1 <= idx <= len(domains):
            removed = domains.pop(idx - 1)
            save_custom(kind, vpn_ip, domains)
            print(color(f"[+] Removed {removed}", GREEN))
        else:
            print(color("[!] Invalid.", RED))
    except ValueError:
        print(color("[!] Invalid.", RED))
    input("\nPress ENTER...")


def list_custom(vpn_ip: str) -> None:
    print()
    print(color("CUSTOM BLOCKS", RED))
    blocks = load_custom("block", vpn_ip)
    print("\n".join(f"  • {d}" for d in blocks) if blocks else "  (none)")
    print()
    print(color("CUSTOM ALLOWS (whitelist)", GREEN))
    allows = load_custom("allow", vpn_ip)
    print("\n".join(f"  • {d}" for d in allows) if allows else "  (none)")
    input("\nPress ENTER...")


def test_domain(vpn_ip: str) -> None:
    print()
    domain = normalize_domain(input("Domain to test: ").strip() or "")
    if not domain:
        print(color("[!] Invalid domain.", RED))
        input("\nPress ENTER...")
        return
    print(color(f"\n[*] Testing {domain} ...", CYAN))
    print(f"Local rules : {test_domain_local(domain, vpn_ip)}")
    if daemon_running():
        print(f"Live DNS    : {live_dns_test(domain)}")
    else:
        print(color("Live DNS    : daemon not running", YELLOW))
    print()
    print(color("Note:", YELLOW))
    print("  YouTube/Netflix in-stream ads often share CDN domains with video.")
    print("  DNS blocking removes many trackers/ad networks; not 100% of video ads.")
    input("\nPress ENTER...")


def show_recent(vpn_ip: str) -> None:
    rows = load_recent_for_client(vpn_ip)
    print()
    print(color("RECENT BLOCKS (your client)", CYAN))
    if not rows:
        print("  (none yet - enable adblock and browse)")
    else:
        for r in reversed(rows):
            ts = r.get("ts")
            try:
                tstr = datetime.fromtimestamp(float(ts)).strftime("%H:%M:%S")
            except Exception:
                tstr = "?"
            print(f"  [{tstr}] {r.get('domain')} ({r.get('qtype')})")
    input("\nPress ENTER...")


def show_help() -> None:
    print()
    print(color("SETUP / TIPS", CYAN))
    print(
        f"""
1. Admin must run the DNS daemon on {SERVER_VPN_IP}:53
2. OpenVPN should push DNS:
     push "dhcp-option DNS {SERVER_VPN_IP}"
3. You ENABLE adblock here for YOUR VPN IP only
4. Other users are unaffected until they enable
5. Custom allow list overrides block (use if a site breaks)
6. Limits of DNS adblock:
   - Great for banners, trackers, many ad domains
   - YouTube/Netflix video ads are only partially blocked
     (same servers as the video stream)
"""
    )
    input("Press ENTER...")


# ============================================================
# MAIN
# ============================================================

def main() -> int:
    ensure_dirs()

    vpn_ip, source = get_vpn_ip()
    if not vpn_ip:
        print(color("[!] No valid VPN client IP (need 10.8.0.2-254).", RED))
        print("    Run this from the lab menu so DEDSEC_SOURCE_IP is set.")
        if os.geteuid() == 0:
            if input("Admin pick client? [y/N]: ").strip().lower() == "y":
                vpn_ip = admin_pick_vpn_ip()
                source = "admin:access_rules"
        if not vpn_ip:
            return 1

    update_client_index(vpn_ip)

    while True:
        os.system("clear" if os.name != "nt" else "cls")
        print(BANNER)
        on = is_enabled(vpn_ip)
        svc = daemon_running()

        print(f"VPN Client : {color(vpn_ip, GREEN)}")
        print(f"Detection  : {source}")
        print(f"Owner      : {get_display_user()}")
        print(
            f"Adblock    : "
            + (color("ON", GREEN) if on else color("OFF", YELLOW))
        )
        print(
            f"Daemon     : "
            + (color("UP", GREEN) if svc else color("DOWN", RED))
        )
        print()
        print(color("[1]  Status / stats", CYAN))
        print(color("[2]  ENABLE adblock for me", GREEN))
        print(color("[3]  DISABLE adblock for me", YELLOW))
        print(color("[4]  Test a domain", CYAN))
        print(color("[5]  Add custom BLOCK domain", RED))
        print(color("[6]  Add custom ALLOW domain", GREEN))
        print(color("[7]  Remove custom rule", CYAN))
        print(color("[8]  List my custom rules", CYAN))
        print(color("[9]  Recent blocks (mine)", CYAN))
        print(color("[10] Help / OpenVPN DNS tips", MAGENTA))
        print(color("[11] Exit", RED))
        print()
        choice = input("Select > ").strip()

        if choice == "1":
            show_status(vpn_ip)
        elif choice == "2":
            enable_adblock(vpn_ip)
        elif choice == "3":
            disable_adblock(vpn_ip)
        elif choice == "4":
            test_domain(vpn_ip)
        elif choice == "5":
            add_custom(vpn_ip, "block")
        elif choice == "6":
            add_custom(vpn_ip, "allow")
        elif choice == "7":
            print("\n[1] From block list  [2] From allow list")
            sub = input("Select: ").strip()
            if sub == "1":
                remove_custom(vpn_ip, "block")
            elif sub == "2":
                remove_custom(vpn_ip, "allow")
        elif choice == "8":
            list_custom(vpn_ip)
        elif choice == "9":
            show_recent(vpn_ip)
        elif choice == "10":
            show_help()
        elif choice == "11":
            print(color("\nGoodbye.", CYAN))
            return 0
        else:
            print(color("[!] Invalid.", RED))
            time.sleep(0.8)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(0)
