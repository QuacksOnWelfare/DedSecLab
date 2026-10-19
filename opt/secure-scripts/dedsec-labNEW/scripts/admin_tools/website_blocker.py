#!/usr/bin/env python3
"""
DedSec Lab - Admin Website Blocker
Per-VPN-user domain/URL block list for OpenVPN clients.
Admin only. Run as root.
"""
import os
import sys
import json
import re
import signal
import subprocess
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

def auto_root():
    if os.geteuid() != 0:
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)

auto_root()

# ============================================================
# PATHS (match your lab layout)
# ============================================================
BASE_DIR = Path("/opt/secure-scripts/dedsec-labNEW")
RULES_FILE = BASE_DIR / "access_rules.json"
BLOCK_DIR = BASE_DIR / "website_blocks"
BLOCK_DIR.mkdir(parents=True, exist_ok=True)

# Optional: write dnsmasq snippets the resolver can include
DNSMASQ_DIR = Path("/etc/dnsmasq.d")
DNSMASQ_PREFIX = "dedsec-block-"

# Sinkhole IP (clients resolve blocked hosts here)
SINKHOLE_IP = "0.0.0.0"

RESET = "\033[0m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
WHITE = "\033[97m"
RED = "\033[31m"
BOLD = "\033[1m"
DIM = "\033[2m"

def handle_sigint(signum, frame):
    print(f"\n{YELLOW}Use the menu to exit cleanly.{RESET}")

signal.signal(signal.SIGINT, handle_sigint)

def clear():
    os.system("clear" if os.name != "nt" else "cls")

def pause():
    input(f"\n{DIM}Press ENTER to continue...{RESET}")

def safe_input(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""

def banner():
    print(f"""
{CYAN}{BOLD}
██████╗ ███████╗██████╗ ███████╗███████╗ ██████╗
██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝
██║  ██║█████╗  ██║  ██║███████╗█████╗  ██║
██║  ██║██╔══╝  ██║  ██║╚════██║██╔══╝  ██║
██████╔╝███████╗██████╔╝███████║███████╗╚██████╗
╚═════╝ ╚══════╝╚═════╝ ╚══════╝╚══════╝ ╚═════╝
{RESET}{YELLOW}
        ADMIN · WEBSITE BLOCKER
        Per-user domain blocks for VPN clients
{RESET}{DIM}════════════════════════════════════════════════════════{RESET}
""")

def load_rules() -> dict:
    try:
        return json.loads(RULES_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"users": {}}

def list_vpn_users() -> list:
    """Return list of dicts: vpn_ip, display_name, app_username, enabled, role."""
    data = load_rules()
    users = []
    for vpn_ip, rule in (data.get("users") or {}).items():
        if not isinstance(rule, dict):
            continue
        users.append({
            "vpn_ip": vpn_ip,
            "display_name": str(rule.get("display_name") or "unknown"),
            "app_username": str(rule.get("app_username") or ""),
            "enabled": bool(rule.get("enabled", True)),
            "role": str(rule.get("role") or "standard"),
        })
    users.sort(key=lambda u: (u["display_name"].lower(), u["vpn_ip"]))
    return users

def block_file_for(vpn_ip: str) -> Path:
    safe = re.sub(r"[^0-9a-zA-Z._-]", "_", vpn_ip)
    return BLOCK_DIR / f"{safe}.json"

def load_blocks(vpn_ip: str) -> dict:
    path = block_file_for(vpn_ip)
    default = {
        "vpn_ip": vpn_ip,
        "domains": [],
        "enabled": True,
        "updated": None,
        "notes": "",
    }
    if not path.is_file():
        return default
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return default
        data.setdefault("vpn_ip", vpn_ip)
        data.setdefault("domains", [])
        data.setdefault("enabled", True)
        return data
    except Exception:
        return default

def save_blocks(vpn_ip: str, data: dict) -> None:
    data["vpn_ip"] = vpn_ip
    data["updated"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    path = block_file_for(vpn_ip)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.chmod(path, 0o600)

def normalize_domain(raw: str) -> str | None:
    """
    Accept:
      example.com
      https://www.example.com/path
      www.example.com
    Store as lowercase hostname without www. optional keep as entered host.
    """
    s = (raw or "").strip().lower()
    if not s:
        return None
    if "://" not in s:
        s = "http://" + s
    try:
        host = urlparse(s).hostname
    except Exception:
        host = None
    if not host:
        # bare domain-ish
        host = raw.strip().lower().split("/")[0].split(":")[0]
    host = (host or "").strip(".").lower()
    if not host or " " in host:
        return None
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", host) and host.count(".") < 1:
        # allow single-label only if clearly domain-like; reject junk
        if not re.match(r"^[a-z0-9.-]+$", host):
            return None
    # strip leading www. for consistency (still blocks www via dnsmasq address=)
    if host.startswith("www."):
        host = host[4:]
    return host

def pick_user() -> dict | None:
    users = list_vpn_users()
    if not users:
        print(f"{RED}No users found in access_rules.json{RESET}")
        return None
    print(f"{CYAN}{BOLD}VPN users{RESET}")
    print(f"{DIM}{'#':<4} {'Name':<22} {'VPN IP':<16} {'Role':<10} Enabled{RESET}")
    print(f"{GREEN}{'-' * 70}{RESET}")
    for i, u in enumerate(users, 1):
        en = f"{GREEN}yes{RESET}" if u["enabled"] else f"{RED}no{RESET}"
        print(f"{i:<4} {u['display_name'][:21]:<22} {u['vpn_ip']:<16} {u['role'][:9]:<10} {en}")
    print()
    choice = safe_input(f"{YELLOW}Select user number (or VPN IP / name):{RESET} ")
    if not choice:
        return None
    if choice.isdigit():
        idx = int(choice)
        if 1 <= idx <= len(users):
            return users[idx - 1]
        print(f"{RED}Invalid number.{RESET}")
        return None
    q = choice.lower()
    for u in users:
        if q == u["vpn_ip"].lower() or q == u["display_name"].lower() or q == u["app_username"].lower():
            return u
    print(f"{RED}User not found.{RESET}")
    return None

def show_blocks(user: dict) -> None:
    data = load_blocks(user["vpn_ip"])
    print()
    print(f"{CYAN}{BOLD}Blocks for {user['display_name']} ({user['vpn_ip']}){RESET}")
    print(f"  List enabled : {GREEN if data.get('enabled') else RED}{data.get('enabled')}{RESET}")
    print(f"  Updated      : {data.get('updated') or 'never'}")
    print(f"  Domains      : {len(data.get('domains') or [])}")
    print(f"{GREEN}{'-' * 50}{RESET}")
    domains = data.get("domains") or []
    if not domains:
        print(f"{DIM}  (empty){RESET}")
        return
    for i, d in enumerate(domains, 1):
        print(f"  {i:>3}. {d}")

def add_domains(user: dict) -> None:
    data = load_blocks(user["vpn_ip"])
    domains = list(data.get("domains") or [])
    print(f"{YELLOW}Enter domains/URLs (one per line). Empty line = done.{RESET}")
    print(f"{DIM}Examples: facebook.com  https://www.tiktok.com  youtube.com{RESET}")
    added = 0
    while True:
        line = safe_input(f"{CYAN}domain>{RESET} ")
        if not line:
            break
        host = normalize_domain(line)
        if not host:
            print(f"{RED}  Invalid: {line}{RESET}")
            continue
        if host in domains:
            print(f"{YELLOW}  Already listed: {host}{RESET}")
            continue
        domains.append(host)
        added += 1
        print(f"{GREEN}  + {host}{RESET}")
    data["domains"] = sorted(set(domains))
    save_blocks(user["vpn_ip"], data)
    print(f"{GREEN}Saved. Added {added}. Total {len(data['domains'])}.{RESET}")
    write_dnsmasq_snippet(user["vpn_ip"], data)

def remove_domains(user: dict) -> None:
    data = load_blocks(user["vpn_ip"])
    domains = list(data.get("domains") or [])
    if not domains:
        print(f"{YELLOW}List empty.{RESET}")
        return
    show_blocks(user)
    raw = safe_input(f"{YELLOW}Numbers to remove (e.g. 1,3) or domain text:{RESET} ")
    if not raw:
        return
    to_remove = set()
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if part.isdigit():
            i = int(part)
            if 1 <= i <= len(domains):
                to_remove.add(domains[i - 1])
        else:
            host = normalize_domain(part) or part.lower()
            to_remove.add(host)
    new_list = [d for d in domains if d not in to_remove]
    data["domains"] = new_list
    save_blocks(user["vpn_ip"], data)
    print(f"{GREEN}Removed {len(domains) - len(new_list)}. Remaining {len(new_list)}.{RESET}")
    write_dnsmasq_snippet(user["vpn_ip"], data)

def clear_domains(user: dict) -> None:
    confirm = safe_input(f"{RED}Clear ALL blocks for {user['display_name']}? type YES:{RESET} ")
    if confirm != "YES":
        print("Cancelled.")
        return
    data = load_blocks(user["vpn_ip"])
    data["domains"] = []
    save_blocks(user["vpn_ip"], data)
    write_dnsmasq_snippet(user["vpn_ip"], data)
    print(f"{GREEN}Cleared.{RESET}")

def toggle_list(user: dict) -> None:
    data = load_blocks(user["vpn_ip"])
    data["enabled"] = not bool(data.get("enabled", True))
    save_blocks(user["vpn_ip"], data)
    write_dnsmasq_snippet(user["vpn_ip"], data)
    state = "ENABLED" if data["enabled"] else "DISABLED"
    print(f"{GREEN}Block list {state} for {user['display_name']}.{RESET}")

def write_dnsmasq_snippet(vpn_ip: str, data: dict | None = None) -> Path | None:
    """
    Per-client dnsmasq style file.
    Real per-IP DNS policy needs your resolver wired to VPN IPs;
    this generates the domain sinkhole list for ops / optional include.
    """
    data = data or load_blocks(vpn_ip)
    safe = re.sub(r"[^0-9a-zA-Z._-]", "_", vpn_ip)
    out = BLOCK_DIR / f"{safe}.dnsmasq"
    lines = [
        f"# DedSec website blocks for VPN client {vpn_ip}",
        f"# updated {data.get('updated')}",
        f"# enabled={data.get('enabled')}",
    ]
    if data.get("enabled"):
        for d in data.get("domains") or []:
            lines.append(f"address=/{d}/{SINKHOLE_IP}")
            lines.append(f"address=/www.{d}/{SINKHOLE_IP}")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out

def export_all_dnsmasq() -> None:
    users = list_vpn_users()
    count = 0
    for u in users:
        data = load_blocks(u["vpn_ip"])
        if data.get("domains"):
            write_dnsmasq_snippet(u["vpn_ip"], data)
            count += 1
    print(f"{GREEN}Wrote dnsmasq snippets for {count} user(s) in {BLOCK_DIR}{RESET}")

def generate_iptables_hint(user: dict) -> None:
    data = load_blocks(user["vpn_ip"])
    print(f"{CYAN}Enforcement notes for {user['display_name']} ({user['vpn_ip']}){RESET}")
    print(f"""
{DIM}Blocks are stored in:{RESET} {block_file_for(user['vpn_ip'])}
{DIM}dnsmasq snippet:{RESET}     {BLOCK_DIR / (re.sub(r'[^0-9a-zA-Z._-]', '_', user['vpn_ip']) + '.dnsmasq')}

{YELLOW}Recommended enforcement (pick one):{RESET}
  1) DNS sinkhole (best for domain blocks)
     - Run dnsmasq/unbound on the VPS
     - Point VPN push "dhcp-option DNS <vpn-gw>"
     - Include per-user address=/domain/0.0.0.0 lists
     - Optional: map source IP {user['vpn_ip']} to a view

  2) Resolve + ipset (IP level, domains change)
     - Script resolves each domain periodically
     - nft/ipset drop for packets from {user['vpn_ip']} to those IPs

  3) Transparent proxy ACL (advanced)
     - Squid ACLs by src {user['vpn_ip']} + dstdomain

{DIM}Domains currently listed:{RESET} {len(data.get('domains') or [])}
""")
    for d in data.get("domains") or []:
        print(f"  - {d}")

def summary_all() -> None:
    users = list_vpn_users()
    print(f"{CYAN}{BOLD}Block summary{RESET}")
    print(f"{DIM}{'User':<22} {'VPN IP':<16} {'Count':<6} On{RESET}")
    print(f"{GREEN}{'-' * 55}{RESET}")
    total = 0
    for u in users:
        data = load_blocks(u["vpn_ip"])
        n = len(data.get("domains") or [])
        total += n
        on = "Y" if data.get("enabled") else "n"
        if n or not data.get("enabled", True):
            print(f"{u['display_name'][:21]:<22} {u['vpn_ip']:<16} {n:<6} {on}")
    print(f"{GREEN}{'-' * 55}{RESET}")
    print(f"Total blocked domain entries: {total}")

def user_menu(user: dict) -> None:
    while True:
        clear()
        banner()
        print(f"{WHITE}Selected:{RESET} {BOLD}{user['display_name']}{RESET}  {DIM}{user['vpn_ip']}{RESET}")
        show_blocks(user)
        print(f"""
{CYAN}{BOLD}USER ACTIONS{RESET}
  {CYAN}1.{RESET} Add domains / URLs
  {CYAN}2.{RESET} Remove domains
  {CYAN}3.{RESET} Clear all domains
  {CYAN}4.{RESET} Enable / disable this user's block list
  {CYAN}5.{RESET} Rebuild dnsmasq snippet
  {CYAN}6.{RESET} Enforcement help
  {CYAN}0.{RESET} Back
""")
        c = safe_input(f"{YELLOW}Choice:{RESET} ")
        if c == "1":
            add_domains(user)
            pause()
        elif c == "2":
            remove_domains(user)
            pause()
        elif c == "3":
            clear_domains(user)
            pause()
        elif c == "4":
            toggle_list(user)
            pause()
        elif c == "5":
            path = write_dnsmasq_snippet(user["vpn_ip"])
            print(f"{GREEN}Wrote {path}{RESET}")
            pause()
        elif c == "6":
            generate_iptables_hint(user)
            pause()
        elif c == "0":
            break
        else:
            print(f"{RED}Invalid.{RESET}")
            pause()

def main() -> None:
    while True:
        clear()
        banner()
        print(f"{DIM}Rules: {RULES_FILE}{RESET}")
        print(f"{DIM}Blocks: {BLOCK_DIR}{RESET}")
        print(f"""
{CYAN}{BOLD}MAIN MENU{RESET}
  {CYAN}1.{RESET} Select VPN user -> manage blocks
  {CYAN}2.{RESET} Summary of all blocks
  {CYAN}3.{RESET} Export / rebuild all dnsmasq snippets
  {CYAN}0.{RESET} Exit
""")
        c = safe_input(f"{YELLOW}Choice:{RESET} ")
        if c == "1":
            clear()
            banner()
            user = pick_user()
            if user:
                user_menu(user)
        elif c == "2":
            clear()
            banner()
            summary_all()
            pause()
        elif c == "3":
            export_all_dnsmasq()
            pause()
        elif c == "0":
            print(f"{GREEN}Bye.{RESET}")
            break
        else:
            print(f"{RED}Invalid.{RESET}")
            pause()

if __name__ == "__main__":
    main()


