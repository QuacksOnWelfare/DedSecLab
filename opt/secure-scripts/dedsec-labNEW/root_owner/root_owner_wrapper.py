#!/usr/bin/env python3
import os, sys, json, time, signal, getpass, subprocess, importlib.util
from datetime import datetime

BASE_DIR = "/opt/secure-scripts/dedsec-labNEW"
ROOT_DIR = os.path.join(BASE_DIR, "root_owner")
RULES_FILE = os.path.join(ROOT_DIR, "root_access_rules.json")
MENU_SCRIPT = os.path.join(ROOT_DIR, "root_owner_menu.py")
LOG_FILE = os.path.join(ROOT_DIR, "logs", "root_access.log")
DISCORD_NOTIFY_SCRIPT = os.path.join(BASE_DIR, "scripts", "system", "discord_notify.py")

RESET="\033[0m"; GREEN="\033[32m"; YELLOW="\033[33m"; CYAN="\033[36m"; WHITE="\033[97m"; RED="\033[31m"; BOLD="\033[1m"

def discord_alert(title, message, color=3447003, event_type="owner_tools"):
    try:
        spec = importlib.util.spec_from_file_location("discord_notify", DISCORD_NOTIFY_SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.send_discord_alert(title, message, color=color, event_type=event_type)
    except Exception:
        pass

def log(msg):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {msg}\n")



def safe_input(prompt=""):
    try:
        return input(prompt).strip()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Use the menu options to exit cleanly.{RESET}")
        time.sleep(1)
        return ""
    except EOFError:
        print(f"\n{YELLOW}Session input closed. Returning safely.{RESET}")
        time.sleep(1)
        return ""

def clear():
    subprocess.run(["clear"], check=False)

def banner():
    try:
        banner_path = os.path.join(BASE_DIR, "utils", "banner.py")
        spec = importlib.util.spec_from_file_location("dedsec_banner", banner_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.dedsec_banner(GREEN, CYAN, RESET, BOLD, lambda: None)
    except Exception:
        print(f"{GREEN}{BOLD}DEDSEC ROOT OWNER ACCESS{RESET}")
        print(f"{GREEN}{'='*56}{RESET}")

def get_source_ip():
    parts = os.environ.get("SSH_CONNECTION", "").split()
    return parts[0] if parts else "unknown"

def get_real_ip_from_vpn_status(vpn_ip):
    try:
        with open("/var/log/openvpn-status.log", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith("CLIENT_LIST,"):
                    parts = line.strip().split(",")
                    if len(parts) >= 4 and parts[3] == vpn_ip:
                        return parts[2].split(":")[0]
    except Exception:
        pass
    return "unknown"

def load_rules():
    with open(RULES_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def deny(reason, source_ip, real_ip):
    clear(); banner()
    print(f"{RED}{BOLD}ROOT OWNER ACCESS DENIED{RESET}\n")
    print(f"{CYAN}Source IP:{RESET} {YELLOW}{source_ip}{RESET}")
    print(f"{CYAN}Real IP:{RESET}   {YELLOW}{real_ip}{RESET}")
    print(f"{CYAN}Reason:{RESET}    {YELLOW}{reason}{RESET}")
    log(f"DENY | source_ip={source_ip} | real_ip={real_ip} | reason={reason}")
    discord_alert("🚫 DEDSEC Root Owner Denied", f"Source IP: `{source_ip}`\nReal IP: `{real_ip}`\nReason: `{reason}`", color=15158332, event_type="owner_deny")
    time.sleep(3)
    sys.exit(1)

def handle_sigint(signum, frame):
    print(f"\n{YELLOW}Use the owner menu to exit cleanly.{RESET}")

signal.signal(signal.SIGINT, handle_sigint)
signal.signal(signal.SIGTSTP, handle_sigint)

def main():
    os.environ.setdefault("TERM", "xterm")

    original_cmd = os.environ.get("SSH_ORIGINAL_COMMAND", "").strip()

    if original_cmd:
        source_ip = get_source_ip()
        real_ip = get_real_ip_from_vpn_status(source_ip)
        log(f"SSH_CMD_BLOCKED | source_ip={source_ip} | real_ip={real_ip} | cmd={original_cmd}")
        discord_alert(
            "🚫 Root SSH Command Blocked",
            f"Source IP: `{source_ip}`\nReal IP: `{real_ip}`\nCommand: `{original_cmd}`",
            color=15158332,
            event_type="owner_deny"
        )
        deny("ssh command execution blocked", source_ip, real_ip)

    if not sys.stdin.isatty():
        source_ip = get_source_ip()
        real_ip = get_real_ip_from_vpn_status(source_ip)
        log(f"SSH_NON_TTY_BLOCKED | source_ip={source_ip} | real_ip={real_ip}")
        deny("non-interactive ssh session blocked", source_ip, real_ip)

    os.environ.pop("SSH_ORIGINAL_COMMAND", None)

    source_ip = get_source_ip()
    real_ip = get_real_ip_from_vpn_status(source_ip)

    try:
        rules = load_rules()
    except Exception:
        deny("root rules missing or unreadable", source_ip, real_ip)

    owner = rules.get("owner", {})
    allowed_ips = owner.get("allowed_ips", [])

    if not owner.get("enabled", False):
        deny("owner access disabled", source_ip, real_ip)

    if source_ip not in allowed_ips and real_ip not in allowed_ips:
        deny("ip not allowlisted", source_ip, real_ip)

    display = owner.get("display_name", "owner")

    log(f"ALLOW | source_ip={source_ip} | real_ip={real_ip} | owner={display}")
    discord_alert("👑 DEDSEC Root Owner Login", f"Owner: `{display}`\nSource IP: `{source_ip}`\nReal IP: `{real_ip}`", color=3066993, event_type="owner_login")

    env = os.environ.copy()
    env["DEDSEC_ROLE"] = "owner"
    env["DEDSEC_USER"] = display
    env["DEDSEC_SOURCE_IP"] = source_ip
    env["DEDSEC_REAL_IP"] = real_ip
    os.execve("/usr/bin/python3", ["python3", MENU_SCRIPT], env)

if __name__ == "__main__":
    main()
