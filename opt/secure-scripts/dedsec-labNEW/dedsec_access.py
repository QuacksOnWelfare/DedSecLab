#!/usr/bin/env python3
import os
import json
import subprocess
import getpass
import shutil
import hashlib
from datetime import datetime

BASE_DIR = "/opt/secure-scripts/dedsec-labNEW"
LOGS_DIR = os.path.join(BASE_DIR, "logs")
THEMES_FILE = os.path.join(BASE_DIR, "user_themes.json")
DISCORD_NOTIFY_SCRIPT = os.path.join(BASE_DIR, "scripts", "system", "discord_notify.py")

TARGET_USER = "dedsecuser"
ALLOWED_VPN_IP = "10.8.0.2"
ALLOWED_VPN_IP = "10.8.0.6"

# Generate with:
# python3 -c 'import hashlib,getpass; print(hashlib.sha256(getpass.getpass("Password: ").encode()).hexdigest())'
ACCESS_PASSWORD_HASH = "PUT_YOUR_SHA256_HASH_HERE"

ACCESS_LOG = os.path.join(LOGS_DIR, "dedsec_user_access.log")

RESET = "\033[0m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
WHITE = "\033[97m"
RED = "\033[31m"
BOLD = "\033[1m"
DIM = "\033[2m"

os.makedirs(LOGS_DIR, exist_ok=True)


def clear():
    os.system("clear")


def pause():
    input(f"\n{YELLOW}Press Enter to continue...{RESET}")


def get_theme_key():
    ip = os.environ.get("DEDSEC_SOURCE_IP", "").strip()
    if ip and ip != "unknown":
        return ip

    user = os.environ.get("DEDSEC_USER", "").strip()
    if user:
        return user

    return "default"


def load_theme():
    try:
        with open(THEMES_FILE, "r", encoding="utf-8") as f:
            themes = json.load(f)
    except Exception:
        return "default"

    role = os.environ.get("DEDSEC_ROLE", "standard").strip().lower()

    if role != "admin":
        return "default"

    return themes.get(get_theme_key(), "default")


def apply_theme():
    global GREEN, CYAN, WHITE, YELLOW, RED

    GREEN = "\033[32m"
    CYAN = "\033[36m"
    WHITE = "\033[97m"
    YELLOW = "\033[33m"
    RED = "\033[31m"

    theme = load_theme()

    if theme == "red":
        GREEN = "\033[31m"
        CYAN = "\033[31m"
        YELLOW = "\033[91m"
    elif theme == "minimal":
        GREEN = "\033[97m"
        CYAN = "\033[97m"
        YELLOW = "\033[97m"
        RED = "\033[97m"
    elif theme == "blue":
        GREEN = "\033[34m"
        CYAN = "\033[94m"
        YELLOW = "\033[94m"
    elif theme == "purple":
        GREEN = "\033[35m"
        CYAN = "\033[95m"
        YELLOW = "\033[95m"
    elif theme == "cyan":
        GREEN = "\033[36m"
        CYAN = "\033[36m"
        YELLOW = "\033[96m"
    elif theme == "yellow":
        GREEN = "\033[33m"
        CYAN = "\033[93m"
        YELLOW = "\033[93m"


def line():
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{GREEN}{'═' * min(width, 80)}{RESET}")


def banner():
    import importlib.util
    banner_path = "/opt/secure-scripts/dedsec-labNEW/utils/banner.py"
    spec = importlib.util.spec_from_file_location("dedsec_banner", banner_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.dedsec_banner(GREEN, CYAN, RESET, BOLD, apply_theme)
    line()
    print()


def log_event(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lab_user = os.environ.get("DEDSEC_USER", "unknown")
    ip = os.environ.get("DEDSEC_SOURCE_IP", "unknown")
    role = os.environ.get("DEDSEC_ROLE", "standard")

    try:
        with open(ACCESS_LOG, "a", encoding="utf-8") as f:
            f.write(f"{timestamp} | {lab_user} | {ip} | {role} | {message}\n")
    except Exception:
        pass


def discord_alert(title, message, color=3447003):
    try:
        import importlib.util

        spec = importlib.util.spec_from_file_location("discord_notify", DISCORD_NOTIFY_SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.send_discord_alert(title, message, color=color, event_type="admin_tools")
    except Exception:
        pass


def user_exists(username):
    result = subprocess.run(
        ["id", username],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return result.returncode == 0


def require_admin_role():
    role = os.environ.get("DEDSEC_ROLE", "standard").strip().lower()

    if role != "admin":
        clear()
        banner()
        print(f"{RED}{BOLD}Access denied.{RESET}")
        print(f"{YELLOW}This tool is restricted to admins only.{RESET}")
        log_event("DENIED | non-admin tried to access dedsecuser launcher")
        pause()
        return False

    return True


def check_ip_and_password():
    source_ip = os.environ.get("DEDSEC_SOURCE_IP", "unknown").strip()

    if source_ip != ALLOWED_VPN_IP:
        clear()
        banner()
        print(f"{RED}{BOLD}Access denied.{RESET}")
        print(f"{YELLOW}This tool is restricted to VPN IP:{RESET} {ALLOWED_VPN_IP}")
        print(f"{YELLOW}Your IP:{RESET} {source_ip}")

        log_event(f"DENIED | invalid VPN IP: {source_ip}")

        discord_alert(
            "🚫 DEDSEC Shell Access Denied",
            (
                f"Reason: `Invalid VPN IP`\n"
                f"Allowed IP: `{ALLOWED_VPN_IP}`\n"
                f"Source IP: `{source_ip}`\n"
                f"User: `{os.environ.get('DEDSEC_USER', 'unknown')}`"
            ),
            color=15158332
        )

        pause()
        return False

    if ACCESS_PASSWORD_HASH == "PUT_YOUR_SHA256_HASH_HERE":
        clear()
        banner()
        print(f"{RED}{BOLD}Password hash not configured.{RESET}")
        print(f"{YELLOW}Edit ACCESS_PASSWORD_HASH in this script first.{RESET}")
        log_event("DENIED | password hash not configured")
        pause()
        return False

    password = getpass.getpass(f"{YELLOW}Access Password:{RESET} ")
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    if password_hash != ACCESS_PASSWORD_HASH:
        clear()
        banner()
        print(f"{RED}{BOLD}Access denied.{RESET}")
        print(f"{YELLOW}Invalid password.{RESET}")

        log_event(f"DENIED | bad password from IP {source_ip}")

        discord_alert(
            "🚫 DEDSEC Shell Access Denied",
            (
                f"Reason: `Bad password`\n"
                f"Source IP: `{source_ip}`\n"
                f"User: `{os.environ.get('DEDSEC_USER', 'unknown')}`"
            ),
            color=15158332
        )

        pause()
        return False

    log_event(f"APPROVED | IP and password accepted from {source_ip}")
    return True


def show_account_info():
    clear()
    banner()

    print(f"{WHITE}{BOLD}Session Info:{RESET}\n")
    print(f"{CYAN}SSH User:{RESET}      {YELLOW}{os.environ.get('DEDSEC_SSH_USER', getpass.getuser())}{RESET}")
    print(f"{CYAN}DEDSEC User:{RESET}   {YELLOW}{os.environ.get('DEDSEC_USER', 'unknown')}{RESET}")
    print(f"{CYAN}Source IP:{RESET}     {YELLOW}{os.environ.get('DEDSEC_SOURCE_IP', 'unknown')}{RESET}")
    print(f"{CYAN}Allowed IP:{RESET}    {YELLOW}{ALLOWED_VPN_IP}{RESET}")
    print(f"{CYAN}Role:{RESET}          {YELLOW}{os.environ.get('DEDSEC_ROLE', 'standard')}{RESET}")
    print(f"{CYAN}Target User:{RESET}   {YELLOW}{TARGET_USER}{RESET}")
    print()

    if user_exists(TARGET_USER):
        print(f"{GREEN}[✓] Target account exists.{RESET}")
        subprocess.run(["id", TARGET_USER])
    else:
        print(f"{RED}[x] Target account does not exist.{RESET}")

    pause()


def open_dedsec_shell():
    clear()
    banner()

    if not user_exists(TARGET_USER):
        print(f"{RED}[x] User not found:{RESET} {YELLOW}{TARGET_USER}{RESET}")
        log_event(f"FAILED | target user missing: {TARGET_USER}")
        pause()
        return

    lab_user = os.environ.get("DEDSEC_USER", "unknown")
    ip = os.environ.get("DEDSEC_SOURCE_IP", "unknown")
    role = os.environ.get("DEDSEC_ROLE", "standard")

    print(f"{WHITE}{BOLD}Opening terminal as:{RESET} {YELLOW}{TARGET_USER}{RESET}")
    print(f"{CYAN}Lab User:{RESET} {YELLOW}{lab_user}{RESET}")
    print(f"{CYAN}Source IP:{RESET} {YELLOW}{ip}{RESET}")
    print()
    print(f"{DIM}Use 'exit' to return to this menu.{RESET}")
    line()

    log_event(f"START | opened shell as {TARGET_USER}")

    discord_alert(
        "💀 DEDSEC User Shell Opened",
        (
            f"👤 **User:** `{lab_user}`\n"
            f"🌐 **IP:** `{ip}`\n"
            f"🎭 **Role:** `{role}`\n"
            f"🖥️ **Target User:** `{TARGET_USER}`"
        ),
        color=15844367
    )

    try:
        subprocess.run(["sudo", "-iu", TARGET_USER])
        exit_code = 0
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Session interrupted.{RESET}")
        exit_code = 130
    except Exception as e:
        print(f"{RED}Failed to open shell:{RESET} {e}")
        exit_code = 1

    log_event(f"END | shell ended for {TARGET_USER} | exit_code={exit_code}")

    discord_alert(
        "✅ DEDSEC User Shell Closed" if exit_code == 0 else "❌ DEDSEC User Shell Failed",
        (
            f"👤 **User:** `{lab_user}`\n"
            f"🌐 **IP:** `{ip}`\n"
            f"🎭 **Role:** `{role}`\n"
            f"🖥️ **Target User:** `{TARGET_USER}`\n"
            f"🔢 **Exit Code:** `{exit_code}`"
        ),
        color=3066993 if exit_code == 0 else 15158332
    )

    pause()


def view_access_log():
    clear()
    banner()

    print(f"{WHITE}{BOLD}dedsecuser Access Log:{RESET}\n")

    if not os.path.isfile(ACCESS_LOG):
        print(f"{YELLOW}No access logs yet.{RESET}")
        pause()
        return

    with open(ACCESS_LOG, "r", encoding="utf-8") as f:
        lines = f.readlines()[-50:]

    for line_text in lines:
        print(f"{YELLOW}{line_text.rstrip()}{RESET}")

    pause()


def main():
    if not require_admin_role():
        return

    if not check_ip_and_password():
        return

    while True:
        clear()
        banner()

        print(f"{CYAN}{BOLD}1.{RESET}  {WHITE}Access {TARGET_USER} Terminal{RESET}")
        print(f"{CYAN}{BOLD}2.{RESET}  {WHITE}Check {TARGET_USER} Account{RESET}")
        print(f"{CYAN}{BOLD}3.{RESET}  {WHITE}View Access Log{RESET}")
        print(f"{CYAN}{BOLD}0.{RESET}  {WHITE}Back / Exit{RESET}")
        print()
        print(f"{GREEN}{'-' * 46}{RESET}")

        choice = input(f"{YELLOW}Select an option:{RESET} ").strip()

        if choice == "1":
            open_dedsec_shell()
        elif choice == "2":
            show_account_info()
        elif choice == "3":
            view_access_log()
        elif choice == "0":
            print(f"{YELLOW}Returning...{RESET}")
            break
        else:
            print(f"{RED}Invalid option.{RESET}")
            pause()


if __name__ == "__main__":
    main()

