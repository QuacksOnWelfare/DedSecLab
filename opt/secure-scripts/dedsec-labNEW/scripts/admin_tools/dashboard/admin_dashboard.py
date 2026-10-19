#!/usr/bin/env python3
import os
import json
from datetime import datetime, date

BASE_DIR = "/opt/secure-scripts/dedsec-labNEW"
RULES_FILE = os.path.join(BASE_DIR, "access_rules.json")
ACCESS_LOG = os.path.join(BASE_DIR, "access_audit.log")
TOOL_LOG = os.path.join(BASE_DIR, "logs", "tool_usage.log")
ADMIN_LOG = os.path.join(BASE_DIR, "logs", "admin_audit.log")
ADMIN_NOTICE_FILE = os.path.join(BASE_DIR, "admin_notice.txt")
SESSIONS_FILE = os.path.join(BASE_DIR, "user_sessions.json")

RESET="\033[0m"
GREEN="\033[32m"
YELLOW="\033[33m"
CYAN="\033[36m"
WHITE="\033[97m"
RED="\033[31m"
BOLD="\033[1m"

def clear():
    os.system("clear")

def pause():
    input(f"\n{YELLOW}Press Enter to continue...{RESET}")

def banner():
    import importlib.util
    banner_path = os.path.join(BASE_DIR, "utils", "banner.py")
    spec = importlib.util.spec_from_file_location("dedsec_banner", banner_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    def noop_theme():
        return None

    mod.dedsec_banner(GREEN, CYAN, RESET, BOLD, noop_theme)

def load_rules():
    try:
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"users": {}}

def parse_date(value):
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except Exception:
        return None

def days_left(expiry):
    d = parse_date(expiry)
    if not d:
        return None
    return (d - date.today()).days

def tail_file(path, limit=20):
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
    return lines[-limit:]


def active_users_live():
    clear()
    banner()

    print(f"{WHITE}{BOLD}Active Users Live:{RESET}\n")

    try:
        with open(SESSIONS_FILE, "r", encoding="utf-8") as f:
            sessions = json.load(f)
    except Exception:
        sessions = {}

    if not sessions:
        print(f"{RED}No sessions found.{RESET}")
        pause()
        return

    now_dt = datetime.now()

    for ip, info in sorted(sessions.items()):
        user = info.get("user", "unknown")
        role = info.get("role", "standard")
        last_seen = info.get("last_seen", "N/A")

        try:
            seen_dt = datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S")
            diff = int((now_dt - seen_dt).total_seconds())
        except Exception:
            diff = 999999

        if diff <= 120:
            status = f"{GREEN}online now{RESET}"
        elif diff <= 300:
            status = f"{YELLOW}idle {diff // 60}m{RESET}"
        else:
            status = f"{RED}last seen {diff // 60}m ago{RESET}"

        print(f"{CYAN}{ip:<12}{RESET} {WHITE}{user:<14}{RESET} {YELLOW}{role:<8}{RESET} {status}")

    pause()


def active_users():
    clear()
    banner()

    rules = load_rules()
    users = rules.get("users", {})

    print(f"{WHITE}{BOLD}Active / Enabled Users:{RESET}\n")

    found = False
    for ip, user in sorted(users.items()):
        if user.get("enabled", True):
            found = True
            name = user.get("display_name", "unknown")
            role = user.get("role", "standard")
            expiry = user.get("subscription_expires", "N/A")
            left = days_left(expiry)

            if left is None:
                status = f"{YELLOW}N/A{RESET}"
            elif left < 0:
                status = f"{RED}EXPIRED{RESET}"
            elif left <= 3:
                status = f"{RED}{left}d left{RESET}"
            elif left <= 7:
                status = f"{YELLOW}{left}d left{RESET}"
            else:
                status = f"{GREEN}{left}d left{RESET}"

            print(f"{CYAN}{ip:<12}{RESET} {WHITE}{name:<14}{RESET} {YELLOW}{role:<8}{RESET} {status}")

    if not found:
        print(f"{RED}No enabled users found.{RESET}")

    pause()

def expiring_soon():
    clear()
    banner()

    rules = load_rules()
    users = rules.get("users", {})

    limit = input(f"{YELLOW}Show users expiring within days [7]:{RESET} ").strip()
    if not limit:
        limit = "7"

    if not limit.isdigit():
        print(f"{RED}Invalid number.{RESET}")
        pause()
        return

    limit = int(limit)

    print(f"\n{WHITE}{BOLD}Users Expiring Soon:{RESET}\n")

    found = False
    for ip, user in sorted(users.items()):
        expiry = user.get("subscription_expires")
        left = days_left(expiry)

        if left is not None and 0 <= left <= limit:
            found = True
            print(f"{CYAN}{ip:<12}{RESET} {WHITE}{user.get('display_name','unknown'):<14}{RESET} {YELLOW}{expiry}{RESET} {RED}{left}d left{RESET}")

    if not found:
        print(f"{GREEN}No users expiring within {limit} days.{RESET}")

    pause()

def expired_users():
    clear()
    banner()

    rules = load_rules()
    users = rules.get("users", {})

    print(f"{WHITE}{BOLD}Expired Users:{RESET}\n")

    found = False
    for ip, user in sorted(users.items()):
        expiry = user.get("subscription_expires")
        left = days_left(expiry)

        if left is not None and left < 0:
            found = True
            enabled = "enabled" if user.get("enabled", True) else "disabled"
            print(f"{CYAN}{ip:<12}{RESET} {WHITE}{user.get('display_name','unknown'):<14}{RESET} {YELLOW}{expiry}{RESET} {RED}{enabled}{RESET}")

    if not found:
        print(f"{GREEN}No expired users found.{RESET}")

    pause()

def auto_disable_expired():
    clear()
    banner()

    rules = load_rules()
    users = rules.get("users", {})

    confirm = input(f"{RED}Disable all expired users in access_rules.json? Type YES:{RESET} ").strip()
    if confirm.upper() != "YES":
        print(f"{YELLOW}Cancelled.{RESET}")
        pause()
        return

    changed = 0
    for ip, user in users.items():
        expiry = user.get("subscription_expires")
        left = days_left(expiry)

        if left is not None and left < 0 and user.get("enabled", True):
            user["enabled"] = False
            changed += 1

    with open(RULES_FILE, "w", encoding="utf-8") as f:
        json.dump(rules, f, indent=2)

    print(f"{GREEN}Disabled expired users:{RESET} {YELLOW}{changed}{RESET}")
    pause()

def access_log():
    clear()
    banner()
    print(f"{WHITE}{BOLD}Recent Access Log:{RESET}\n")
    lines = tail_file(ACCESS_LOG, 25)
    if not lines:
        print(f"{RED}No access log found.{RESET}")
    else:
        for line in lines:
            parts = line.strip().split(" | ")

            # New format: timestamp | user | ip | category | tool
            if len(parts) >= 5:
                ts, user, ip, category, tool = parts[:5]
                print(f"{CYAN}{ts}{RESET} {YELLOW}{user}{RESET} {RED}{ip}{RESET} {WHITE}{category} -> {tool}{RESET}")

            # Old format fallback
            else:
                print(f"{WHITE}{line.rstrip()}{RESET}")
    pause()

def tool_usage_log():
    clear()
    banner()
    print(f"{WHITE}{BOLD}Recent Tool Usage:{RESET}\n")
    lines = tail_file(TOOL_LOG, 25)
    if not lines:
        print(f"{RED}No tool usage log found.{RESET}")
    else:
        for line in lines:
            parts = line.strip().split(" | ")

            # New format: timestamp | user | ip | category | tool
            if len(parts) >= 5:
                ts, user, ip, category, tool = parts[:5]
                print(f"{CYAN}{ts}{RESET} {YELLOW}{user}{RESET} {RED}{ip}{RESET} {WHITE}{category} -> {tool}{RESET}")

            # Old format fallback
            else:
                print(f"{WHITE}{line.rstrip()}{RESET}")
    pause()

def admin_audit_log():
    clear()
    banner()
    print(f"{WHITE}{BOLD}Recent Admin Audit:{RESET}\n")
    lines = tail_file(ADMIN_LOG, 25)
    if not lines:
        print(f"{RED}No admin audit log found.{RESET}")
    else:
        for line in lines:
            parts = line.strip().split(" | ")

            # New format: timestamp | user | ip | category | tool
            if len(parts) >= 5:
                ts, user, ip, category, tool = parts[:5]
                print(f"{CYAN}{ts}{RESET} {YELLOW}{user}{RESET} {RED}{ip}{RESET} {WHITE}{category} -> {tool}{RESET}")

            # Old format fallback
            else:
                print(f"{WHITE}{line.rstrip()}{RESET}")
    pause()


def recent_logins():
    clear()
    banner()
    print(f"{WHITE}{BOLD}Recent Logins:{RESET}\n")

    lines = tail_file(ACCESS_LOG, 100)
    login_lines = [line.strip() for line in lines if "LOGIN" in line]

    if not login_lines:
        print(f"{YELLOW}No login events found.{RESET}")
        pause()
        return

    for line in login_lines[-25:]:
        parts = line.split(" | ")
        ts = parts[0] if parts else "unknown"

        fields = {}
        for part in parts[1:]:
            if "=" in part:
                key, value = part.split("=", 1)
                fields[key.strip()] = value.strip()

        user = fields.get("user", "unknown")
        ip = fields.get("ip", "unknown")
        role = fields.get("role", "unknown")
        discord = fields.get("discord", "N/A")

        print(f"{CYAN}{ts}{RESET}  {YELLOW}{user:<12}{RESET} {RED}{ip:<12}{RESET} {WHITE}{role:<8}{RESET} {CYAN}{discord}{RESET}")

    pause()


def set_admin_notice():
    clear()
    banner()

    print(f"{WHITE}{BOLD}Set Admin Notice:{RESET}\n")
    notice = input(f"{YELLOW}Notice message:{RESET} ").strip()

    if not notice:
        print(f"{RED}Notice cannot be empty.{RESET}")
        pause()
        return

    with open(ADMIN_NOTICE_FILE, "w", encoding="utf-8") as f:
        f.write(notice + "\n")

    print(f"\n{GREEN}Admin notice set.{RESET}")
    pause()


def clear_admin_notice():
    clear()
    banner()

    if not os.path.isfile(ADMIN_NOTICE_FILE):
        print(f"{YELLOW}No admin notice exists.{RESET}")
        pause()
        return

    confirm = input(f"{RED}Clear current admin notice? Type YES:{RESET} ").strip()

    if confirm.upper() != "YES":
        print(f"{YELLOW}Cancelled.{RESET}")
        pause()
        return

    with open(ADMIN_NOTICE_FILE, "w", encoding="utf-8") as f:
        f.write("")

    print(f"{GREEN}Admin notice cleared.{RESET}")
    pause()


def main():
    while True:
        clear()
        banner()

        print(f"{WHITE}{BOLD}Admin Dashboard:{RESET}\n")
        menu_items = [
            ("1", "Active Users Live"),
            ("2", "Active / Enabled Users"),
            ("3", "Users Expiring Soon"),
            ("4", "Expired Users"),
            ("5", "Auto Disable Expired Users"),
            ("6", "Recent Logins"),
            ("7", "Recent Access Log"),
            ("8", "Recent Tool Usage"),
            ("9", "Recent Admin Audit"),
            ("10", "Set Admin Notice"),
            ("11", "Clear Admin Notice"),
            ("0", "Back / Exit"),
        ]

        for num, label in menu_items:
            print(f"{CYAN}{BOLD}{num:>2}.{RESET} {WHITE}{label}{RESET}")
        print()
        print(f"{GREEN}{'-' * 46}{RESET}")

        choice = input(f"{YELLOW}Select an option:{RESET} ").strip()

        if choice == "1":
            active_users_live()
        elif choice == "2":
            active_users()
        elif choice == "3":
            expiring_soon()
        elif choice == "4":
            expired_users()
        elif choice == "5":
            auto_disable_expired()
        elif choice == "6":
            recent_logins()
        elif choice == "6":
            access_log()
        elif choice == "7":
            tool_usage_log()
        elif choice == "8":
            admin_audit_log()
        elif choice == "10":
            set_admin_notice()
        elif choice == "11":
            clear_admin_notice()
        elif choice == "0":
            break
        else:
            print(f"{RED}Invalid option.{RESET}")
            pause()

if __name__ == "__main__":
    main()
