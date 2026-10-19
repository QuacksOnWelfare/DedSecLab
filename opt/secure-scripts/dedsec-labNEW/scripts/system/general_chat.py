#!/usr/bin/env python3
import os
import json
from datetime import datetime
import time

BASE_DIR = "/opt/secure-scripts/dedsec-labNEW"
CHAT_FILE = os.path.join(BASE_DIR, "general_chat.json")
RULES_FILE = os.path.join(BASE_DIR, "access_rules.json")

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

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def save_chat(data):
    with open(CHAT_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def load_chat():
    data = load_json(CHAT_FILE, {"messages": [], "last_seen": {}, "last_sent": {}})
    data.setdefault("messages", [])
    data.setdefault("last_seen", {})
    data.setdefault("last_sent", {})
    return data

def get_user():
    vpn_ip = os.environ.get("DEDSEC_SOURCE_IP", "unknown")
    role = os.environ.get("DEDSEC_ROLE", "standard").strip().lower()

    rules = load_json(RULES_FILE, {})
    info = rules.get("users", {}).get(vpn_ip, {})

    return {
        "vpn_ip": vpn_ip,
        "role": info.get("role", role),
        "display_name": info.get("display_name", os.environ.get("DEDSEC_USER", "unknown")),
        "discord_name": info.get("discord_name", "N/A"),
        "discord_id": info.get("discord_id", "N/A")
    }


def new_message_count(data, user):
    vpn_ip = user.get("vpn_ip", "unknown")
    last_seen = data.get("last_seen", {}).get(vpn_ip, "")

    count = 0
    for msg in data.get("messages", []):
        if msg.get("time", "") > last_seen and msg.get("vpn_ip") != vpn_ip:
            count += 1

    return count


def view_chat():
    clear()
    banner()

    data = load_chat()
    user = get_user()
    messages = data.get("messages", [])

    print(f"{WHITE}{BOLD}General Chat:{RESET}\n")

    if not messages:
        print(f"{YELLOW}No messages yet.{RESET}")
        pause()
        return

    for msg in messages[-50:]:
        role = msg.get("role", "standard")
        discord_name = msg.get("discord_name", "N/A")
        display_name = msg.get("from", "unknown")

        if discord_name and discord_name != "N/A":
            name = discord_name
        else:
            name = display_name

        if role == "admin":
            color = RED + BOLD
            label = "ADMIN"
        else:
            color = CYAN
            label = "USER"

        icon = "👑" if role == "admin" else "💬"
        time_str = msg.get("time", "")
        short_time = time_str.split(" ")[1][:5] if " " in time_str else time_str

        print(f"{GREEN}{'-' * 46}{RESET}")
        print(f"{color}{icon} {name}  •  {label}{RESET}")
        print(f"{YELLOW}🕒 {short_time}{RESET}")
        print()
        print(f"{WHITE}   {msg.get('message')}{RESET}")
        print(f"{GREEN}{'-' * 46}{RESET}\n")

    data["last_seen"][user["vpn_ip"]] = now()
    save_chat(data)

    pause()


def send_message():
    clear()
    banner()

    user = get_user()
    data = load_chat()

    vpn_ip = user.get("vpn_ip", "unknown")
    current_time = int(time.time())
    last_sent = int(data.get("last_sent", {}).get(vpn_ip, 0))

    if current_time - last_sent < 5:
        wait = 5 - (current_time - last_sent)
        print(f"{RED}Slow down.{RESET} {YELLOW}Wait {wait}s before sending another message.{RESET}")
        pause()
        return

    print(f"{WHITE}{BOLD}Send Message To General Chat:{RESET}\n")
    print(f"{YELLOW}Keep chat respectful. Do not spam.{RESET}\n")

    msg = input(f"{YELLOW}Message:{RESET} ").strip()

    if not msg:
        print(f"{RED}Message required.{RESET}")
        pause()
        return

    data["messages"].append({
        "from": user["display_name"],
        "role": user["role"],
        "vpn_ip": user["vpn_ip"],
        "discord_name": user["discord_name"],
        "discord_id": user["discord_id"],
        "time": now(),
        "message": msg
    })

    data["last_sent"][user["vpn_ip"]] = int(time.time())
    save_chat(data)

    print(f"\n{GREEN}Message sent.{RESET}")
    pause()

def clear_chat():
    clear()
    banner()

    user = get_user()
    if user["role"] != "admin":
        print(f"{RED}Admin only.{RESET}")
        pause()
        return

    confirm = input(f"{RED}Clear ALL general chat messages? Type YES:{RESET} ").strip()

    if confirm.upper() != "YES":
        print(f"{YELLOW}Cancelled.{RESET}")
        pause()
        return

    save_chat({"messages": []})
    print(f"{GREEN}General chat cleared.{RESET}")
    pause()

def main():
    while True:
        clear()
        banner()

        user = get_user()
        is_admin = user["role"] == "admin"
        data = load_chat()
        new_count = new_message_count(data, user)

        if new_count > 0:
            print(f"{WHITE}{BOLD}General Chat:{RESET} {GREEN}{BOLD}({new_count} new){RESET}\n")
        else:
            print(f"{WHITE}{BOLD}General Chat:{RESET}\n")
        print(f"{CYAN}{BOLD}1.{RESET}  {WHITE}View Chat{RESET}")
        print(f"{CYAN}{BOLD}2.{RESET}  {WHITE}Send Message{RESET}")
        if is_admin:
            print(f"{CYAN}{BOLD}3.{RESET}  {WHITE}Clear Chat{RESET}")
        print(f"{CYAN}{BOLD}0.{RESET}  {WHITE}Back / Exit{RESET}")
        print()
        print(f"{GREEN}{'-' * 46}{RESET}")

        choice = input(f"{YELLOW}Select an option:{RESET} ").strip()

        if choice == "1":
            view_chat()
        elif choice == "2":
            send_message()
        elif choice == "3" and is_admin:
            clear_chat()
        elif choice == "0":
            break
        else:
            print(f"{RED}Invalid option.{RESET}")
            pause()

if __name__ == "__main__":
    main()
