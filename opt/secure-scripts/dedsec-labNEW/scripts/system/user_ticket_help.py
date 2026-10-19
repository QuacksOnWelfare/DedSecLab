#!/usr/bin/env python3
import os
import json
import importlib.util
from datetime import datetime

BASE_DIR = "/opt/secure-scripts/dedsec-labNEW"
TICKETS_FILE = os.path.join(BASE_DIR, "tickets.json")
RULES_FILE = os.path.join(BASE_DIR, "access_rules.json")
DISCORD_NOTIFY_SCRIPT = os.path.join(BASE_DIR, "scripts", "system", "discord_notify.py")

RESET = "\033[0m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
WHITE = "\033[97m"
RED = "\033[31m"
BOLD = "\033[1m"



def discord_alert(title, message, color=3447003, event_type="tickets"):
    try:
        spec = importlib.util.spec_from_file_location("discord_notify", DISCORD_NOTIFY_SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.send_discord_alert(title, message, color=color, event_type=event_type)
    except Exception:
        pass


def clear():
    os.system("clear")


def pause():
    input(f"\n{YELLOW}Press Enter to continue...{RESET}")


def banner():
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


def save_tickets(data):
    with open(TICKETS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def get_user_info():
    vpn_ip = os.environ.get("DEDSEC_SOURCE_IP", "unknown")
    display_name = os.environ.get("DEDSEC_USER", "unknown")
    ssh_user = os.environ.get("DEDSEC_SSH_USER", "unknown")

    rules = load_json(RULES_FILE, {})
    user_rule = rules.get("users", {}).get(vpn_ip, {})

    return {
        "vpn_ip": vpn_ip,
        "display_name": user_rule.get("display_name", display_name),
        "ssh_user": user_rule.get("ssh_user", ssh_user),
        "discord_name": user_rule.get("discord_name", "N/A"),
        "discord_id": user_rule.get("discord_id", "N/A"),
        "role": user_rule.get("role", os.environ.get("DEDSEC_ROLE", "standard")),
    }


def load_tickets():
    data = load_json(TICKETS_FILE, {"last_id": 0, "tickets": []})
    data.setdefault("last_id", 0)
    data.setdefault("tickets", [])
    return data


def my_tickets(data, vpn_ip):
    return [t for t in data["tickets"] if t.get("vpn_ip") == vpn_ip]


def open_ticket():
    clear()
    banner()

    user = get_user_info()
    data = load_tickets()

    print(f"{WHITE}{BOLD}Open New Ticket:{RESET}\n")
    print(f"{YELLOW}Note:{RESET} Do not spam tickets or replies. Admins will respond when available.\n")

    subject = input(f"{YELLOW}Subject:{RESET} ").strip()

    if not subject:
        print(f"{RED}Subject required.{RESET}")
        pause()
        return

    message = input(f"{YELLOW}Message:{RESET} ").strip()

    if not message:
        print(f"{RED}Message required.{RESET}")
        pause()
        return

    data["last_id"] += 1
    ticket_id = f"TCK-{data['last_id']:04d}"

    ticket = {
        "ticket_id": ticket_id,
        "status": "open",
        "subject": subject,
        "created_at": now(),
        "updated_at": now(),
        "vpn_ip": user["vpn_ip"],
        "display_name": user["display_name"],
        "ssh_user": user["ssh_user"],
        "discord_name": user["discord_name"],
        "discord_id": user["discord_id"],
        "messages": [
            {
                "from": user["display_name"],
                "role": "user",
                "time": now(),
                "message": message
            }
        ]
    }

    data["tickets"].append(ticket)
    save_tickets(data)

    discord_alert(
        "🎟️ DEDSEC Ticket Created",
        (
            f"🆔 **Ticket:** `{ticket_id}`\n"
            f"👤 **User:** `{user['display_name']}`\n"
            f"🔐 **SSH:** `{user['ssh_user']}`\n"
            f"🌐 **IP:** `{user['vpn_ip']}`\n"
            f"🎭 **Role:** `{user['role']}`\n"
            f"💬 **Discord:** `{user['discord_name']}` / `{user['discord_id']}`\n\n"
            f"📌 **Subject:** `{subject}`\n"
            f"📝 **Message:** {message}"
        ),
        color=15844367,
        event_type="tickets"
    )

    print(f"\n{GREEN}Ticket opened:{RESET} {YELLOW}{ticket_id}{RESET}")
    pause()


def show_ticket(ticket):
    print(f"{GREEN}{'-' * 46}{RESET}")
    print(f"{CYAN}{ticket['ticket_id']}{RESET} | {WHITE}{ticket.get('status', 'unknown').upper()}{RESET}")
    print(f"{WHITE}Subject:{RESET} {YELLOW}{ticket.get('subject', 'N/A')}{RESET}")
    print(f"{WHITE}Updated:{RESET} {YELLOW}{ticket.get('updated_at', 'N/A')}{RESET}")
    print(f"{GREEN}{'-' * 46}{RESET}")

    for msg in ticket.get("messages", []):
        role = msg.get("role", "user")

        if role == "admin":
            name_color = RED + BOLD
        else:
            name_color = CYAN

        print(f"{name_color}[{msg.get('time', 'N/A')}] {msg.get('from', 'unknown')}:{RESET}")
        print(f"{WHITE}{msg.get('message', '')}{RESET}\n")


def view_my_tickets():
    clear()
    banner()

    user = get_user_info()
    data = load_tickets()
    tickets = my_tickets(data, user["vpn_ip"])

    print(f"{WHITE}{BOLD}My Tickets:{RESET}\n")

    if not tickets:
        print(f"{RED}No tickets found.{RESET}")
        pause()
        return

    for i, t in enumerate(tickets, 1):
        print(f"{CYAN}{BOLD}{i}.{RESET} {WHITE}{t['ticket_id']}{RESET} | {YELLOW}{t.get('status', 'unknown')}{RESET} | {t.get('subject', 'N/A')}")

    choice = input(f"\n{YELLOW}Select ticket number or 0 back:{RESET} ").strip()

    if choice == "0":
        return

    if not choice.isdigit() or not (1 <= int(choice) <= len(tickets)):
        print(f"{RED}Invalid choice.{RESET}")
        pause()
        return

    clear()
    banner()
    show_ticket(tickets[int(choice) - 1])
    pause()


def reply_ticket():
    clear()
    banner()

    user = get_user_info()
    data = load_tickets()
    tickets = [t for t in my_tickets(data, user["vpn_ip"]) if t.get("status") != "closed"]

    print(f"{WHITE}{BOLD}Reply To Ticket:{RESET}\n")
    print(f"{YELLOW}Note:{RESET} Do not spam tickets or replies. Admins will respond when available.\n")


    if not tickets:
        print(f"{RED}No open tickets found.{RESET}")
        pause()
        return

    for i, t in enumerate(tickets, 1):
        print(f"{CYAN}{BOLD}{i}.{RESET} {WHITE}{t['ticket_id']}{RESET} | {YELLOW}{t.get('subject', 'N/A')}{RESET}")

    choice = input(f"\n{YELLOW}Select ticket number or 0 back:{RESET} ").strip()

    if choice == "0":
        return

    if not choice.isdigit() or not (1 <= int(choice) <= len(tickets)):
        print(f"{RED}Invalid choice.{RESET}")
        pause()
        return

    ticket = tickets[int(choice) - 1]

    message = input(f"{YELLOW}Reply:{RESET} ").strip()

    if not message:
        print(f"{RED}Message required.{RESET}")
        pause()
        return

    ticket["messages"].append({
        "from": user["display_name"],
        "role": "user",
        "time": now(),
        "message": message
    })
    ticket["status"] = "open"
    ticket["updated_at"] = now()

    save_tickets(data)

    discord_alert(
        "💬 DEDSEC Ticket Reply",
        (
            f"🆔 **Ticket:** `{ticket.get('ticket_id')}`\n"
            f"👤 **User:** `{user['display_name']}`\n"
            f"🔐 **SSH:** `{user['ssh_user']}`\n"
            f"🌐 **IP:** `{user['vpn_ip']}`\n"
            f"💬 **Discord:** `{user['discord_name']}` / `{user['discord_id']}`\n\n"
            f"📌 **Subject:** `{ticket.get('subject', 'N/A')}`\n"
            f"📝 **Reply:** {message}"
        ),
        color=3447003,
        event_type="tickets"
    )

    print(f"\n{GREEN}Reply added.{RESET}")
    pause()


def main():
    while True:
        clear()
        banner()

        print(f"{WHITE}{BOLD}Help / Tickets:{RESET}\n")
        print(f"{CYAN}{BOLD}1.{RESET}  {WHITE}Open New Ticket{RESET}")
        print(f"{CYAN}{BOLD}2.{RESET}  {WHITE}View My Tickets{RESET}")
        print(f"{CYAN}{BOLD}3.{RESET}  {WHITE}Reply To Ticket{RESET}")
        print(f"{CYAN}{BOLD}0.{RESET}  {WHITE}Back / Exit{RESET}")
        print()
        print(f"{GREEN}{'-' * 46}{RESET}")

        choice = input(f"{YELLOW}Select an option:{RESET} ").strip()

        if choice == "1":
            open_ticket()
        elif choice == "2":
            view_my_tickets()
        elif choice == "3":
            reply_ticket()
        elif choice == "0":
            break
        else:
            print(f"{RED}Invalid option.{RESET}")
            pause()


if __name__ == "__main__":
    main()
