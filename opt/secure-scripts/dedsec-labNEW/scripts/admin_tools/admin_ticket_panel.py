#!/usr/bin/env python3
import os
import json
from datetime import datetime

BASE_DIR = "/opt/secure-scripts/dedsec-labNEW"
TICKETS_FILE = os.path.join(BASE_DIR, "tickets.json")

RESET = "\033[0m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
WHITE = "\033[97m"
RED = "\033[31m"
BOLD = "\033[1m"


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


def load_tickets():
    try:
        with open(TICKETS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = {"last_id": 0, "tickets": []}

    data.setdefault("last_id", 0)
    data.setdefault("tickets", [])
    return data


def save_tickets(data):
    with open(TICKETS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def print_ticket_list(tickets):
    if not tickets:
        print(f"{RED}No tickets found.{RESET}")
        return

    for i, t in enumerate(tickets, 1):
        status = t.get("status", "unknown")
        color = GREEN if status == "closed" else YELLOW
        print(f"{CYAN}{BOLD}{i}.{RESET} {WHITE}{t.get('ticket_id')}{RESET} | {color}{status}{RESET} | {YELLOW}{t.get('display_name', 'unknown')}{RESET} | {t.get('vpn_ip', 'N/A')}")
        print(f"   {WHITE}{t.get('subject', 'N/A')}{RESET}")


def show_ticket(ticket):
    print(f"{GREEN}{'-' * 46}{RESET}")
    print(f"{CYAN}{ticket['ticket_id']}{RESET} | {WHITE}{ticket.get('status', 'unknown').upper()}{RESET}")
    print(f"{WHITE}User:{RESET} {YELLOW}{ticket.get('display_name')}{RESET}")
    print(f"{WHITE}VPN IP:{RESET} {YELLOW}{ticket.get('vpn_ip')}{RESET}")
    print(f"{WHITE}Discord:{RESET} {YELLOW}{ticket.get('discord_name', 'N/A')} / {ticket.get('discord_id', 'N/A')}{RESET}")
    print(f"{WHITE}Subject:{RESET} {YELLOW}{ticket.get('subject', 'N/A')}{RESET}")
    print(f"{WHITE}Updated:{RESET} {YELLOW}{ticket.get('updated_at', 'N/A')}{RESET}")
    print(f"{GREEN}{'-' * 46}{RESET}")

    for msg in ticket.get("messages", []):
        role = msg.get("role", "user")

        if role == "admin":
            name_color = RED + BOLD
        else:
            name_color = CYAN

        print(f"{name_color}[{msg.get('time', 'N/A')}] {msg.get('from', 'unknown')} ({role}):{RESET}")
        print(f"{WHITE}{msg.get('message', '')}{RESET}\n")


def select_ticket(filter_status=None):
    data = load_tickets()
    tickets = data["tickets"]

    if filter_status:
        tickets = [t for t in tickets if t.get("status") == filter_status]

    clear()
    banner()
    print_ticket_list(tickets)

    if not tickets:
        pause()
        return None, None

    choice = input(f"\n{YELLOW}Select ticket number or 0 back:{RESET} ").strip()

    if choice == "0":
        return None, None

    if not choice.isdigit() or not (1 <= int(choice) <= len(tickets)):
        print(f"{RED}Invalid choice.{RESET}")
        pause()
        return None, None

    return data, tickets[int(choice) - 1]


def view_open():
    data, ticket = select_ticket("open")
    if not ticket:
        return
    clear()
    banner()
    show_ticket(ticket)
    pause()


def view_all():
    data, ticket = select_ticket(None)
    if not ticket:
        return
    clear()
    banner()
    show_ticket(ticket)
    pause()


def reply_ticket():
    data, ticket = select_ticket(None)
    if not ticket:
        return

    clear()
    banner()
    show_ticket(ticket)

    print(f"{YELLOW}Note:{RESET} Do not spam replies. Users will see your response when they check tickets.\n")
    message = input(f"{YELLOW}Admin reply:{RESET} ").strip()

    if not message:
        print(f"{RED}Message required.{RESET}")
        pause()
        return

    ticket["messages"].append({
        "from": "admin",
        "role": "admin",
        "time": now(),
        "message": message
    })
    ticket["status"] = "open"
    ticket["updated_at"] = now()

    save_tickets(data)
    print(f"\n{GREEN}Reply added.{RESET}")
    pause()


def close_ticket():
    data, ticket = select_ticket(None)
    if not ticket:
        return

    ticket["status"] = "closed"
    ticket["updated_at"] = now()
    save_tickets(data)

    print(f"{GREEN}Ticket closed:{RESET} {YELLOW}{ticket['ticket_id']}{RESET}")
    pause()


def delete_ticket():
    data, ticket = select_ticket(None)
    if not ticket:
        return

    confirm = input(f"{RED}Delete {ticket['ticket_id']} permanently? Type YES:{RESET} ").strip()

    if confirm.upper() != "YES":
        print(f"{YELLOW}Cancelled.{RESET}")
        pause()
        return

    data["tickets"] = [t for t in data["tickets"] if t.get("ticket_id") != ticket.get("ticket_id")]
    save_tickets(data)

    print(f"{GREEN}Ticket deleted.{RESET}")
    pause()


def main():
    while True:
        clear()
        banner()

        data = load_tickets()
        open_count = len([t for t in data["tickets"] if t.get("status") == "open"])

        print(f"{WHITE}{BOLD}Admin Ticket Panel:{RESET} {YELLOW}({open_count} open){RESET}\n")
        print(f"{CYAN}{BOLD}1.{RESET}  {WHITE}View Open Tickets{RESET}")
        print(f"{CYAN}{BOLD}2.{RESET}  {WHITE}View All Tickets{RESET}")
        print(f"{CYAN}{BOLD}3.{RESET}  {WHITE}Reply To Ticket{RESET}")
        print(f"{CYAN}{BOLD}4.{RESET}  {WHITE}Close Ticket{RESET}")
        print(f"{CYAN}{BOLD}5.{RESET}  {WHITE}Delete Ticket{RESET}")
        print(f"{CYAN}{BOLD}0.{RESET}  {WHITE}Back / Exit{RESET}")
        print()
        print(f"{GREEN}{'-' * 46}{RESET}")

        choice = input(f"{YELLOW}Select an option:{RESET} ").strip()

        if choice == "1":
            view_open()
        elif choice == "2":
            view_all()
        elif choice == "3":
            reply_ticket()
        elif choice == "4":
            close_ticket()
        elif choice == "5":
            delete_ticket()
        elif choice == "0":
            break
        else:
            print(f"{RED}Invalid option.{RESET}")
            pause()


if __name__ == "__main__":
    main()
