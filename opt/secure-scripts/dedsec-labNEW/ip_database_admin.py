#!/usr/bin/env python3
import json
import os

DATA_DIR = "/opt/secure-scripts/dedsec-labNEW/data/ip_database"
JSON_DB = os.path.join(DATA_DIR, "ip_database.json")
TEXT_DB = os.path.join(DATA_DIR, "list.txt")

RESET = "\033[0m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
WHITE = "\033[97m"
RED = "\033[31m"
BOLD = "\033[1m"

os.makedirs(DATA_DIR, exist_ok=True)


def clear():
    os.system("clear")


def pause():
    input(f"\n{YELLOW}Press Enter to continue...{RESET}")


def banner():
    clear()
    import importlib.util
    banner_path = "/opt/secure-scripts/dedsec-labNEW/utils/banner.py"
    spec = importlib.util.spec_from_file_location("dedsec_banner", banner_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    def noop_theme():
        return None

    mod.dedsec_banner(GREEN, CYAN, RESET, BOLD, noop_theme)


def load_entries():
    if not os.path.isfile(JSON_DB):
        return []
    try:
        with open(JSON_DB, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def save_entries(entries):
    with open(JSON_DB, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)


def rewrite_text_list(entries):
    with open(TEXT_DB, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write("=" * 54 + "\n")
            f.write(f"Added: {entry['created_at']}\n")
            f.write(f"IP Address: {entry['target']}\n")
            f.write(f"Tags: {entry['tags']}\n")
            f.write(f"Ports: {entry['ports']}\n\n")


def view_saved_list():
    banner()
    print(f"{WHITE}{BOLD}Saved IP Database List{RESET}\n")

    if not os.path.isfile(TEXT_DB):
        print(f"{RED}No saved list found yet.{RESET}")
        pause()
        return

    with open(TEXT_DB, "r", encoding="utf-8") as f:
        content = f.read().strip()

    if not content:
        print(f"{RED}Saved list is empty.{RESET}")
    else:
        print(content)

    pause()


def delete_entry():
    banner()
    print(f"{WHITE}{BOLD}Delete IP Database Entry{RESET}\n")

    entries = load_entries()
    if not entries:
        print(f"{RED}No entries found.{RESET}")
        pause()
        return

    for i, entry in enumerate(entries, start=1):
        print(f"{CYAN}{BOLD}[{i}]{RESET} {WHITE}{entry.get('target', 'N/A')}{RESET}")
        print(f"  {WHITE}Added:{RESET} {entry.get('created_at', '')}")
        print(f"  {WHITE}Tags:{RESET} {entry.get('tags', '')}")
        print(f"  {WHITE}Ports:{RESET} {entry.get('ports', '')}")
        print(f"{GREEN}{'-' * 46}{RESET}")

    choice = input(f"{YELLOW}Enter entry number to delete:{RESET} ").strip()

    if not choice.isdigit():
        print(f"\n{RED}Invalid entry number.{RESET}")
        pause()
        return

    index = int(choice) - 1
    if index < 0 or index >= len(entries):
        print(f"\n{RED}Entry number out of range.{RESET}")
        pause()
        return

    deleted = entries.pop(index)
    save_entries(entries)
    rewrite_text_list(entries)

    print(f"\n{GREEN}Deleted:{RESET} {WHITE}{deleted.get('target', 'N/A')}{RESET}")
    pause()


while True:
    banner()
    print(f"{WHITE}{BOLD}IP Database Admin Menu{RESET}\n")
    print(f"{CYAN}{BOLD}1.{RESET}  {WHITE}View Saved List{RESET}")
    print(f"{CYAN}{BOLD}2.{RESET}  {WHITE}Delete IP Entry{RESET}")
    print(f"{CYAN}{BOLD}0.{RESET}  {WHITE}Back{RESET}")
    print()
    print(f"{GREEN}{'-' * 46}{RESET}")

    choice = input(f"{YELLOW}Select an option:{RESET} ").strip()

    if choice == "1":
        view_saved_list()
    elif choice == "2":
        delete_entry()
    elif choice == "0":
        print(f"{YELLOW}Goodbye.{RESET}")
        break
    else:
        print(f"{RED}Invalid option.{RESET}")
        pause()
