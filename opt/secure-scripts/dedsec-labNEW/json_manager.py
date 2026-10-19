#!/usr/bin/env python3

import json
import os
import shutil
from collections import defaultdict
from datetime import datetime


# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_FILE = "/opt/secure-scripts/dedsec-labNEW/ip_database.json"
BACKUP_DIR = "/opt/secure-scripts/dedsec-labNEW/ip_databasebkups"

# ============================================================
# COLORS
# ============================================================

class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"

    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GREY = "\033[90m"


# ============================================================
# SCREEN / UI
# ============================================================

def clear_screen():
    os.system("clear" if os.name != "nt" else "cls")


def banner():
    print(C.CYAN + C.BOLD)
    print("╔══════════════════════════════════════════════════════╗")
    print("║              JSON IP DATABASE MANAGER                ║")
    print("╠══════════════════════════════════════════════════════╣")
    print("║  Duplicate detection / editing / searching          ║")
    print("╚══════════════════════════════════════════════════════╝")
    print(C.RESET)


def pause():
    input("\nPress ENTER to continue...")


# ============================================================
# JSON LOAD / SAVE
# ============================================================

def load_json(filename):
    try:
        with open(filename, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, list):
            print(
                C.RED +
                "ERROR: JSON root must be a list." +
                C.RESET
            )
            return None

        return data

    except FileNotFoundError:
        print(
            C.RED +
            f"File not found: {filename}" +
            C.RESET
        )
        return None

    except json.JSONDecodeError as e:
        print(
            C.RED +
            f"Invalid JSON: {e}" +
            C.RESET
        )
        return None

    except Exception as e:
        print(
            C.RED +
            f"Error loading file: {e}" +
            C.RESET
        )
        return None


def save_json(filename, data, backup=True):

    try:

        # ----------------------------------------------------
        # CREATE BACKUP
        # ----------------------------------------------------

        if backup and os.path.exists(filename):

            os.makedirs(
                BACKUP_DIR,
                exist_ok=True
            )

            timestamp = datetime.now().strftime(
                "%Y%m%d_%H%M%S"
            )

            backup_file = os.path.join(
                BACKUP_DIR,
                f"ip_database_{timestamp}.json"
            )

            shutil.copy2(
                filename,
                backup_file
            )

            print(
                C.GREEN +
                f"\nBackup created:\n{backup_file}" +
                C.RESET
            )

        # ----------------------------------------------------
        # SAVE JSON
        # ----------------------------------------------------

        with open(
            filename,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                data,
                f,
                indent=2,
                ensure_ascii=False
            )

            f.write("\n")

        print(
            C.GREEN +
            "\n✓ Database saved successfully." +
            C.RESET
        )

        print(
            f"File: {filename}"
        )

        return True

    except Exception as e:

        print(
            C.RED +
            f"\nError saving JSON: {e}" +
            C.RESET
        )

        return False


# ============================================================
# BACKUP MANAGER
# ============================================================

def get_backups():

    """
    Return backup files sorted newest first.

    Only files directly inside BACKUP_DIR are considered.
    """

    if not os.path.isdir(BACKUP_DIR):
        return []

    backups = []

    for filename in os.listdir(BACKUP_DIR):

        path = os.path.join(
            BACKUP_DIR,
            filename
        )

        if not os.path.isfile(path):
            continue

        try:

            stat = os.stat(path)

            backups.append({
                "name": filename,
                "path": path,
                "size": stat.st_size,
                "modified": stat.st_mtime
            })

        except OSError:
            continue

    backups.sort(
        key=lambda x: x["modified"],
        reverse=True
    )

    return backups


def format_size(size):

    if size < 1024:
        return f"{size} B"

    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"

    if size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.1f} MB"

    return f"{size / (1024 * 1024 * 1024):.1f} GB"


def manage_backups():

    while True:

        clear_screen()
        banner()

        print(
            C.CYAN +
            C.BOLD +
            "━━ BACKUP MANAGER ━━" +
            C.RESET
        )

        print(
            f"\nBackup folder: "
            f"{C.CYAN}{BACKUP_DIR}/{C.RESET}"
        )

        backups = get_backups()

        # ----------------------------------------------------
        # NO BACKUPS
        # ----------------------------------------------------

        if not backups:

            print(
                C.YELLOW +
                "\nNo backups found." +
                C.RESET
            )

            print(
                "\nBackups will automatically be created "
                "when you save the database."
            )

            pause()
            return

        # ----------------------------------------------------
        # LIST BACKUPS
        # ----------------------------------------------------

        print()

        print(
            f"{C.BOLD}"
            f"{'#':<5}"
            f"{'Filename':<45}"
            f"{'Size':<12}"
            f"{'Date'}"
            f"{C.RESET}"
        )

        print(
            C.GREY +
            "-" * 85 +
            C.RESET
        )

        for number, backup in enumerate(
            backups,
            start=1
        ):

            date = datetime.fromtimestamp(
                backup["modified"]
            ).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            print(
                f"{number:<5}"
                f"{backup['name']:<45}"
                f"{format_size(backup['size']):<12}"
                f"{date}"
            )

        # ----------------------------------------------------
        # BACKUP MENU
        # ----------------------------------------------------

        print()

        print("1. Delete one backup")
        print("2. Delete all backups")
        print("0. Return to main menu")

        choice = input(
            C.BOLD +
            "\nSelect option: " +
            C.RESET
        ).strip()

        # ----------------------------------------------------
        # DELETE ONE
        # ----------------------------------------------------

        if choice == "1":

            try:

                number = int(
                    input(
                        f"\nEnter backup number "
                        f"(1-{len(backups)}): "
                    )
                )

                if number < 1 or number > len(backups):
                    raise ValueError

            except ValueError:

                print(
                    C.RED +
                    "\nInvalid backup number." +
                    C.RESET
                )

                pause()
                continue

            backup = backups[number - 1]

            print()

            print(
                C.YELLOW +
                f"Selected backup:\n"
                f"{backup['name']}" +
                C.RESET
            )

            print(
                f"Size: "
                f"{format_size(backup['size'])}"
            )

            confirmation = input(
                C.RED +
                "\nType YES to permanently delete this backup: " +
                C.RESET
            ).strip()

            if confirmation != "YES":

                print(
                    C.YELLOW +
                    "\n✓ Deletion cancelled." +
                    C.RESET
                )

                pause()
                continue

            try:

                os.remove(
                    backup["path"]
                )

                print(
                    C.GREEN +
                    f"\n✓ Deleted: {backup['name']}" +
                    C.RESET
                )

            except Exception as e:

                print(
                    C.RED +
                    f"\nCould not delete backup: {e}" +
                    C.RESET
                )

            pause()

        # ----------------------------------------------------
        # DELETE ALL
        # ----------------------------------------------------

        elif choice == "2":

            print()

            print(
                C.RED +
                C.BOLD +
                f"⚠ This will permanently delete "
                f"ALL {len(backups)} backups." +
                C.RESET
            )

            print(
                C.YELLOW +
                "\nYour current ip_database.json will NOT "
                "be deleted." +
                C.RESET
            )

            print(
                C.YELLOW +
                "Only files inside the backups folder "
                "will be removed." +
                C.RESET
            )

            confirmation = input(
                C.RED +
                "\nType YES to delete ALL backups: " +
                C.RESET
            ).strip()

            if confirmation != "YES":

                print(
                    C.YELLOW +
                    "\n✓ Deletion cancelled." +
                    C.RESET
                )

                pause()
                continue

            deleted = 0
            failed = 0

            for backup in backups:

                try:

                    os.remove(
                        backup["path"]
                    )

                    deleted += 1

                except Exception:
                    failed += 1

            print()

            print(
                C.GREEN +
                f"✓ Deleted {deleted} backup(s)." +
                C.RESET
            )

            if failed:

                print(
                    C.RED +
                    f"✗ Failed to delete {failed} backup(s)." +
                    C.RESET
                )

            pause()

        # ----------------------------------------------------
        # RETURN
        # ----------------------------------------------------

        elif choice == "0":

            return

        else:

            print(
                C.RED +
                "\nInvalid option." +
                C.RESET
            )

            pause()


# ============================================================
# ENTRY HELPERS
# ============================================================

def get_label(entry):
    return str(
        entry.get("label", "")
    ).strip()


def get_ip(entry):
    return str(
        entry.get("ip", "")
    ).strip()


def print_entry(index, entry):

    print(
        C.WHITE +
        f"\n[{index}]" +
        C.RESET
    )

    print(
        f"  User       : {get_label(entry)}"
    )

    print(
        f"  IP         : {get_ip(entry)}"
    )

    print(
        f"  Country    : {entry.get('country', '')}"
    )

    print(
        f"  City       : {entry.get('city', '')}"
    )

    print(
        f"  ISP        : {entry.get('isp', '')}"
    )

    print(
        f"  ASN        : {entry.get('asn', '')}"
    )

    print(
        f"  Network    : {entry.get('network', '')}"
    )

    print(
        f"  Status     : {entry.get('status', '')}"
    )

    print(
        f"  Added      : {entry.get('added', '')}"
    )

    print(
        f"  CountryCode: {entry.get('country_code', '')}"
    )

    print(
        f"  Notes      : {entry.get('notes', '')}"
    )


# ============================================================
# DATABASE STATISTICS
# ============================================================

def database_stats(data):

    users = defaultdict(list)
    ips = defaultdict(list)

    for index, entry in enumerate(data):

        label = get_label(entry).lower()
        ip = get_ip(entry)

        if label:
            users[label].append(index)

        if ip:
            ips[ip].append(index)

    duplicate_users = {
        key: indexes
        for key, indexes in users.items()
        if len(indexes) > 1
    }

    duplicate_ips = {
        key: indexes
        for key, indexes in ips.items()
        if len(indexes) > 1
    }

    exact_duplicates = []

    for label, indexes in users.items():

        if len(indexes) > 1:

            same_ips = defaultdict(list)

            for index in indexes:

                ip = get_ip(
                    data[index]
                )

                same_ips[ip].append(index)

            for ip, same_indexes in same_ips.items():

                if len(same_indexes) > 1:

                    exact_duplicates.append(
                        (
                            label,
                            ip,
                            same_indexes
                        )
                    )

    return (
        duplicate_users,
        duplicate_ips,
        exact_duplicates
    )


# ============================================================
# DUPLICATE SCANNER
# ============================================================

def scan_duplicates(data):

    print(
        C.CYAN +
        C.BOLD +
        "\nScanning database...\n" +
        C.RESET
    )

    (
        duplicate_users,
        duplicate_ips,
        exact_duplicates
    ) = database_stats(data)

    print(
        f"Total entries: "
        f"{C.BOLD}{len(data)}{C.RESET}"
    )

    print(
        f"Duplicate usernames: "
        f"{C.YELLOW}{len(duplicate_users)}{C.RESET}"
    )

    print(
        f"Duplicate IPs: "
        f"{C.YELLOW}{len(duplicate_ips)}{C.RESET}"
    )

    print(
        f"Exact user + IP duplicate groups: "
        f"{C.RED}{len(exact_duplicates)}{C.RESET}"
    )

    # --------------------------------------------------------
    # DUPLICATE USERNAMES
    # --------------------------------------------------------

    if duplicate_users:

        print(
            C.YELLOW +
            C.BOLD +
            "\n━━ DUPLICATE USERNAMES ━━" +
            C.RESET
        )

        for label, indexes in duplicate_users.items():

            print(
                f"\n{C.YELLOW}{label}{C.RESET} "
                f"appears {len(indexes)} times:"
            )

            for index in indexes:

                print_entry(
                    index,
                    data[index]
                )

    # --------------------------------------------------------
    # DUPLICATE IPS
    # --------------------------------------------------------

    if duplicate_ips:

        print(
            C.YELLOW +
            C.BOLD +
            "\n━━ DUPLICATE IPs ━━" +
            C.RESET
        )

        for ip, indexes in duplicate_ips.items():

            print(
                f"\n{C.YELLOW}{ip}{C.RESET} "
                f"appears {len(indexes)} times:"
            )

            for index in indexes:

                print_entry(
                    index,
                    data[index]
                )

    # --------------------------------------------------------
    # EXACT DUPLICATES
    # --------------------------------------------------------

    if exact_duplicates:

        print(
            C.RED +
            C.BOLD +
            "\n━━ EXACT USER + IP DUPLICATES ━━" +
            C.RESET
        )

        for label, ip, indexes in exact_duplicates:

            print(
                f"\n{C.RED}Duplicate:{C.RESET} "
                f"{label} @ {ip}"
            )

            print(
                f"Occurrences: {len(indexes)}"
            )

            for index in indexes:

                print(
                    f"  Entry #{index}"
                )

    # --------------------------------------------------------
    # CLEAN
    # --------------------------------------------------------

    if not duplicate_users and not duplicate_ips:

        print(
            C.GREEN +
            "\n✓ No duplicate usernames or IPs detected." +
            C.RESET
        )


# ============================================================
# REMOVE EXACT DUPLICATES
# ============================================================

def remove_exact_duplicates(data):

    """
    Exact duplicate definition:

        label + ip

    The FIRST occurrence is kept.

    Example:

        User/IP appears 2 times:
            KEEP 1
            REMOVE 1

        User/IP appears 3 times:
            KEEP 1
            REMOVE 2
    """

    groups = defaultdict(list)

    # --------------------------------------------------------
    # GROUP ENTRIES
    # --------------------------------------------------------

    for index, entry in enumerate(data):

        label = get_label(entry).strip().lower()
        ip = get_ip(entry).strip()

        if not label and not ip:
            continue

        key = (
            label,
            ip
        )

        groups[key].append(index)

    # --------------------------------------------------------
    # FIND DUPLICATE GROUPS
    # --------------------------------------------------------

    duplicate_groups = {
        key: indexes
        for key, indexes in groups.items()
        if len(indexes) > 1
    }

    if not duplicate_groups:

        print(
            C.GREEN +
            "\n✓ No exact username + IP duplicates found." +
            C.RESET
        )

        return data

    # --------------------------------------------------------
    # DETERMINE ENTRIES TO REMOVE
    # --------------------------------------------------------

    indexes_to_delete = []

    for indexes in duplicate_groups.values():

        indexes_to_delete.extend(
            indexes[1:]
        )

    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    print()

    print(
        C.RED +
        C.BOLD +
        "╔══════════════════════════════════════════════════╗" +
        C.RESET
    )

    print(
        C.RED +
        C.BOLD +
        "║              DUPLICATES DETECTED                ║" +
        C.RESET
    )

    print(
        C.RED +
        C.BOLD +
        "╚══════════════════════════════════════════════════╝" +
        C.RESET
    )

    print()

    print(
        f"Total database entries : "
        f"{C.CYAN}{len(data)}{C.RESET}"
    )

    print(
        f"Duplicate groups       : "
        f"{C.YELLOW}{len(duplicate_groups)}{C.RESET}"
    )

    print(
        f"Entries to remove      : "
        f"{C.RED}{len(indexes_to_delete)}{C.RESET}"
    )

    print(
        f"Entries after cleanup  : "
        f"{C.GREEN}{len(data) - len(indexes_to_delete)}{C.RESET}"
    )

    print()

    print(
        C.YELLOW +
        "The FIRST occurrence of every username + IP pair " +
        "will be kept." +
        C.RESET
    )

    # --------------------------------------------------------
    # SHOW GROUPS
    # --------------------------------------------------------

    print()

    print(
        C.CYAN +
        C.BOLD +
        "━━ DUPLICATE GROUPS ━━" +
        C.RESET
    )

    for number, (
        (label, ip),
        indexes
    ) in enumerate(
        duplicate_groups.items(),
        start=1
    ):

        print()

        print(
            C.BOLD +
            f"[{number}] {label} @ {ip}" +
            C.RESET
        )

        print(
            f"    Occurrences : "
            f"{C.YELLOW}{len(indexes)}{C.RESET}"
        )

        print(
            f"    Keep        : "
            f"entry #{indexes[0]} "
            f"{C.GREEN}(FIRST){C.RESET}"
        )

        print(
            f"    Remove      : "
            f"{C.RED}{len(indexes) - 1}{C.RESET}"
        )

        for position, index in enumerate(indexes):

            if position == 0:

                status = (
                    C.GREEN +
                    "KEEP" +
                    C.RESET
                )

            else:

                status = (
                    C.RED +
                    "REMOVE" +
                    C.RESET
                )

            print(
                f"      #{index:<6} {status}"
            )

    # --------------------------------------------------------
    # FINAL CONFIRMATION
    # --------------------------------------------------------

    print()

    print(
        C.YELLOW +
        C.BOLD +
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" +
        C.RESET
    )

    print(
        C.YELLOW +
        f"This will remove {len(indexes_to_delete)} entries." +
        C.RESET
    )

    print(
        C.GREEN +
        f"This will leave "
        f"{len(data) - len(indexes_to_delete)} entries." +
        C.RESET
    )

    print()

    print(
        C.BOLD +
        "Type YES to continue." +
        C.RESET
    )

    print(
        C.GREY +
        "Anything else will cancel." +
        C.RESET
    )

    confirmation = input(
        "\nConfirm deletion: "
    ).strip()

    if confirmation != "YES":

        print(
            C.YELLOW +
            "\n✓ Operation cancelled." +
            C.RESET
        )

        print(
            "No entries were changed."
        )

        return data

    # --------------------------------------------------------
    # DELETE
    # --------------------------------------------------------

    duplicate_set = set(
        indexes_to_delete
    )

    new_data = [
        entry
        for index, entry in enumerate(data)
        if index not in duplicate_set
    ]

    print()

    print(
        C.GREEN +
        C.BOLD +
        "✓ DUPLICATES REMOVED" +
        C.RESET
    )

    print(
        f"Removed : "
        f"{C.RED}{len(indexes_to_delete)}{C.RESET}"
    )

    print(
        f"Kept    : "
        f"{C.GREEN}{len(new_data)}{C.RESET}"
    )

    print()

    print(
        C.YELLOW +
        "Changes are currently only in memory." +
        C.RESET
    )

    print(
        "Use option 9 or 10 to save them."
    )

    return new_data


# ============================================================
# REMOVE DUPLICATE USERNAMES
# ============================================================

def remove_duplicate_users(data):

    """
    Finds usernames that occur multiple times,
    even when the IP addresses are different.

    This does NOT automatically choose which record
    to keep. The user must choose.
    """

    users = defaultdict(list)

    for index, entry in enumerate(data):

        label = get_label(entry).lower()

        if label:
            users[label].append(index)

    duplicates = {
        label: indexes
        for label, indexes in users.items()
        if len(indexes) > 1
    }

    if not duplicates:

        print(
            C.GREEN +
            "\n✓ Every username occurs only once." +
            C.RESET
        )

        return data

    print()

    print(
        C.YELLOW +
        f"⚠ Found {len(duplicates)} usernames "
        f"with multiple entries." +
        C.RESET
    )

    indexes_to_delete = set()

    # --------------------------------------------------------
    # REVIEW EACH USER
    # --------------------------------------------------------

    for label, indexes in duplicates.items():

        print()

        print(
            C.CYAN +
            C.BOLD +
            f"━━ USER: {label} ━━" +
            C.RESET
        )

        for index in indexes:

            print_entry(
                index,
                data[index]
            )

        print()

        print(
            "Choose which entry to keep."
        )

        print(
            "Type S to skip this username."
        )

        while True:

            choice = input(
                f"Keep entry "
                f"[{', '.join(map(str, indexes))}] "
                f"or [S]kip: "
            ).strip().lower()

            if choice == "s":
                break

            try:

                keep = int(choice)

                if keep not in indexes:
                    raise ValueError

                for index in indexes:

                    if index != keep:
                        indexes_to_delete.add(index)

                break

            except ValueError:

                print(
                    C.RED +
                    "Invalid entry number." +
                    C.RESET
                )

    # --------------------------------------------------------
    # NOTHING SELECTED
    # --------------------------------------------------------

    if not indexes_to_delete:

        print(
            C.YELLOW +
            "\nNo entries selected for deletion." +
            C.RESET
        )

        return data

    # --------------------------------------------------------
    # CONFIRM
    # --------------------------------------------------------

    print()

    print(
        C.YELLOW +
        f"⚠ {len(indexes_to_delete)} entries "
        f"are marked for deletion." +
        C.RESET
    )

    confirmation = input(
        "\nType YES to delete them: "
    ).strip()

    if confirmation != "YES":

        print(
            C.YELLOW +
            "\nOperation cancelled." +
            C.RESET
        )

        return data

    # --------------------------------------------------------
    # DELETE
    # --------------------------------------------------------

    new_data = [
        entry
        for index, entry in enumerate(data)
        if index not in indexes_to_delete
    ]

    print(
        C.GREEN +
        f"\n✓ Removed {len(indexes_to_delete)} entries." +
        C.RESET
    )

    return new_data


# ============================================================
# SEARCH
# ============================================================

def search_entries(data):

    query = input(
        "\nSearch username, IP, country, city, ISP or ASN: "
    ).strip().lower()

    if not query:
        return

    matches = []

    for index, entry in enumerate(data):

        searchable = " ".join(
            str(value)
            for value in entry.values()
        ).lower()

        if query in searchable:
            matches.append(index)

    if not matches:

        print(
            C.YELLOW +
            "\nNo matches found." +
            C.RESET
        )

        return

    print()

    print(
        C.GREEN +
        f"Found {len(matches)} matching entries." +
        C.RESET
    )

    for index in matches:

        print_entry(
            index,
            data[index]
        )


# ============================================================
# VIEW ENTRIES
# ============================================================

def view_entries(data):

    if not data:

        print(
            C.YELLOW +
            "\nDatabase is empty." +
            C.RESET
        )

        return

    try:

        amount = int(
            input(
                f"\nShow how many entries? "
                f"(1-{len(data)}): "
            )
        )

        if amount < 1:
            return

        amount = min(
            amount,
            len(data)
        )

    except ValueError:

        print(
            C.RED +
            "Invalid number." +
            C.RESET
        )

        return

    for index in range(amount):

        print_entry(
            index,
            data[index]
        )


# ============================================================
# EDIT ENTRY
# ============================================================

def edit_entry(data):

    if not data:

        print(
            C.YELLOW +
            "\nDatabase is empty." +
            C.RESET
        )

        return

    try:

        index = int(
            input(
                f"\nEntry number "
                f"(0-{len(data) - 1}): "
            )
        )

        if index < 0 or index >= len(data):
            raise ValueError

    except ValueError:

        print(
            C.RED +
            "Invalid entry number." +
            C.RESET
        )

        return

    entry = data[index]

    print_entry(
        index,
        entry
    )

    print()

    print(
        C.CYAN +
        "Leave a field blank to keep its current value." +
        C.RESET
    )

    fields = [
        "ip",
        "label",
        "network",
        "country",
        "notes",
        "status",
        "added",
        "country_code",
        "city",
        "isp",
        "asn",
    ]

    for field in fields:

        current = entry.get(
            field,
            ""
        )

        value = input(
            f"{field} [{current}]: "
        )

        if value.strip():

            entry[field] = value.strip()

    print()

    print(
        C.GREEN +
        "✓ Entry updated." +
        C.RESET
    )


# ============================================================
# DELETE SINGLE ENTRY
# ============================================================

def delete_entry(data):

    if not data:

        print(
            C.YELLOW +
            "\nDatabase is empty." +
            C.RESET
        )

        return data

    try:

        index = int(
            input(
                f"\nEntry number "
                f"(0-{len(data) - 1}): "
            )
        )

        if index < 0 or index >= len(data):
            raise ValueError

    except ValueError:

        print(
            C.RED +
            "Invalid entry number." +
            C.RESET
        )

        return data

    print_entry(
        index,
        data[index]
    )

    confirmation = input(
        C.RED +
        "\nType YES to delete this entry: " +
        C.RESET
    ).strip()

    if confirmation != "YES":

        print(
            C.YELLOW +
            "Cancelled." +
            C.RESET
        )

        return data

    del data[index]

    print(
        C.GREEN +
        "\n✓ Entry deleted." +
        C.RESET
    )

    return data


# ============================================================
# MAIN MENU
# ============================================================

def main():

    filename = DEFAULT_FILE

    data = load_json(
        filename
    )

    if data is None:

        print(
            C.RED +
            "\nCould not load the database." +
            C.RESET
        )

        return

    while True:

        clear_screen()

        banner()

        print(
            f"File: "
            f"{C.CYAN}{filename}{C.RESET}"
        )

        print(
            f"Entries: "
            f"{C.GREEN}{len(data)}{C.RESET}"
        )

        print()

        print("1. View entries")
        print("2. Search entries")
        print("3. Scan for duplicates")
        print("4. Remove exact duplicates")
        print("5. Remove duplicate usernames")
        print("6. Edit entry")
        print("7. Delete entry")
        print("8. Manage backups")
        print("9. Save database")
        print("10. Save & exit")
        print("0. Exit without saving")

        choice = input(
            C.BOLD +
            "\nSelect option: " +
            C.RESET
        ).strip()

        # ----------------------------------------------------
        # VIEW
        # ----------------------------------------------------

        if choice == "1":

            clear_screen()
            banner()

            view_entries(data)

            pause()

        # ----------------------------------------------------
        # SEARCH
        # ----------------------------------------------------

        elif choice == "2":

            clear_screen()
            banner()

            search_entries(data)

            pause()

        # ----------------------------------------------------
        # SCAN
        # ----------------------------------------------------

        elif choice == "3":

            clear_screen()
            banner()

            scan_duplicates(data)

            pause()

        # ----------------------------------------------------
        # REMOVE EXACT DUPLICATES
        # ----------------------------------------------------

        elif choice == "4":

            clear_screen()
            banner()

            old_count = len(data)

            data = remove_exact_duplicates(
                data
            )

            removed = (
                old_count -
                len(data)
            )

            if removed:

                print()

                print(
                    C.GREEN +
                    f"Database now contains "
                    f"{len(data)} entries." +
                    C.RESET
                )

            pause()

        # ----------------------------------------------------
        # REMOVE DUPLICATE USERNAMES
        # ----------------------------------------------------

        elif choice == "5":

            clear_screen()
            banner()

            old_count = len(data)

            data = remove_duplicate_users(
                data
            )

            removed = (
                old_count -
                len(data)
            )

            if removed:

                print()

                print(
                    C.GREEN +
                    f"Database now contains "
                    f"{len(data)} entries." +
                    C.RESET
                )

            pause()

        # ----------------------------------------------------
        # EDIT
        # ----------------------------------------------------

        elif choice == "6":

            clear_screen()
            banner()

            edit_entry(data)

            pause()

        # ----------------------------------------------------
        # DELETE
        # ----------------------------------------------------

        elif choice == "7":

            clear_screen()
            banner()

            data = delete_entry(
                data
            )

            pause()

        # ----------------------------------------------------
        # BACKUP MANAGER
        # ----------------------------------------------------

        elif choice == "8":

            manage_backups()

        # ----------------------------------------------------
        # SAVE
        # ----------------------------------------------------

        elif choice == "9":

            clear_screen()
            banner()

            save_json(
                filename,
                data,
                backup=True
            )

            pause()

        # ----------------------------------------------------
        # SAVE & EXIT
        # ----------------------------------------------------

        elif choice == "10":

            save_json(
                filename,
                data,
                backup=True
            )

            print(
                C.GREEN +
                "\nGoodbye." +
                C.RESET
            )

            break

        # ----------------------------------------------------
        # EXIT WITHOUT SAVING
        # ----------------------------------------------------

        elif choice == "0":

            print()

            confirmation = input(
                C.YELLOW +
                "Exit without saving? "
                "[y/N]: " +
                C.RESET
            ).strip().lower()

            if confirmation in (
                "y",
                "yes"
            ):

                print(
                    "\nGoodbye."
                )

                break

        # ----------------------------------------------------
        # INVALID
        # ----------------------------------------------------

        else:

            print(
                C.RED +
                "\nInvalid option." +
                C.RESET
            )

            pause()


# ============================================================
# START
# ============================================================

if __name__ == "__main__":
    main()
