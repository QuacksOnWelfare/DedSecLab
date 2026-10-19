#!/usr/bin/env python3
import os
import json
import shutil
import subprocess
import importlib.util
from datetime import datetime

BASE_DIR = "/opt/secure-scripts/dedsec-labNEW"
THEMES_FILE = os.path.join(BASE_DIR, "user_themes.json")

SSHD = "/etc/ssh/sshd_config"
BACKUP = "/etc/ssh/sshd_config.owner-wrapper-safe"
STAMP = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

START = "# 👑 ROOT OWNER -> ALL root SSH goes through owner wrapper"
MATCH = "Match User root"
WRAPPER = "root_owner_wrapper.py"

RESET = "\033[0m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
WHITE = "\033[97m"
RED = "\033[31m"
BOLD = "\033[1m"


def clear():
    os.system("clear")


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


def banner():
    apply_theme()

    banner_path = os.path.join(BASE_DIR, "utils", "banner.py")

    if not os.path.isfile(banner_path):
        print(f"{GREEN}{BOLD}DEDSEC SFTP Maintenance Window{RESET}")
        print(f"{GREEN}{'-' * 46}{RESET}")
        return

    spec = importlib.util.spec_from_file_location("dedsec_banner", banner_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.dedsec_banner(GREEN, CYAN, RESET, BOLD, apply_theme)


def run(cmd):
    return subprocess.run(cmd, text=True, capture_output=True)


def test_and_restart():
    test = run(["/usr/sbin/sshd", "-t", "-f", SSHD])

    if test.returncode != 0:
        print(f"{RED}❌ sshd config test failed:{RESET}")
        print(test.stderr)
        return False

    for service in ["ssh", "sshd"]:
        restart = run(["systemctl", "restart", service])

        if restart.returncode == 0:
            return True

    print(f"{RED}❌ SSH restart failed:{RESET}")
    print(f"{YELLOW}Could not restart SSH using ssh or sshd.{RESET}")
    return False


def disable_wrapper():
    shutil.copy2(SSHD, BACKUP)
    shutil.copy2(SSHD, f"{SSHD}.pre-sftp-window-{STAMP}")

    with open(SSHD, "r", encoding="utf-8") as f:
        lines = f.readlines()

    out = []
    in_root_block = False
    i = 0

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if stripped.startswith(MATCH) and WRAPPER in "".join(lines[i:i + 8]):
            in_root_block = True
            out.append("# " + line if not line.startswith("#") else line)
            i += 1
            continue

        if in_root_block:
            if stripped.startswith("Match ") and not stripped.startswith(MATCH):
                in_root_block = False
                out.append(line)
            else:
                out.append("# " + line if line.strip() and not line.startswith("#") else line)

            i += 1
            continue

        out.append(line)
        i += 1

    with open(SSHD, "w", encoding="utf-8") as f:
        f.writelines(out)

    return test_and_restart()


def restore_wrapper():
    if not os.path.isfile(BACKUP):
        print(f"{RED}❌ No safe backup found.{RESET}")
        return False

    shutil.copy2(BACKUP, SSHD)
    return test_and_restart()


clear()
banner()

print(f"{WHITE}{BOLD}SFTP Maintenance Window:{RESET}\n")
print(f"{CYAN}{BOLD}1.{RESET}  {WHITE}Open temporary FileZilla/SFTP access{RESET}")
print(f"{CYAN}{BOLD}2.{RESET}  {WHITE}Restore root wrapper now{RESET}")
print(f"{CYAN}{BOLD}0.{RESET}  {WHITE}Exit{RESET}")
print()
print(f"{GREEN}{'-' * 46}{RESET}")

choice = input(f"{YELLOW}Select an option:{RESET} ").strip()

if choice == "1":
    print(f"\n{YELLOW}Opening temporary SFTP access...{RESET}")

    if disable_wrapper():
        print(f"{GREEN}✅ Root wrapper temporarily disabled.{RESET}")
        print(f"{WHITE}Use FileZilla now.{RESET}")

        input(f"\n{YELLOW}Press Enter AFTER you finish downloading files...{RESET}")

        print(f"{YELLOW}Restoring root wrapper...{RESET}")

        if restore_wrapper():
            print(f"{GREEN}✅ Root wrapper restored.{RESET}")
        else:
            print(f"{RED}❌ Restore failed. Use VPS console and restore manually.{RESET}")

elif choice == "2":
    print(f"\n{YELLOW}Restoring root wrapper...{RESET}")

    if restore_wrapper():
        print(f"{GREEN}✅ Root wrapper restored.{RESET}")

else:
    print(f"{YELLOW}Goodbye.{RESET}")


