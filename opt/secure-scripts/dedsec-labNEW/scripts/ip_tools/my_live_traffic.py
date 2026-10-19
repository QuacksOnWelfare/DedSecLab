#!/usr/bin/env python3
import os
import sys
import json
import signal
import subprocess
import threading
import time

RESET = "\033[0m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
WHITE = "\033[97m"
RED = "\033[31m"
BOLD = "\033[1m"

BASE_DIR = "/opt/secure-scripts/dedsec-labNEW"
RULES_FILE = os.path.join(BASE_DIR, "access_rules.json")


def auto_root():
    if os.geteuid() != 0:
        env_args = []
        for key in [
            "DEDSEC_SOURCE_IP",
            "DEDSEC_USER",
            "DEDSEC_SSH_USER",
            "DEDSEC_ROLE",
            "SSH_CONNECTION"
        ]:
            value = os.environ.get(key, "")
            if value:
                env_args.append(f"{key}={value}")

        os.execvp("sudo", ["sudo"] + env_args + [sys.executable] + sys.argv)


auto_root()


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


def handle_sigtstp(signum, frame):
    print(f"\n{YELLOW}Use the menu to exit cleanly.{RESET}")


signal.signal(signal.SIGTSTP, handle_sigtstp)


def get_user_vpn_ip():
    ip = os.environ.get("DEDSEC_SOURCE_IP", "").strip()
    if ip and ip != "unknown":
        return ip

    ssh_connection = os.environ.get("SSH_CONNECTION", "").strip()
    if ssh_connection:
        parts = ssh_connection.split()
        if parts:
            ssh_ip = parts[0]
            if ssh_ip.startswith("10.8.0."):
                return ssh_ip

    try:
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            rules = json.load(f)

        dedsec_user = os.environ.get("DEDSEC_USER", "").strip()
        ssh_user = os.environ.get("DEDSEC_SSH_USER", "").strip()

        for vpn_ip, info in rules.get("users", {}).items():
            if dedsec_user and info.get("display_name") == dedsec_user:
                return vpn_ip
            if ssh_user and info.get("ssh_user") == ssh_user:
                return vpn_ip
    except Exception:
        pass

    return ""


def choose_protocol():
    print(f"{WHITE}{BOLD}Protocol Filter:{RESET}\n")
    print(f"{CYAN}{BOLD}1.{RESET}  {WHITE}TCP only{RESET}")
    print(f"{CYAN}{BOLD}2.{RESET}  {WHITE}UDP only{RESET}")
    print(f"{CYAN}{BOLD}3.{RESET}  {WHITE}TCP + UDP{RESET}")
    print()

    choice = input(f"{YELLOW}Select protocol [3]:{RESET} ").strip()

    if choice == "1":
        return ["tcp"], "TCP only"
    if choice == "2":
        return ["udp"], "UDP only"

    return ["tcp", "or", "udp"], "TCP + UDP"


def stop_listener(stop_event):
    while not stop_event.is_set():
        try:
            value = input().strip().lower()
            if value in ["s", "stop", "q", "quit", "exit"]:
                stop_event.set()
                return
        except Exception:
            return


def run_live_capture(user_ip):
    proto_parts, proto_label = choose_protocol()

    port = input(f"{YELLOW}Filter port optional, example 22/80/443:{RESET} ").strip()

    if port and (not port.isdigit() or not (1 <= int(port) <= 65535)):
        print(f"{RED}Invalid port.{RESET}")
        pause()
        return

    cmd = [
        "timeout", "60",
        "tcpdump",
        "-i", "tun0",
        "-nn",
        "-tttt",
        "-l",
    ] + proto_parts + ["and", "host", user_ip]

    if port:
        cmd += ["and", "port", port]

    clear()
    banner()

    print(f"{WHITE}{BOLD}Live Capture Locked To Your VPN IP:{RESET}\n")
    print(f"{CYAN}VPN IP:{RESET}   {YELLOW}{user_ip}{RESET}")
    print(f"{CYAN}Protocol:{RESET} {YELLOW}{proto_label}{RESET}")
    print(f"{CYAN}Port:{RESET}     {YELLOW}{port if port else 'Any'}{RESET}")
    print()
    print(f"{GREEN}{'-' * 46}{RESET}")
    print(f"{YELLOW}Capture stops after 60 seconds.{RESET}")
    print(f"{YELLOW}Type S then Enter, or CTRL+C, to stop sooner.{RESET}\n")

    stop_event = threading.Event()
    listener = threading.Thread(target=stop_listener, args=(stop_event,), daemon=True)
    listener.start()

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    try:
        while process.poll() is None:
            if stop_event.is_set():
                process.terminate()
                break

            line = process.stdout.readline()
            if line:
                print(line, end="")

            time.sleep(0.01)

    except KeyboardInterrupt:
        process.terminate()

    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()

    print(f"\n{GREEN}{'-' * 46}{RESET}")
    print(f"{YELLOW}Capture stopped.{RESET}")
    pause()


def main():
    while True:
        clear()
        banner()

        user_ip = get_user_vpn_ip()

        if not user_ip:
            print(f"{RED}Could not detect your VPN IP.{RESET}")
            pause()
            return

        print(f"{WHITE}{BOLD}My Live VPN Traffic:{RESET}\n")
        print(f"{CYAN}Interface:{RESET}   {YELLOW}tun0{RESET}")
        print(f"{CYAN}Your VPN IP:{RESET} {YELLOW}{user_ip}{RESET}")
        print()
        print(f"{CYAN}{BOLD}1.{RESET}  {WHITE}Start Live Capture{RESET}")
        print(f"{CYAN}{BOLD}0.{RESET}  {WHITE}Back / Exit{RESET}")
        print()
        print(f"{GREEN}{'-' * 46}{RESET}")

        try:
            choice = input(f"{YELLOW}Select an option:{RESET} ").strip()
        except KeyboardInterrupt:
            print(f"\n{YELLOW}Use the menu to exit cleanly.{RESET}")
            pause()
            continue

        if choice == "1":
            run_live_capture(user_ip)
        elif choice == "0":
            break
        else:
            print(f"{RED}Invalid option.{RESET}")
            pause()


if __name__ == "__main__":
    main()
