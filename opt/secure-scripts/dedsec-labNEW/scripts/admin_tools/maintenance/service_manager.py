#!/usr/bin/env python3
import os
import subprocess
import signal

RESET = "\033[0m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
WHITE = "\033[97m"
RED = "\033[31m"
BOLD = "\033[1m"


def handle_sigint(signum, frame):
    print(f"\n{YELLOW}Use the menu to exit cleanly.{RESET}")


def handle_sigtstp(signum, frame):
    print(f"\n{YELLOW}Use the menu to exit cleanly.{RESET}")


signal.signal(signal.SIGINT, handle_sigint)
signal.signal(signal.SIGTSTP, handle_sigtstp)


def clear():
    os.system("clear")


def pause():
    input(f"\n{YELLOW}Press Enter to continue...{RESET}")


def banner():
    import importlib.util
    banner_path = "/opt/secure-scripts/dedsec-labNEW/utils/banner.py"
    spec = importlib.util.spec_from_file_location("dedsec_banner", banner_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    def noop_theme():
        return None

    mod.dedsec_banner(GREEN, CYAN, RESET, BOLD, noop_theme)


def run_cmd(cmd):
    return subprocess.run(cmd, check=False)


COMMON_SERVICES = [
    "ssh",
    "openvpn",
    "apache2",
    "nginx",
    "postgresql",
    "docker",
    "fail2ban"
]


def service_action(service, action):
    clear()
    banner()
    print(f"{WHITE}{BOLD}Service:{RESET} {YELLOW}{service}{RESET}")
    print(f"{WHITE}{BOLD}Action:{RESET} {YELLOW}{action}{RESET}\n")

    print(f"{GREEN}{'-' * 46}{RESET}")
    result = run_cmd(["sudo", "systemctl", action, service])
    print(f"{GREEN}{'-' * 46}{RESET}")

    print(f"{WHITE}Exit code:{RESET} {result.returncode}")
    pause()


def service_status(service):
    clear()
    banner()
    print(f"{WHITE}{BOLD}Service Status:{RESET} {YELLOW}{service}{RESET}\n")

    print(f"{GREEN}{'-' * 46}{RESET}")
    os.system(f"systemctl status {service} --no-pager")
    print(f"{GREEN}{'-' * 46}{RESET}")

    pause()


def custom_service_menu():
    while True:
        clear()
        banner()
        print(f"{WHITE}{BOLD}Custom Service{RESET}\n")

        service = input(f"{YELLOW}Enter service name (or 0 to go back):{RESET} ").strip()
        if service == "0":
            return

        service_menu(service)


def service_menu(service):
    while True:
        clear()
        banner()
        print(f"{WHITE}{BOLD}Manage Service:{RESET} {YELLOW}{service}{RESET}\n")

        print(f"{CYAN}{BOLD}1.{RESET}  {WHITE}Status{RESET}")
        print(f"{CYAN}{BOLD}2.{RESET}  {WHITE}Start{RESET}")
        print(f"{CYAN}{BOLD}3.{RESET}  {WHITE}Stop{RESET}")
        print(f"{CYAN}{BOLD}4.{RESET}  {WHITE}Restart{RESET}")
        print(f"{CYAN}{BOLD}5.{RESET}  {WHITE}Enable (startup){RESET}")
        print(f"{CYAN}{BOLD}6.{RESET}  {WHITE}Disable (startup){RESET}")
        print(f"{CYAN}{BOLD}0.{RESET}  {WHITE}Back{RESET}")

        try:
            choice = input(f"\n{YELLOW}Select an option:{RESET} ").strip()
        except KeyboardInterrupt:
            print(f"\n{YELLOW}Use the menu to exit cleanly.{RESET}")
            pause()
            continue

        if choice == "1":
            service_status(service)
        elif choice == "2":
            service_action(service, "start")
        elif choice == "3":
            service_action(service, "stop")
        elif choice == "4":
            service_action(service, "restart")
        elif choice == "5":
            service_action(service, "enable")
        elif choice == "6":
            service_action(service, "disable")
        elif choice == "0":
            return
        else:
            print(f"{RED}Invalid option.{RESET}")
            pause()


while True:
    clear()
    banner()
    print(f"{WHITE}{BOLD}Service Manager{RESET}\n")

    for i, svc in enumerate(COMMON_SERVICES, start=1):
        print(f"{CYAN}{BOLD}{i}.{RESET}  {WHITE}{svc}{RESET}")

    print(f"{CYAN}{BOLD}9.{RESET}  {WHITE}Custom Service{RESET}")
    print(f"{CYAN}{BOLD}0.{RESET}  {WHITE}Exit{RESET}")
    print()
    print(f"{GREEN}{'-' * 46}{RESET}")

    try:
        choice = input(f"{YELLOW}Select a service:{RESET} ").strip()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Use the menu to exit cleanly.{RESET}")
        pause()
        continue

    if choice == "0":
        break
    elif choice == "9":
        custom_service_menu()
    elif choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(COMMON_SERVICES):
            service_menu(COMMON_SERVICES[idx])
        else:
            print(f"{RED}Invalid choice.{RESET}")
            pause()
    else:
        print(f"{RED}Invalid option.{RESET}")
        pause()
