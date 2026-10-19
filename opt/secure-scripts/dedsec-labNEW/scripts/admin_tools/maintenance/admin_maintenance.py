#!/usr/bin/env python3
import os
import time
import signal
import socket
import shutil
import platform
import subprocess
from datetime import datetime

try:
    import psutil
except ImportError:
    psutil = None

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


def enable_menu_signal_handlers():
    signal.signal(signal.SIGINT, handle_sigint)
    signal.signal(signal.SIGTSTP, handle_sigtstp)


def enable_default_sigint():
    signal.signal(signal.SIGINT, signal.SIG_DFL)


enable_menu_signal_handlers()


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


def cmd_exists(cmd):
    return shutil.which(cmd) is not None


def is_linux():
    return platform.system().lower() == "linux"


def human_bytes(num):
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    size = float(num)
    for unit in units:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} EB"


def get_package_manager():
    if cmd_exists("apt"):
        return "apt"
    if cmd_exists("dnf"):
        return "dnf"
    if cmd_exists("yum"):
        return "yum"
    if cmd_exists("pacman"):
        return "pacman"
    if cmd_exists("zypper"):
        return "zypper"
    return None


def update_upgrade_server():
    clear()
    banner()
    print(f"{WHITE}{BOLD}Server Update and Upgrade{RESET}\n")

    pm = get_package_manager()
    if not pm:
        print(f"{RED}No supported package manager found.{RESET}")
        pause()
        return

    print(f"{WHITE}Detected package manager:{RESET} {YELLOW}{pm}{RESET}")
    confirm = input(f"\n{YELLOW}Proceed with update/upgrade? (y/n):{RESET} ").strip().lower()
    if confirm != "y":
        print(f"{RED}Cancelled.{RESET}")
        pause()
        return

    commands = {
        "apt": [
            ["sudo", "apt", "update"],
            ["sudo", "apt", "upgrade", "-y"],
            ["sudo", "apt", "autoremove", "-y"],
            ["sudo", "apt", "autoclean"],
        ],
        "dnf": [
            ["sudo", "dnf", "check-update"],
            ["sudo", "dnf", "upgrade", "-y"],
            ["sudo", "dnf", "autoremove", "-y"],
        ],
        "yum": [
            ["sudo", "yum", "check-update"],
            ["sudo", "yum", "update", "-y"],
            ["sudo", "yum", "autoremove", "-y"],
        ],
        "pacman": [
            ["sudo", "pacman", "-Syu", "--noconfirm"],
        ],
        "zypper": [
            ["sudo", "zypper", "refresh"],
            ["sudo", "zypper", "update", "-y"],
        ]
    }

    print(f"{GREEN}{'-' * 46}{RESET}")
    for cmd in commands[pm]:
        print(f"{WHITE}Running:{RESET} {YELLOW}{' '.join(cmd)}{RESET}")
        result = run_cmd(cmd)
        print(f"{WHITE}Exit code:{RESET} {result.returncode}")
        print(f"{GREEN}{'-' * 46}{RESET}")

    print(f"{GREEN}Update and upgrade completed.{RESET}")
    pause()


def restart_server():
    clear()
    banner()
    print(f"{WHITE}{BOLD}Server Restart{RESET}\n")
    confirm = input(f"{YELLOW}Are you sure you want to restart the server? (y/n):{RESET} ").strip().lower()
    if confirm == "y":
        print(f"{WHITE}Running:{RESET} {YELLOW}sudo reboot{RESET}")
        run_cmd(["sudo", "reboot"])
    else:
        print(f"{RED}Cancelled.{RESET}")
        pause()


def shutdown_server():
    clear()
    banner()
    print(f"{WHITE}{BOLD}Server Shutdown{RESET}\n")
    confirm = input(f"{YELLOW}Are you sure you want to shut down the server? (y/n):{RESET} ").strip().lower()
    if confirm == "y":
        print(f"{WHITE}Running:{RESET} {YELLOW}sudo shutdown now{RESET}")
        run_cmd(["sudo", "shutdown", "now"])
    else:
        print(f"{RED}Cancelled.{RESET}")
        pause()


def hardware_summary():
    clear()
    banner()
    print(f"{WHITE}{BOLD}Hardware Summary{RESET}\n")

    print(f"{WHITE}Hostname:{RESET} {YELLOW}{socket.gethostname()}{RESET}")
    print(f"{WHITE}System:{RESET} {YELLOW}{platform.system()} {platform.release()}{RESET}")
    print(f"{WHITE}Machine:{RESET} {YELLOW}{platform.machine()}{RESET}")
    print(f"{WHITE}Processor:{RESET} {YELLOW}{platform.processor() or 'Unknown'}{RESET}")

    if psutil:
        print(f"{WHITE}Physical Cores:{RESET} {YELLOW}{psutil.cpu_count(logical=False)}{RESET}")
        print(f"{WHITE}Logical Cores:{RESET} {YELLOW}{psutil.cpu_count(logical=True)}{RESET}")

        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")

        print(f"{WHITE}Memory Total:{RESET} {YELLOW}{human_bytes(mem.total)}{RESET}")
        print(f"{WHITE}Memory Used:{RESET} {YELLOW}{human_bytes(mem.used)} ({mem.percent}%){RESET}")
        print(f"{WHITE}Disk Total:{RESET} {YELLOW}{human_bytes(disk.total)}{RESET}")
        print(f"{WHITE}Disk Used:{RESET} {YELLOW}{human_bytes(disk.used)} ({disk.percent}%){RESET}")
    else:
        print(f"{RED}psutil is not installed. Install with: sudo apt install python3-psutil{RESET}")

    print(f"\n{GREEN}{'-' * 46}{RESET}")
    if cmd_exists("uptime"):
        os.system("uptime")
    if cmd_exists("df"):
        print()
        os.system("df -h /")
    if cmd_exists("lsblk"):
        print()
        os.system("lsblk")
    print(f"{GREEN}{'-' * 46}{RESET}")

    pause()


def live_system_monitor():
    if not psutil:
        clear()
        banner()
        print(f"{RED}psutil is not installed. Install with: sudo apt install python3-psutil{RESET}")
        pause()
        return

    enable_default_sigint()

    try:
        while True:
            clear()
            banner()
            print(f"{WHITE}{BOLD}Live System Monitor{RESET}")
            print(f"{YELLOW}Press Ctrl+C to return to menu.{RESET}\n")

            cpu = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory()
            swap = psutil.swap_memory()
            disk = psutil.disk_usage("/")

            print(f"{WHITE}CPU Usage:{RESET} {YELLOW}{cpu}%{RESET}")
            print(f"{WHITE}RAM Usage:{RESET} {YELLOW}{mem.percent}%{RESET} {WHITE}({human_bytes(mem.used)} / {human_bytes(mem.total)}){RESET}")
            print(f"{WHITE}Swap Usage:{RESET} {YELLOW}{swap.percent}%{RESET} {WHITE}({human_bytes(swap.used)} / {human_bytes(swap.total)}){RESET}")
            print(f"{WHITE}Disk Usage:{RESET} {YELLOW}{disk.percent}%{RESET} {WHITE}({human_bytes(disk.used)} / {human_bytes(disk.total)}){RESET}")

            if hasattr(os, "getloadavg"):
                load = os.getloadavg()
                print(f"{WHITE}Load Average:{RESET} {YELLOW}{load[0]:.2f}, {load[1]:.2f}, {load[2]:.2f}{RESET}")

            print(f"\n{GREEN}{'-' * 46}{RESET}")

    except KeyboardInterrupt:
        print(f"\n{YELLOW}Returning to menu...{RESET}")
        time.sleep(1)

    finally:
        enable_menu_signal_handlers()


def get_interfaces():
    if psutil:
        return list(psutil.net_io_counters(pernic=True).keys())

    if cmd_exists("ip"):
        result = subprocess.run(["ip", "-o", "link", "show"], text=True, capture_output=True, check=False)
        interfaces = []
        for line in result.stdout.splitlines():
            parts = line.split(":")
            if len(parts) > 1:
                interfaces.append(parts[1].strip())
        return interfaces

    return []


def monitor_network_speeds():
    if not psutil:
        clear()
        banner()
        print(f"{RED}psutil is not installed. Install with: sudo apt install python3-psutil{RESET}")
        pause()
        return

    interfaces = get_interfaces()
    if not interfaces:
        clear()
        banner()
        print(f"{RED}No network interfaces found.{RESET}")
        pause()
        return

    while True:
        clear()
        banner()
        print(f"{WHITE}{BOLD}Monitor Upload / Download Speeds{RESET}\n")

        for i, iface in enumerate(interfaces, start=1):
            print(f"{CYAN}{BOLD}{i}.{RESET}  {WHITE}{iface}{RESET}")
        print(f"{CYAN}{BOLD}0.{RESET}  {WHITE}Back{RESET}")

        try:
            choice = input(f"\n{YELLOW}Select an interface:{RESET} ").strip()
        except KeyboardInterrupt:
            print(f"\n{YELLOW}Use the menu to exit cleanly.{RESET}")
            pause()
            continue

        if choice == "0":
            return
        if not choice.isdigit():
            print(f"{RED}Invalid choice.{RESET}")
            pause()
            continue

        idx = int(choice) - 1
        if idx < 0 or idx >= len(interfaces):
            print(f"{RED}Invalid choice.{RESET}")
            pause()
            continue

        iface = interfaces[idx]

        enable_default_sigint()

        try:
            old = psutil.net_io_counters(pernic=True)[iface]
            while True:
                time.sleep(1)
                new = psutil.net_io_counters(pernic=True)[iface]

                upload = new.bytes_sent - old.bytes_sent
                download = new.bytes_recv - old.bytes_recv

                clear()
                banner()
                print(f"{WHITE}{BOLD}Monitoring Interface:{RESET} {YELLOW}{iface}{RESET}")
                print(f"{YELLOW}Press Ctrl+C to return to interface list.{RESET}\n")

                print(f"{WHITE}Upload Speed:{RESET}   {YELLOW}{human_bytes(upload)}/s{RESET}")
                print(f"{WHITE}Download Speed:{RESET} {YELLOW}{human_bytes(download)}/s{RESET}")
                print(f"{WHITE}Packets Sent:{RESET}   {YELLOW}{new.packets_sent - old.packets_sent}/s{RESET}")
                print(f"{WHITE}Packets Recv:{RESET}   {YELLOW}{new.packets_recv - old.packets_recv}/s{RESET}")

                print(f"\n{GREEN}{'-' * 46}{RESET}")
                print(f"{WHITE}Useful for checking VPN tunnel throughput.{RESET}")

                old = new

        except KeyboardInterrupt:
            print(f"\n{YELLOW}Returning to interface list...{RESET}")
            time.sleep(1)

        finally:
            enable_menu_signal_handlers()


def show_tcp_connections():
    clear()
    banner()
    print(f"{WHITE}{BOLD}TCP Connections{RESET}\n")
    print(f"{GREEN}{'-' * 46}{RESET}")

    if cmd_exists("ss"):
        os.system("ss -tuna")
    elif cmd_exists("netstat"):
        os.system("netstat -tuna")
    else:
        print(f"{RED}Neither ss nor netstat is installed.{RESET}")

    print(f"{GREEN}{'-' * 46}{RESET}")
    pause()


def vpn_speed_test():
    clear()
    banner()
    print(f"{WHITE}{BOLD}VPN / Internet Speed Test{RESET}\n")

    print(f"{GREEN}{'-' * 46}{RESET}")
    if cmd_exists("speedtest-cli"):
        os.system("speedtest-cli --simple")
    elif cmd_exists("speedtest"):
        os.system("speedtest")
    else:
        print(f"{RED}No speed test tool found.{RESET}")
        print(f"{WHITE}Install one of these:{RESET}")
        print(f"{YELLOW}sudo apt install speedtest-cli{RESET}")
        print(f"{WHITE}or install Ookla Speedtest CLI.{RESET}")
    print(f"{GREEN}{'-' * 46}{RESET}")

    pause()


def cpu_temperature_check():
    clear()
    banner()
    print(f"{WHITE}{BOLD}CPU Temperature Check{RESET}\n")

    found = False

    if psutil and hasattr(psutil, "sensors_temperatures"):
        try:
            temps = psutil.sensors_temperatures()
            if temps:
                found = True
                for chip, entries in temps.items():
                    print(f"{CYAN}{BOLD}{chip}:{RESET}")
                    for entry in entries:
                        label = entry.label or "sensor"
                        current = getattr(entry, "current", None)
                        high = getattr(entry, "high", None)
                        critical = getattr(entry, "critical", None)

                        line = f"  {WHITE}{label}:{RESET} {YELLOW}{current}°C{RESET}"
                        if high is not None:
                            line += f" {WHITE}| high:{RESET} {YELLOW}{high}°C{RESET}"
                        if critical is not None:
                            line += f" {WHITE}| critical:{RESET} {YELLOW}{critical}°C{RESET}"
                        print(line)
                    print()
        except Exception as e:
            print(f"{RED}Temperature read failed:{RESET} {e}")

    if not found and cmd_exists("sensors"):
        found = True
        os.system("sensors")

    if not found and cmd_exists("vcgencmd"):
        found = True
        os.system("vcgencmd measure_temp")

    if not found:
        print(f"{RED}No temperature source found.{RESET}")
        print(f"{WHITE}Try installing:{RESET} {YELLOW}sudo apt install lm-sensors{RESET}")
        print(f"{WHITE}Then run:{RESET} {YELLOW}sudo sensors-detect{RESET}")

    pause()


def show_system_info():
    clear()
    banner()
    print(f"{WHITE}{BOLD}System Information{RESET}\n")
    print(f"{WHITE}Current User:{RESET} {YELLOW}{os.getenv('USER', 'unknown')}{RESET}")
    print(f"{WHITE}Hostname:{RESET} {YELLOW}{socket.gethostname()}{RESET}")
    print(f"{WHITE}Current Time:{RESET} {YELLOW}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"{WHITE}Current Directory:{RESET} {YELLOW}{os.getcwd()}{RESET}")
    pause()


if not is_linux():
    clear()
    banner()
    print(f"{RED}This script is intended for Linux systems only.{RESET}")
    pause()
    raise SystemExit(1)


while True:
    clear()
    banner()
    print(f"{CYAN}{BOLD}1.{RESET}  {WHITE}Server Update and Upgrade{RESET}")
    print(f"{CYAN}{BOLD}2.{RESET}  {WHITE}Restart Server{RESET}")
    print(f"{CYAN}{BOLD}3.{RESET}  {WHITE}Shutdown Server{RESET}")
    print(f"{CYAN}{BOLD}4.{RESET}  {WHITE}Hardware Summary{RESET}")
    print(f"{CYAN}{BOLD}5.{RESET}  {WHITE}Live System Monitor{RESET}")
    print(f"{CYAN}{BOLD}6.{RESET}  {WHITE}Monitor Upload / Download Speeds{RESET}")
    print(f"{CYAN}{BOLD}7.{RESET}  {WHITE}Show TCP Connections{RESET}")
    print(f"{CYAN}{BOLD}8.{RESET}  {WHITE}VPN / Internet Speed Test{RESET}")
    print(f"{CYAN}{BOLD}9.{RESET}  {WHITE}CPU Temperature Check{RESET}")
    print(f"{CYAN}{BOLD}10.{RESET} {WHITE}Show System Information{RESET}")
    print(f"{CYAN}{BOLD}0.{RESET}  {WHITE}Exit{RESET}")
    print()
    print(f"{GREEN}{'-' * 46}{RESET}")

    try:
        choice = input(f"{YELLOW}Select an option:{RESET} ").strip()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Use the menu to exit cleanly.{RESET}")
        pause()
        continue

    if choice == "1":
        update_upgrade_server()
    elif choice == "2":
        restart_server()
    elif choice == "3":
        shutdown_server()
    elif choice == "4":
        hardware_summary()
    elif choice == "5":
        live_system_monitor()
    elif choice == "6":
        monitor_network_speeds()
    elif choice == "7":
        show_tcp_connections()
    elif choice == "8":
        vpn_speed_test()
    elif choice == "9":
        cpu_temperature_check()
    elif choice == "10":
        show_system_info()
    elif choice == "0":
        print(f"{YELLOW}Goodbye.{RESET}")
        break
    else:
        print(f"{RED}Invalid option.{RESET}")
        pause()
