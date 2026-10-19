#!/usr/bin/env python3

import os
import subprocess
import time
import shutil

# ============================================================
# DEDSEC TRAFFIC INTELLIGENCE PANEL
# ============================================================

VPN_SERVICE = "openvpn-server@server"
VPN_PORT = "54321"


# ------------------------------------------------------------
# Colours
# ------------------------------------------------------------

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
WHITE = "\033[97m"
MAGENTA = "\033[95m"
RESET = "\033[0m"
BOLD = "\033[1m"


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def clear():
    os.system("clear")


def pause():
    input(f"\n{CYAN}Press ENTER to return to the menu...{RESET}")


def run_command(command):
    try:
        result = subprocess.run(
            command,
            shell=True,
            text=True,
            capture_output=True
        )

        if result.stdout:
            print(result.stdout)

        if result.stderr:
            print(f"{YELLOW}{result.stderr}{RESET}")

        return result.returncode

    except Exception as e:
        print(f"{RED}Command failed: {e}{RESET}")
        return 1


# ------------------------------------------------------------
# Banner
# ------------------------------------------------------------

def banner():
    print(f"""{CYAN}
██████╗ ███████╗██████╗ ███████╗███████╗ ██████╗
██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝
██║  ██║█████╗  ██║  ██║███████╗█████╗  ██║
██║  ██║██╔══╝  ██║  ██║╚════██║██╔══╝  ██║
██████╔╝███████╗██████╔╝███████║███████╗╚██████╗
╚═════╝ ╚══════╝╚═════╝ ╚══════╝╚══════╝ ╚═════╝
{RESET}
{WHITE}{BOLD}Secure Terminal Access Launcher{RESET}
{CYAN}════════════════════════════════════════════════════════{RESET}
""")


# ------------------------------------------------------------
# Service status
# ------------------------------------------------------------

def vpn_status():
    clear()

    print(f"{CYAN}{BOLD}DEDSEC VPN STATUS{RESET}")
    print(f"{CYAN}{'═' * 60}{RESET}\n")

    run_command(f"systemctl status {VPN_SERVICE} --no-pager")

    pause()


# ------------------------------------------------------------
# Start VPN
# ------------------------------------------------------------

def vpn_start():
    clear()

    print(f"{GREEN}{BOLD}STARTING OPENVPN...{RESET}\n")

    run_command(f"systemctl start {VPN_SERVICE}")

    print()

    run_command(f"systemctl is-active {VPN_SERVICE}")

    pause()


# ------------------------------------------------------------
# Stop VPN
# ------------------------------------------------------------

def vpn_stop():
    clear()

    print(f"{YELLOW}{BOLD}STOPPING OPENVPN...{RESET}\n")

    run_command(f"systemctl stop {VPN_SERVICE}")

    print()

    run_command(f"systemctl is-active {VPN_SERVICE}")

    pause()


# ------------------------------------------------------------
# Restart VPN
# ------------------------------------------------------------

def vpn_restart():
    clear()

    print(f"{MAGENTA}{BOLD}RESTARTING OPENVPN...{RESET}\n")

    run_command(f"systemctl restart {VPN_SERVICE}")

    print()

    run_command(f"systemctl is-active {VPN_SERVICE}")

    pause()


# ------------------------------------------------------------
# All TCP connections
# ------------------------------------------------------------

def tcp_connections():
    clear()

    print(f"{CYAN}{BOLD}TCP CONNECTIONS{RESET}")
    print(f"{CYAN}{'═' * 70}{RESET}\n")

    run_command("ss -tnp")

    pause()


# ------------------------------------------------------------
# TCP summary
# ------------------------------------------------------------

def tcp_summary():
    clear()

    print(f"{CYAN}{BOLD}TCP CONNECTION SUMMARY{RESET}")
    print(f"{CYAN}{'═' * 70}{RESET}\n")

    run_command("ss -s")

    pause()


# ------------------------------------------------------------
# Web connections
# ------------------------------------------------------------

def web_connections():
    clear()

    print(f"{CYAN}{BOLD}WEB CONNECTIONS - TCP 80 / 443{RESET}")
    print(f"{CYAN}{'═' * 80}{RESET}\n")

    run_command(
        "ss -tnp state established "
        "'( sport = :80 or sport = :443 )'"
    )

    pause()


# ------------------------------------------------------------
# OpenVPN TCP connections
# ------------------------------------------------------------

def vpn_connections():
    clear()

    print(f"{GREEN}{BOLD}OPENVPN CONNECTIONS - PORT {VPN_PORT}{RESET}")
    print(f"{GREEN}{'═' * 90}{RESET}\n")

    run_command(
        f"ss -tnp | grep ':{VPN_PORT}' || "
        f"echo 'No active connections on port {VPN_PORT}.'"
    )

    pause()


# ------------------------------------------------------------
# Listening ports
# ------------------------------------------------------------

def listening_ports():
    clear()

    print(f"{CYAN}{BOLD}LISTENING TCP / UDP PORTS{RESET}")
    print(f"{CYAN}{'═' * 90}{RESET}\n")

    run_command("ss -lntup")

    pause()


# ------------------------------------------------------------
# Live TCP monitor
# ------------------------------------------------------------

def live_tcp():
    clear()

    print(f"{MAGENTA}{BOLD}LIVE TCP CONNECTION MONITOR{RESET}")
    print(f"{MAGENTA}{'═' * 80}{RESET}")
    print(f"{YELLOW}Press CTRL+C to stop the live monitor.{RESET}\n")

    try:
        while True:
            os.system("clear")

            print(f"{MAGENTA}{BOLD}DEDSEC LIVE TCP MONITOR{RESET}")
            print(f"{MAGENTA}{'═' * 80}{RESET}")
            print(f"{YELLOW}Refreshing every 2 seconds - CTRL+C to exit{RESET}\n")

            os.system("ss -tnp")

            time.sleep(2)

    except KeyboardInterrupt:
        print(f"\n\n{GREEN}Live monitor stopped.{RESET}")
        time.sleep(1)


# ------------------------------------------------------------
# Process view
# ------------------------------------------------------------

def running_processes():
    clear()

    print(f"{CYAN}{BOLD}RUNNING PROCESSES{RESET}")
    print(f"{CYAN}{'═' * 100}{RESET}\n")

    run_command("ps aux")

    pause()


# ------------------------------------------------------------
# VPN logs
# ------------------------------------------------------------

def vpn_logs():
    clear()

    print(f"{YELLOW}{BOLD}OPENVPN LOGS - LAST 100 LINES{RESET}")
    print(f"{YELLOW}{'═' * 90}{RESET}\n")

    run_command(
        f"journalctl -u {VPN_SERVICE} -n 100 --no-pager"
    )

    pause()


# ------------------------------------------------------------
# Traffic Intelligence Menu
# ------------------------------------------------------------

def traffic_menu():

    while True:

        clear()
        banner()

        print(f"{GREEN}{BOLD}DEDSEC Owner Root Panel:{RESET}\n")

        print(f"{WHITE}1.  Start OpenVPN")
        print(f"2.  Stop OpenVPN")
        print(f"3.  Restart OpenVPN")
        print(f"4.  OpenVPN Status")
        print(f"5.  TCP Connections")
        print(f"6.  TCP Connection Summary")
        print(f"7.  Web Connections [80/443]")
        print(f"8.  OpenVPN Connections [{VPN_PORT}]")
        print(f"9.  Listening Ports")
        print(f"10. Live TCP Monitor")
        print(f"11. Running Processes")
        print(f"12. OpenVPN Logs")
        print(f"0.  Back")
        print()

        print(f"{CYAN}{'-' * 50}{RESET}")

        choice = input(f"{GREEN}Select: {RESET}").strip()

        if choice == "1":
            vpn_start()

        elif choice == "2":
            vpn_stop()

        elif choice == "3":
            vpn_restart()

        elif choice == "4":
            vpn_status()

        elif choice == "5":
            tcp_connections()

        elif choice == "6":
            tcp_summary()

        elif choice == "7":
            web_connections()

        elif choice == "8":
            vpn_connections()

        elif choice == "9":
            listening_ports()

        elif choice == "10":
            live_tcp()

        elif choice == "11":
            running_processes()

        elif choice == "12":
            vpn_logs()

        elif choice == "0":
            break

        else:
            print(f"{RED}Invalid selection.{RESET}")
            time.sleep(1)


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

if __name__ == "__main__":

    if os.geteuid() != 0:
        print(f"{RED}This panel must be run as root.{RESET}")
        print("Run it with:")
        print("sudo python3 traffic_panel.py")
        exit(1)

    traffic_menu()
