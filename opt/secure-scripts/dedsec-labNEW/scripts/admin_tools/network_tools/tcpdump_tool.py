#!/usr/bin/env python3
import os
import sys
import signal
import subprocess
from datetime import datetime

RESET = "\033[0m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
WHITE = "\033[97m"
RED = "\033[31m"
BOLD = "\033[1m"

DUMP_DIR = "/opt/secure-scripts/dedsec-labNEW/logs/traffic_dumps"
os.makedirs(DUMP_DIR, exist_ok=True)

def auto_root():
    if os.geteuid() != 0:
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)

auto_root()

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

def handle_sigtstp(signum, frame):
    print(f"\n{YELLOW}Use the menu to exit cleanly.{RESET}")

signal.signal(signal.SIGTSTP, handle_sigtstp)


def get_interfaces():
    result = subprocess.run(["ip", "-br", "addr"], capture_output=True, text=True)
    lines = result.stdout.strip().splitlines()

    interfaces = []

    for line in lines:
        parts = line.split()
        if len(parts) < 2:
            continue

        name = parts[0]
        state = parts[1]

        ipv4 = "N/A"
        for part in parts[2:]:
            if "." in part:
                ipv4 = part
                break

        interfaces.append((name, state, ipv4))

    return interfaces

def choose_protocol():
    print(f"{WHITE}{BOLD}Protocol Filter:{RESET}\n")
    print(f"{CYAN}{BOLD}1.{RESET}  {WHITE}TCP only{RESET}")
    print(f"{CYAN}{BOLD}2.{RESET}  {WHITE}UDP only{RESET}")
    print(f"{CYAN}{BOLD}3.{RESET}  {WHITE}TCP + UDP{RESET}")
    print(f"{CYAN}{BOLD}4.{RESET}  {WHITE}All traffic{RESET}")
    print()

    choice = input(f"{YELLOW}Select protocol [3]:{RESET} ").strip()

    if choice == "1":
        return ["tcp"], "TCP only"
    if choice == "2":
        return ["udp"], "UDP only"
    if choice == "4":
        return [], "All traffic"
    return ["tcp", "or", "udp"], "TCP + UDP"

def build_filter(proto_parts, host, port):
    parts = []

    if proto_parts:
        if len(proto_parts) > 1:
            parts += ["("] + proto_parts + [")"]
        else:
            parts += proto_parts

    if host:
        if parts:
            parts += ["and"]
        parts += ["host", host]

    if port:
        if parts:
            parts += ["and"]
        parts += ["port", port]

    return parts

def collect_options():
    clear()
    banner()

    interfaces = get_interfaces()

    print(f"{WHITE}{BOLD}Available Interfaces:{RESET}\n")
    for i, (name, state, ip) in enumerate(interfaces, 1):
        print(f"{CYAN}{BOLD}{i}.{RESET}  {WHITE}{name:<6}{RESET} {YELLOW}{ip}{RESET}")
    print(f"{CYAN}{BOLD}0.{RESET}  {WHITE}any{RESET}\n")

    choice = input(f"{YELLOW}Select interface [0]:{RESET} ").strip()

    if choice == "" or choice == "0":
        iface = "any"
    elif choice.isdigit() and 1 <= int(choice) <= len(interfaces):
        iface = interfaces[int(choice) - 1][0]
    else:
        print(f"{RED}Invalid interface selection.{RESET}")
        pause()
        return None
    host = input(f"{YELLOW}Filter IP optional, example 10.8.0.3:{RESET} ").strip()
    port = input(f"{YELLOW}Filter port optional, example 22/443/9981:{RESET} ").strip()
    proto_parts, proto_label = choose_protocol()

    return iface, host, port, proto_parts, proto_label

def live_capture():
    options = collect_options()
    if not options:
        return
    iface, host, port, proto_parts, proto_label = options
    tcpdump_filter = build_filter(proto_parts, host, port)

    cmd = ["timeout", "60", "tcpdump", "-i", iface, "-nn", "-tttt", "-l"] + tcpdump_filter

    clear()
    banner()
    print(f"{WHITE}{BOLD}Live TCPDump:{RESET}\n")
    print(f"{CYAN}Interface:{RESET} {YELLOW}{iface}{RESET}")
    print(f"{CYAN}Protocol:{RESET}  {YELLOW}{proto_label}{RESET}")
    print(f"{CYAN}Host:{RESET}      {YELLOW}{host if host else 'Any'}{RESET}")
    print(f"{CYAN}Port:{RESET}      {YELLOW}{port if port else 'Any'}{RESET}")
    print()
    print(f"{GREEN}{'-' * 46}{RESET}")
    print(f"{YELLOW}Live capture stops after 60 seconds, or CTRL+C.{RESET}\n")

    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        pass

    print(f"\n{GREEN}{'-' * 46}{RESET}")
    print(f"{YELLOW}Live capture stopped.{RESET}")
    pause()

def file_capture():
    options = collect_options()
    if not options:
        return
    iface, host, port, proto_parts, proto_label = options

    seconds = "60"
    print(f"{YELLOW}File capture is limited to 60 seconds.{RESET}")

    tcpdump_filter = build_filter(proto_parts, host, port)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"capture_{iface}_{timestamp}.pcap".replace("/", "_")
    output_path = os.path.join(DUMP_DIR, filename)

    cmd = [
        "timeout",
        seconds,
        "tcpdump",
        "-i",
        iface,
        "-nn",
        "-s",
        "0",
        "-w",
        output_path,
    ] + tcpdump_filter

    clear()
    banner()
    print(f"{WHITE}{BOLD}TCPDump File Capture:{RESET}\n")
    print(f"{CYAN}Interface:{RESET} {YELLOW}{iface}{RESET}")
    print(f"{CYAN}Protocol:{RESET}  {YELLOW}{proto_label}{RESET}")
    print(f"{CYAN}Host:{RESET}      {YELLOW}{host if host else 'Any'}{RESET}")
    print(f"{CYAN}Port:{RESET}      {YELLOW}{port if port else 'Any'}{RESET}")
    print(f"{CYAN}Seconds:{RESET}   {YELLOW}{seconds}{RESET}")
    print(f"{CYAN}Output:{RESET}    {YELLOW}{output_path}{RESET}")
    print()
    print(f"{GREEN}{'-' * 46}{RESET}")
    print(f"{YELLOW}Capturing...{RESET}\n")

    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Capture interrupted.{RESET}")
        pause()
        return

    print(f"\n{GREEN}{'-' * 46}{RESET}")

    if os.path.isfile(output_path) and os.path.getsize(output_path) > 24:
        print(f"{GREEN}Capture complete.{RESET}")
        print(f"{WHITE}Saved:{RESET} {YELLOW}{output_path}{RESET}")
        print(f"{WHITE}Size:{RESET}  {YELLOW}{os.path.getsize(output_path)} bytes{RESET}")
    else:
        print(f"{RED}No useful packets captured.{RESET}")

    pause()

def list_dumps():
    clear()
    banner()

    print(f"{WHITE}{BOLD}Saved Traffic Dumps:{RESET}\n")
    files = sorted([f for f in os.listdir(DUMP_DIR) if f.endswith(".pcap")])

    if not files:
        print(f"{RED}No dump files found.{RESET}")
        pause()
        return

    for i, filename in enumerate(files, 1):
        path = os.path.join(DUMP_DIR, filename)
        print(f"{CYAN}{BOLD}{i}.{RESET}  {WHITE}{filename}{RESET} {YELLOW}({os.path.getsize(path)} bytes){RESET}")

    pause()

def delete_dumps():
    clear()
    banner()

    confirm = input(f"{RED}Delete ALL saved tcpdump files? Type YES:{RESET} ").strip()
    if confirm.upper() != "YES":
        print(f"{YELLOW}Cancelled.{RESET}")
        pause()
        return

    deleted = 0
    for filename in os.listdir(DUMP_DIR):
        if filename.endswith(".pcap"):
            os.remove(os.path.join(DUMP_DIR, filename))
            deleted += 1

    print(f"{GREEN}Deleted dump files:{RESET} {YELLOW}{deleted}{RESET}")
    pause()

def main():
    while True:
        clear()
        banner()

        print(f"{WHITE}{BOLD}TCPDump Tool:{RESET}\n")
        print(f"{CYAN}{BOLD}1.{RESET}  {WHITE}Live Capture Only{RESET}")
        print(f"{CYAN}{BOLD}2.{RESET}  {WHITE}Save Capture To File{RESET}")
        print(f"{CYAN}{BOLD}3.{RESET}  {WHITE}List Saved Dumps{RESET}")
        print(f"{CYAN}{BOLD}4.{RESET}  {WHITE}Delete Saved Dumps{RESET}")
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
            live_capture()
        elif choice == "2":
            file_capture()
        elif choice == "3":
            list_dumps()
        elif choice == "4":
            delete_dumps()
        elif choice == "0":
            break
        else:
            print(f"{RED}Invalid option.{RESET}")
            pause()

if __name__ == "__main__":
    main()
