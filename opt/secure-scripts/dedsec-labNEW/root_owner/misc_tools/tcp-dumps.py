#!/usr/bin/env python3
import sys
import os
import time
import subprocess
import signal
import re
import requests
import urllib3
from statistics import mode

# === CONFIGURATION ===
DATA_DIR = "/opt/secure-scripts/dedsec-labNEW/data/vpn_puller"
os.makedirs(DATA_DIR, exist_ok=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
signal.signal(signal.SIGINT, signal.SIG_IGN)

RESET, GREEN, YELLOW, CYAN, WHITE, RED, BOLD = "\033[0m", "\033[32m", "\033[33m", "\033[36m", "\033[97m", "\033[31m", "\033[1m"

if len(sys.argv) < 2:
    print(f"{RED}Usage: python3 vpn_puller.py <source_ip>{RESET}")
    sys.exit(1)

userip = sys.argv[1]

def clear_screen(): os.system("clear")
def draw_header(title):
    clear_screen()
    print(f"{WHITE}{BOLD}{title}{RESET}\n{GREEN}{'-'*46}{RESET}")

def lookup_ip(ipaddr):
    try:
        res = requests.get(f"https://pro.ip-api.com/line/{ipaddr}?key=ipapiq9SFY1Ic4", timeout=2)
        return res.text.splitlines() if res.status_code == 200 else None
    except: return None

def generic_capture(title, filter_cmd, count=50):
    draw_header(title)
    dumpname = os.path.join(DATA_DIR, f"{time.time()}.pcap")
    cmd = f"sudo tcpdump -i tun0 src {userip} and {filter_cmd} -nn -c {count} > {dumpname} 2>&1"
    subprocess.run(cmd, shell=True)
    
    ips = []
    if os.path.exists(dumpname):
        with open(dumpname, "r") as f:
            for line in f:
                match = re.search(r'> (\d{1,3}(?:\.\d{1,3}){3})', line)
                if match: ips.append(match.group(1))
        os.remove(dumpname)
    
    unique_ips = list(set([ip for ip in ips if not ip.startswith(('10.', '192.168.', '172.16.'))]))
    print(f"{CYAN}Results found:{RESET}")
    for ip in unique_ips:
        loc = lookup_ip(ip)
        print(f"{WHITE}{ip.ljust(15)} | {str(loc[0:2] if loc else 'Unknown')}{RESET}")
    input(f"\n{YELLOW}Press Enter to continue...{RESET}")

# --- Service Modules ---
def fb_call(): generic_capture("FB/WHATSAPP CALL", "udp dst port 3478")
def discord_voice(): generic_capture("DISCORD VOICE", "udp dst portrange 50000-65535")
def steam_valve(): generic_capture("STEAM/VALVE", "udp dst portrange 27000-27030")
def minecraft(): generic_capture("MINECRAFT", "tcp dst port 25565")
def gta_lobby(): generic_capture("GTA 5 LOBBY", "udp dst port 6672")

# --- Menu System ---
MENU_PAGES = [
    [("1", "GTA 5 Lobby", gta_lobby), ("2", "FB/WhatsApp Call", fb_call), ("3", "Discord Voice", discord_voice)],
    [("4", "Steam/Valve Games", steam_valve), ("5", "Minecraft Server", minecraft)]
]

current_page = 0

while True:
    clear_screen()
    print(f"{BOLD}VPN PULLER - PAGE {current_page + 1}{RESET}")
    for k, name, func in MENU_PAGES[current_page]:
        print(f"{CYAN}{k}){RESET} {name}")
    print(f"\n{YELLOW}N{RESET} Next | {YELLOW}P{RESET} Prev | {YELLOW}0{RESET} Exit")
    
    choice = input(f"\n{WHITE}Choice: {RESET}").lower()
    if choice == 'n' and current_page < len(MENU_PAGES)-1: current_page += 1
    elif choice == 'p' and current_page > 0: current_page -= 1
    elif choice == '0': break
    else:
        for k, name, func in MENU_PAGES[current_page]:
            if choice == k: func()
