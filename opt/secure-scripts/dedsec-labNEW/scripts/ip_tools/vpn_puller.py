#!/usr/bin/env python3
import requests
import sys
import socket
import certifi
import subprocess
import os
import time
import chardet
import re
import statistics
import signal
import urllib3
from statistics import mode

# === DATA DIRECTORY ===
DATA_DIR = "/opt/secure-scripts/dedsec-labNEW/data/vpn_puller"
os.makedirs(DATA_DIR, exist_ok=True)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
signal.signal(signal.SIGINT, signal.SIG_IGN)
signal.signal(signal.SIGTSTP, signal.SIG_IGN)

RESET = "\033[0m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
WHITE = "\033[97m"
RED = "\033[31m"
BOLD = "\033[1m"

# --- Config ---
# REMOTE CHECKS DISABLED / COMMENTED OUT
# version_check_url = "https://YOUR_VERSION_CHECK_HOST.example/path"
# whitelist_check_base_url = "https://YOUR_VERSION_CHECK_HOST.example/path"
# application_version = "1.0"

# --- Local argument validation replacement ---
if len(sys.argv) < 2:
    print(f"{RED}Usage: python3 vpn_puller.py <source_ip>{RESET}")
    input(f"{YELLOW}Press Enter to exit...{RESET}")
    sys.exit(1)

userip = sys.argv[1]

def most_common(List):
    return mode(List)

def clear_screen():
    os.system("clear" if os.name == "posix" else "cls")

def draw_header(title):
    clear_screen()
    shared_banner()
    print(f"{WHITE}{BOLD}{title}{RESET}")
    print(f"{GREEN}{'-' * 46}{RESET}")

def pause():
    input(f"\n{YELLOW}Press Enter to return to menu...{RESET}")

def show_info(message):
    print(f"{WHITE}{message}{RESET}")

def show_success(message):
    print(f"{GREEN}{message}{RESET}")

def show_warning(message):
    print(f"{YELLOW}{message}{RESET}")

def show_error(message):
    print(f"{RED}{message}{RESET}")

def print_rule():
    print(f"{GREEN}{'-' * 46}{RESET}")

def lookup_ip(ipaddr):
    """Pro ip-api when IPAPI_KEY is set; otherwise free ip-api.com line API."""
    import os
    try:
        key = (os.environ.get("IPAPI_KEY") or "").strip()
        if key:
            headers = {
                'Accept': '*/*',
                'Accept-Encoding': 'gzip, deflate, br',
                'Accept-Language': 'en-GB,en-US;q=0.9,en;q=0.8',
                'Connection': 'keep-alive',
                'Host': 'pro.ip-api.com',
                'Origin': 'https://members.ip-api.com'
            }
            res = requests.get(
                f"https://pro.ip-api.com/line/{ipaddr}?fields=country,regionName,city,isp&key={key}",
                headers=headers,
                timeout=5,
            )
            if res.status_code == 200:
                return res.text.splitlines()[0:4]
        res = requests.get(
            f"http://ip-api.com/line/{ipaddr}?fields=country,regionName,city,isp",
            timeout=5,
        )
        if res.status_code == 200:
            return res.text.splitlines()[0:4]
    except Exception:
        return None
    return None


# --- Define menu actions ---
def gta_lobby_puller():
    draw_header("GTA 5 FULL LOBBY PULLER")
    show_info("Getting lobby info, please wait...")
    time.sleep(1)
    tcpdumpres = []
    ipsfound = []
    portsfound = []

    dumpname = os.path.join(DATA_DIR, f"{round(time.time())}.pcap")
    tcpdump_cmd = f"sudo tcpdump -i tun0 src {userip} and udp dst port 6672 and not host YOUR_FILTER_EXCLUDE_IP_1 and not dst net 10.8.0.0/16 and not dst net 192.168.0.0/16 and not dst net 10.0.0.0/16 -nn -c 250 > {dumpname}"
    subprocess.getoutput(tcpdump_cmd)
    time.sleep(1)

    try:
        with open(dumpname, "r") as f:
            dump = f.readlines()
    except FileNotFoundError:
        show_error("Failed to open tcpdump output file.")
        pause()
        return

    for line in dump:
        if 'IP' in line:
            parts = line.split(" ")[4].split(".")
            if len(parts) >= 4:
                ip = ".".join(parts[:4])
                tcpdumpres.append(ip)
        if 'UDP' in line:
            port = line.split(".")[-1].split(":")[0]
            portsfound.append(port)

    if tcpdumpres:
        show_success("Lobby has been found!")
        ipsfound = list(set(tcpdumpres))
        print_rule()
        show_info(f"Player IPs found in your lobby [{len(ipsfound)}/30] (not including yourself)")
        show_info("Here are the listed IPs in the GTA 5 lobby")
        print()
        print(f"{CYAN}IP ADDRESS      || COUNTRY        || STATE/REGION   || CITY           || ISP           || DEST PORT{RESET}")
        print(f"{GREEN}----------------||----------------||----------------||----------------||----------------||----------{RESET}")
        for nongeo, port in zip(ipsfound, portsfound):
            try:
                loc = lookup_ip(nongeo)
                if loc:
                    country, regionName, city, isp = loc
                    if re.search(r'Google|Microsoft|Take-two Interactive Software|Take-two|Interactive|Software|Amazon|Cloudflare|i3D.net B.V', isp):
                        continue
                    print(f"{WHITE}{nongeo.ljust(15)} || {country.ljust(14)} || {regionName.ljust(14)} || {city.ljust(14)} || {isp.ljust(14)} || {port}{RESET}")
                else:
                    show_warning(f"{nongeo} || Failed to locate IP (API may be down)")
            except Exception as e:
                show_error(f"{nongeo} || Unexpected error: {e}")
        print_rule()
    else:
        show_warning("No lobby found")

    try:
        os.remove(dumpname)
    except Exception:
        pass

    pause()

def gta_nearest_player_puller():
    draw_header("GTA 5 NEAREST PLAYER PULLER")
    show_info("Getting lobby info, please wait...")
    time.sleep(1)
    tcpdumpres = []

    dumpname = os.path.join(DATA_DIR, f"{round(time.time())}.pcap")
    tcpdump_cmd = f"sudo tcpdump -i tun0 src {userip} and udp dst port 6672 and greater 250 and not host YOUR_FILTER_EXCLUDE_IP_1 and not dst net 10.8.0.0/16 and not dst net 192.168.0.0/16 and not dst net 10.0.0.0/16 -nn -c 20 > {dumpname}"
    subprocess.getoutput(tcpdump_cmd)
    time.sleep(1)

    try:
        with open(dumpname, "r") as f:
            dump = f.readlines()
    except FileNotFoundError:
        show_error("Failed to open tcpdump output file.")
        pause()
        return

    fliine = "unknown"
    for line in dump:
        if 'IP' in line:
            try:
                liine = line.split(" ")[4]
                aliine = liine.split(".")[0]
                bliine = liine.split(".")[1]
                cliine = liine.split(".")[2]
                dliine = liine.split(".")[3]
                eliine = liine.split(".")[4]
                fliine = eliine.replace(":", "")
                gliine = f"{aliine}.{bliine}.{cliine}.{dliine}"
                tcpdumpres.append(gliine)
            except Exception:
                continue

    if tcpdumpres:
        ipaddr = most_common(tcpdumpres)
        loc = lookup_ip(ipaddr)
        print_rule()
        show_info("The nearest player's IP address is listed here")
        print()
        print(f"{WHITE}IP Address:{RESET} {YELLOW}{ipaddr}{RESET}")
        print(f"{WHITE}Destination Port:{RESET} {YELLOW}{fliine}{RESET}")
        if loc:
            country, regionName, city, isp = loc
            print(f"{WHITE}Country:{RESET} {country}")
            print(f"{WHITE}State:{RESET} {regionName}")
            print(f"{WHITE}City:{RESET} {city}")
            print(f"{WHITE}ISP:{RESET} {isp}")
        else:
            show_warning("Error locating IP")
        print_rule()
    else:
        show_warning("No lobby found")

    try:
        os.remove(dumpname)
    except Exception:
        pass

    pause()

def gta_orb_puller():
    draw_header("GTA 5 ORBITAL CANNON PULLER")
    show_info("Getting lobby info, please wait...")
    time.sleep(1)
    tcpdumpres = []

    dumpname = os.path.join(DATA_DIR, f"{round(time.time())}.pcap")
    tcpdump_cmd = f"sudo tcpdump -i tun0 src {userip} and udp dst port 6672 and greater 165 and not host YOUR_FILTER_EXCLUDE_IP_1 and not dst net 10.8.0.0/16 and not dst net 192.168.0.0/16 and not dst net 10.0.0.0/16 -nn -c 100 > {dumpname}"
    subprocess.getoutput(tcpdump_cmd)
    time.sleep(1)

    try:
        with open(dumpname, "r") as f:
            dump = f.readlines()
    except FileNotFoundError:
        show_error("Failed to open tcpdump output file.")
        pause()
        return

    fliine = "unknown"
    for line in dump:
        if 'IP' in line:
            try:
                liine = line.split(" ")[4]
                aliine = liine.split(".")[0]
                bliine = liine.split(".")[1]
                cliine = liine.split(".")[2]
                dliine = liine.split(".")[3]
                eliine = liine.split(".")[4]
                fliine = eliine.replace(":", "")
                gliine = f"{aliine}.{bliine}.{cliine}.{dliine}"
                tcpdumpres.append(gliine)
            except Exception:
                continue

    if tcpdumpres:
        ipaddr = most_common(tcpdumpres)
        loc = lookup_ip(ipaddr)
        print_rule()
        show_info("The orbital cannon target IP is listed here")
        print()
        print(f"{WHITE}IP Address:{RESET} {YELLOW}{ipaddr}{RESET}")
        print(f"{WHITE}Destination Port:{RESET} {YELLOW}{fliine}{RESET}")
        if loc:
            country, regionName, city, isp = loc
            print(f"{WHITE}Country:{RESET} {country}")
            print(f"{WHITE}State:{RESET} {regionName}")
            print(f"{WHITE}City:{RESET} {city}")
            print(f"{WHITE}ISP:{RESET} {isp}")
        else:
            show_warning("Error locating IP")
        print_rule()
    else:
        show_warning("No target found")

    try:
        os.remove(dumpname)
    except Exception:
        pass

    pause()

def gta_spectate_puller():
    draw_header("GTA 5 TV SPECTATING PULLER")
    show_warning("This mode is not currently implemented.")
    pause()

def xbox_party_server_ip_puller():
    draw_header("XBOX PARTY CHAT SERVER IP PULLER")
    show_info("Getting server info, please wait...")
    time.sleep(1)
    tcpdumpres = []

    dumpname = os.path.join(DATA_DIR, f"{round(time.time())}.pcap")
    tcpdump_cmd = f"sudo tcpdump -i tun0 src {userip} and udp and 'udp[8:4] = 0xaaa501a5' -nn -c 20 > {dumpname}"
    subprocess.getoutput(tcpdump_cmd)
    time.sleep(1)

    try:
        with open(dumpname, "r") as f:
            dump = f.readlines()
    except FileNotFoundError:
        show_error("Failed to open tcpdump output file.")
        pause()
        return

    fliine = "unknown"
    for line in dump:
        if 'IP' in line:
            try:
                liine = line.split(" ")[4]
                aliine = liine.split(".")[0]
                bliine = liine.split(".")[1]
                cliine = liine.split(".")[2]
                dliine = liine.split(".")[3]
                eliine = liine.split(".")[4]
                fliine = eliine.replace(":", "")
                gliine = f"{aliine}.{bliine}.{cliine}.{dliine}"
                tcpdumpres.append(gliine)
            except Exception:
                continue

    if tcpdumpres:
        ipaddr = most_common(tcpdumpres)
        loc = lookup_ip(ipaddr)
        print_rule()
        show_info("The Xbox party server IP address is listed here")
        print()
        print(f"{WHITE}IP Address:{RESET} {YELLOW}{ipaddr}{RESET}")
        print(f"{WHITE}Destination Port:{RESET} {YELLOW}{fliine}{RESET}")
        if loc:
            country, regionName, city, isp = loc
            print(f"{WHITE}Country:{RESET} {country}")
            print(f"{WHITE}State:{RESET} {regionName}")
            print(f"{WHITE}City:{RESET} {city}")
            print(f"{WHITE}ISP:{RESET} {isp}")
        else:
            show_warning("Error locating IP")
        print_rule()
    else:
        show_warning("No server found")

    try:
        os.remove(dumpname)
    except Exception:
        pass

    pause()

def rainbow_siege_server_ip_puller():
    draw_header("RAINBOW 6 SIEGE SERVER IP PULLER")
    show_info("Getting server info, please wait...")
    time.sleep(1)
    tcpdumpres = []

    dumpname = os.path.join(DATA_DIR, f"{round(time.time())}.pcap")
    tcpdump_cmd = f"sudo tcpdump -i tun0 src {userip} and udp and 'ip[2:2] = 86' -nn -c 15 > {dumpname}"
    subprocess.getoutput(tcpdump_cmd)
    time.sleep(1)

    try:
        with open(dumpname, "r") as f:
            dump = f.readlines()
    except FileNotFoundError:
        show_error("Failed to open tcpdump output file.")
        pause()
        return

    fliine = "unknown"
    for line in dump:
        if 'IP' in line:
            try:
                liine = line.split(" ")[4]
                aliine = liine.split(".")[0]
                bliine = liine.split(".")[1]
                cliine = liine.split(".")[2]
                dliine = liine.split(".")[3]
                eliine = liine.split(".")[4]
                fliine = eliine.replace(":", "")
                gliine = aliine + "." + bliine + "." + cliine + "." + dliine
                tcpdumpres.append(gliine)
            except Exception:
                continue

    if tcpdumpres:
        ipaddr = most_common(tcpdumpres)
        loc = lookup_ip(ipaddr)
        print_rule()
        show_info("The Siege server IP address is listed here")
        print()
        print(f"{WHITE}IP Address:{RESET} {YELLOW}{ipaddr}{RESET}")
        print(f"{WHITE}Destination Port:{RESET} {YELLOW}{fliine}{RESET}")
        if loc:
            country, regionName, city, isp = loc
            print(f"{WHITE}Country:{RESET} {country}")
            print(f"{WHITE}State:{RESET} {regionName}")
            print(f"{WHITE}City:{RESET} {city}")
            print(f"{WHITE}ISP:{RESET} {isp}")
        else:
            show_warning("Error locating IP")
        print_rule()
    else:
        show_warning("No lobby found")

    try:
        os.remove(dumpname)
    except Exception:
        pass

    pause()

def fortnite_server_ip_puller():
    draw_header("FORTNITE SERVER IP PULLER")
    show_info("Getting server info, please wait...")
    time.sleep(1)
    tcpdumpres = []

    dumpname = os.path.join(DATA_DIR, f"{round(time.time())}.pcap")
    tcpdump_cmd = f"sudo tcpdump -i tun0 src {userip} and udp and dst portrange 9000-10000 and 'ip[2:2] = 68' -nn -c 20 > {dumpname}"
    subprocess.getoutput(tcpdump_cmd)
    time.sleep(1)

    try:
        with open(dumpname, "r") as f:
            dump = f.readlines()
    except FileNotFoundError:
        show_error("Failed to open tcpdump output file.")
        pause()
        return

    fliine = "unknown"
    for line in dump:
        if 'IP' in line:
            try:
                liine = line.split(" ")[4]
                aliine = liine.split(".")[0]
                bliine = liine.split(".")[1]
                cliine = liine.split(".")[2]
                dliine = liine.split(".")[3]
                eliine = liine.split(".")[4]
                fliine = eliine.replace(":", "")
                gliine = f"{aliine}.{bliine}.{cliine}.{dliine}"
                tcpdumpres.append(gliine)
            except Exception:
                continue

    if tcpdumpres:
        ipaddr = most_common(tcpdumpres)
        loc = lookup_ip(ipaddr)
        print_rule()
        show_info("The Fortnite server IP address is listed here")
        print()
        print(f"{WHITE}IP Address:{RESET} {YELLOW}{ipaddr}{RESET}")
        print(f"{WHITE}Destination Port:{RESET} {YELLOW}{fliine}{RESET}")
        if loc:
            country, regionName, city, isp = loc
            print(f"{WHITE}Country:{RESET} {country}")
            print(f"{WHITE}State:{RESET} {regionName}")
            print(f"{WHITE}City:{RESET} {city}")
            print(f"{WHITE}ISP:{RESET} {isp}")
        else:
            show_warning("Error locating IP")
        print_rule()
    else:
        show_warning("No server found")

    try:
        os.remove(dumpname)
    except Exception:
        pass

    pause()

def Dayz_host_ip_finder():
    draw_header("DAYZ HOST IP FINDER")
    show_info("Getting host info, please wait...")
    time.sleep(1)
    tcpdumpres = []

    dumpname = os.path.join(DATA_DIR, f"{round(time.time())}.pcap")
    tcpdump_cmd = (
        f"sudo tcpdump -i tun0 src {userip} and greater 110 and less 512 and "
        "not host YOUR_FILTER_EXCLUDE_IP_2 and not host YOUR_FILTER_EXCLUDE_IP_1 and not host YOUR_FILTER_EXCLUDE_IP_3 "
        "and not host YOUR_FILTER_EXCLUDE_IP_4 and not host YOUR_FILTER_EXCLUDE_IP_5 and not net 192.168.0.0/16 "
        "-nn -c 70 > " + dumpname
    )
    subprocess.getoutput(tcpdump_cmd)
    time.sleep(1)

    try:
        with open(dumpname, "r") as f:
            dump = f.readlines()
    except FileNotFoundError:
        show_error("Failed to open tcpdump output file.")
        pause()
        return

    fliine = "unknown"
    for line in dump:
        if 'IP' in line:
            try:
                liine = line.split(" ")[4]
                aliine = liine.split(".")[0]
                bliine = liine.split(".")[1]
                cliine = liine.split(".")[2]
                dliine = liine.split(".")[3]
                eliine = liine.split(".")[4]
                fliine = eliine.replace(":", "")
                gliine = f"{aliine}.{bliine}.{cliine}.{dliine}"
                tcpdumpres.append(gliine)
            except Exception:
                continue

    if tcpdumpres:
        ipaddr = most_common(tcpdumpres)
        loc = lookup_ip(ipaddr)
        print_rule()
        show_info("The host IP in your lobby is listed here")
        print()
        print(f"{WHITE}IP Address:{RESET} {YELLOW}{ipaddr}{RESET}")
        print(f"{WHITE}Destination Port:{RESET} {YELLOW}{fliine}{RESET}")
        if loc:
            country, regionName, city, isp = loc
            print(f"{WHITE}Country:{RESET} {country}")
            print(f"{WHITE}State:{RESET} {regionName}")
            print(f"{WHITE}City:{RESET} {city}")
            print(f"{WHITE}ISP:{RESET} {isp}")
        else:
            show_warning("Error locating IP")
        print_rule()
    else:
        show_warning("No host found")

    try:
        os.remove(dumpname)
    except Exception:
        pass

    pause()

def geolocate_ip():
    draw_header("GEO LOCATE IP")
    ipaddr = input(f"{YELLOW}Please enter an IP address:{RESET} ").strip()

    loc = lookup_ip(ipaddr)
    print_rule()
    if loc:
        country, regionName, city, isp = loc
        show_success("The IP address you requested has been located")
        print(f"{WHITE}IP Address:{RESET} {YELLOW}{ipaddr}{RESET}")
        print(f"{WHITE}Country:{RESET} {country}")
        print(f"{WHITE}State:{RESET} {regionName}")
        print(f"{WHITE}City:{RESET} {city}")
        print(f"{WHITE}ISP:{RESET} {isp}")
    else:
        show_error("Error locating IP")
        print(f"{WHITE}IP Address:{RESET} {YELLOW}{ipaddr}{RESET}")
    print_rule()
    pause()

def live_attack_detection():
    draw_header("LIVE ATTACK DETECTION")
    show_warning("This mode is not currently implemented.")
    pause()

def idkmaybe():
    show_warning("This mode is disabled.")
    pause()

if sys.version_info >= (3, 7):
    sys.stdout.reconfigure(encoding='utf-8')


def shared_banner():
    try:
        import importlib.util
        banner_path = "/opt/secure-scripts/dedsec-labNEW/utils/banner.py"
        spec = importlib.util.spec_from_file_location("dedsec_banner", banner_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        def noop_theme():
            return None

        mod.dedsec_banner(GREEN, CYAN, RESET, BOLD, noop_theme)
    except Exception:
        print(f"{GREEN}{BOLD}DEDSEC LAB{RESET}")
        print(f"{GREEN}{'-' * 46}{RESET}")

def print_banner():
    clear_screen()
    shared_banner()
    print(f"{WHITE}Watching source IP:{RESET} {YELLOW}{userip}{RESET}")
    print()

# --- Map menu options to functions ---
menu_actions = {
    "1": gta_lobby_puller,
    "2": gta_nearest_player_puller,
    "3": gta_orb_puller,
    "999": gta_spectate_puller,
    "4": xbox_party_server_ip_puller,
    "5": rainbow_siege_server_ip_puller,
    "6": fortnite_server_ip_puller,
    "7": Dayz_host_ip_finder,
    "8": geolocate_ip
}

# --- Menu loop ---
print_banner()
while True:
    print(f"{WHITE}{BOLD}VPN Tools And Puller Menu{RESET}")
    print(f"{WHITE}Type {CYAN}cls{WHITE} or {CYAN}clear{WHITE} to clear the session.{RESET}")
    print()
    print(f"{CYAN}{BOLD}1.{RESET}  {WHITE}GTA 5 Full Lobby Puller{RESET}")
    print(f"{CYAN}{BOLD}2.{RESET}  {WHITE}GTA 5 Nearest Player Puller{RESET}")
    print(f"{CYAN}{BOLD}3.{RESET}  {WHITE}GTA 5 Orbital Cannon Puller{RESET}")
    print(f"{CYAN}{BOLD}4.{RESET}  {WHITE}Xbox Party Chat Server IP Puller{RESET}")
    print(f"{CYAN}{BOLD}5.{RESET}  {WHITE}Rainbow 6 Siege Server IP Puller{RESET}")
    print(f"{CYAN}{BOLD}6.{RESET}  {WHITE}Fortnite Server IP Puller{RESET}")
    print(f"{CYAN}{BOLD}7.{RESET}  {WHITE}Dayz Host IP Finder{RESET}")
    print(f"{CYAN}{BOLD}8.{RESET}  {WHITE}Geo Locate IP{RESET}")
    print(f"{CYAN}{BOLD}0.{RESET}  {WHITE}Exit{RESET}")
    print()
    print_rule()

    choice = input(f"{YELLOW}Select an option:{RESET} ").strip()

    if choice.lower() in ("cls", "clear"):
        print_banner()
        continue

    if choice == "0":
        print(f"{YELLOW}Goodbye.{RESET}")
        break

    action = menu_actions.get(choice)

    if action:
        action()
        print_banner()
    else:
        show_error("Invalid option was entered!")
        pause()
        print_banner()
