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
try:
    os.makedirs(DATA_DIR, exist_ok=True)
except PermissionError:
    DATA_DIR = "/tmp/vpn_puller"
    os.makedirs(DATA_DIR, exist_ok=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# === COLORS ===
RESET = "\033[0m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
WHITE = "\033[97m"
RED = "\033[31m"
BOLD = "\033[1m"
# === SETTINGS ===
CAPTURE_INTERFACE = "tun0"
CAPTURE_COUNT = 250
# Per-game display limits.
# These limit the number of endpoints displayed in the table.
GAME_LIMITS = {
    "FACEBOOK/META CALL": 4,
    "WHATSAPP CALL": 8,
    "DISCORD VOICE": 8,
    "PLAYSTATION PARTY": 8,
    "PLAYSTATION MULTIPLAYER": 16,
    "XBOX MULTIPLAYER": 16,
    "NINTENDO ONLINE": 8,
    "BLACK OPS 2 ZOMBIES": 4,
    "BLACK OPS 3 ZOMBIES": 8,
    "BLACK OPS 3 MULTIPLAYER": 20,
    "CALL OF DUTY MULTIPLAYER": 20,
    "STEAM/VALVE GAMES": 16,
    "STEAM P2P": 16,
    "SOURCE ENGINE": 32,
    "QUAKE": 16,
    "MINECRAFT SERVER": 20,
    "MINECRAFT BEDROCK": 20,
    "BATTLEFIELD": 64,
    "EA SPORTS FC / FIFA": 22,
    "EA P2P": 22,
    "ROCKET LEAGUE": 8,
    "RUST": 100,
    "VALHEIM": 10,
    "TERRARIA": 8,
    "FACTORIO": 65,
    "ARK SURVIVAL EVOLVED": 16,
    "ARK SURVIVAL ASCENDED": 16,
    "FORTNITE": 24,
    "APEX LEGENDS": 24,
    "VALORANT": 16,
    "GTA ONLINE / FIVEM": 32,
    "RAINBOW SIX SIEGE": 16,
    "PUBG": 24,
    "DESTINY 2": 16,
    "SEA OF THIEVES": 16,
    "PALWORLD": 16,
    "ENSHROUDED": 12,
    "DAYZ / ARMA": 16,
    "PROJECT ZOMBOID": 12,
    "7 DAYS TO DIE": 12,
    "CONAN EXILES": 12,
    "DONT STARVE TOGETHER": 10,
    "STARDEW VALLEY": 8,
    "DEAD BY DAYLIGHT": 12,
    "PHASMOPHOBIA": 10,
    "SONS OF THE FOREST": 12,
    "V RISING": 12,
    "HELLDIVERS 2": 16,
    "LEAGUE OF LEGENDS": 16,
    "OVERWATCH": 16,
    "WAR THUNDER": 16,
    "NO MANS SKY": 10,
    "FALLOUT 76": 16,
    "BROAD UDP GAME TRAFFIC": 20,
    "BROAD TCP GAME TRAFFIC": 20,
}
# Ctrl+C / Ctrl+Z do not terminate the application.
signal.signal(signal.SIGINT, signal.SIG_IGN)
signal.signal(signal.SIGTSTP, signal.SIG_IGN)
# === ARGUMENT CHECK ===
if len(sys.argv) < 2:
    print(f"{RED}Usage: python3 vpn_puller.py <source_ip>{RESET}")
    raise SystemExit
userip = sys.argv[1]
# ============================================================
# SCREEN
# ============================================================
def clear_screen():
    """
    Clear terminal without invoking a shell command.
    """
    print("\033[2J\033[H", end="", flush=True)
def shared_banner():
    try:
        import importlib.util
        banner_path = "/opt/secure-scripts/dedsec-labNEW/utils/banner.py"
        if os.path.exists(banner_path):
            spec = importlib.util.spec_from_file_location(
                "dedsec_banner",
                banner_path
            )
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            mod.dedsec_banner(
                GREEN,
                CYAN,
                RESET,
                BOLD,
                lambda: None
            )
        else:
            raise FileNotFoundError
    except Exception:
        print(f"{GREEN}{BOLD}DEDSEC LAB - VPN PULLER{RESET}")
        print(f"{GREEN}{'-' * 46}{RESET}")
def draw_header(title):
    clear_screen()
    shared_banner()
    print(f"{WHITE}{BOLD}{title}{RESET}")
    print(f"{GREEN}{'-' * 46}{RESET}")
# ============================================================
# IP LOOKUP
# ============================================================
def lookup_ip(ipaddr):
    """
    IP lookup using pro.ip-api.com when IPAPI_KEY is set, else free ip-api.com.
    On 403 / failure from the pro endpoint, falls back to the free line API.
    """
    import os
    try:
        headers = {
            "User-Agent":
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36"
        }
        key = (os.environ.get("IPAPI_KEY") or "").strip()
        if key:
            url = (
                f"https://pro.ip-api.com/line/"
                f"{ipaddr}"
                f"?fields=country,regionName,city,isp"
                f"&key={key}"
            )
            res = requests.get(
                url,
                headers=headers,
                timeout=5
            )
            if res.status_code == 200:
                lines = [
                    line.strip()
                    for line in res.text.splitlines()
                ]
                lines += ["Unknown"] * (4 - len(lines))
                return lines[:4]
            # 403 / other: fall through to free endpoint
        # Free no-key fallback (public ip-api.com)
        fallback_url = (
            f"http://ip-api.com/line/"
            f"{ipaddr}"
            f"?fields=country,regionName,city,isp"
        )
        res = requests.get(
            fallback_url,
            timeout=5
        )
        if res.status_code == 200:
            lines = [
                line.strip()
                for line in res.text.splitlines()
            ]
            lines += ["Unknown"] * (4 - len(lines))
            return lines[:4]
    except requests.exceptions.RequestException:
        return None
    except Exception:
        return None
    return None

def is_private_or_local_ip(ip):
    """
    Filter private/local IPv4 and IPv6 addresses.
    """
    ip = ip.strip("[]")
    # IPv4
    if re.fullmatch(
        r"\d{1,3}(?:\.\d{1,3}){3}",
        ip
    ):
        if ip.startswith(
            (
                "10.",
                "127.",
                "192.168.",
                "169.254."
            )
        ):
            return True
        try:
            first, second, *_ = map(
                int,
                ip.split(".")
            )
            # 172.16.0.0/12
            if first == 172 and 16 <= second <= 31:
                return True
        except Exception:
            pass
        return False
    # IPv6
    ip_lower = ip.lower()
    if (
        ip_lower == "::1"
        or ip_lower.startswith("fe80:")
        or ip_lower.startswith("fc")
        or ip_lower.startswith("fd")
    ):
        return True
    return False
JUNK_ISP = re.compile(
    r"Google|Microsoft|Amazon|AWS|Cloudflare|Akamai|Fastly|"
    r"DigitalOcean|Linode|Akamai|i3D|OVH|Hetzner|SoftLayer|"
    r"Oracle|Alibaba|Tencent|Leaseweb|Choopa|Constant|"
    r"Take-?Two|TakeTwo|2K Games|Rockstar|"
    r"Electronic Arts|EA Games|Sony Interactive|PlayStation Network|"
    r"Nintendo|Xbox Live|Riot Games|Epic Games|Valve Corporation|"
    r"Activision|Blizzard|Ubisoft|Wargaming|Bohemia|"
    r"Level 3|Level3|NTT|Cogent|Edgecast|Limelight|StackPath|"
    r"Highwinds|Incapsula|Sucuri|Cloudfront",
    re.I,
)
# Official publisher / relay ranges that show up as "players".
JUNK_PREFIXES = (
    "185.56.64.",   # Take-Two / Rockstar EU
    "185.56.65.",
    "185.56.66.",
    "185.56.67.",
    "192.81.240.",  # Rockstar
    "192.81.241.",
)
def is_junk_endpoint(ip, isp=""):
    ip = (ip or "").strip("[]")
    if any(ip.startswith(p) for p in JUNK_PREFIXES):
        return True
    if isp and JUNK_ISP.search(isp):
        return True
    return False
def extract_endpoints(line):
    """
    Extract IPv4/IPv6 destination addresses from tcpdump output.
    """
    endpoints = []
    # IPv4
    ipv4_matches = re.findall(
        r">\s*"
        r"(\d{1,3}(?:\.\d{1,3}){3})"
        r"(?:\.(?:\d+))?"
        r"(?:\s*:|\s*$)",
        line
    )
    endpoints.extend(ipv4_matches)
    # IPv4 fallback
    if not ipv4_matches:
        match = re.search(
            r">\s*(\d{1,3}(?:\.\d{1,3}){3})",
            line
        )
        if match:
            endpoints.append(
                match.group(1)
            )
    # IPv6
    ipv6_matches = re.findall(
        r">\s*"
        r"([0-9a-fA-F:]+)"
        r"(?:\.\d+)?"
        r"(?:\s*:|\s*$)",
        line
    )
    endpoints.extend(ipv6_matches)
    # IPv6 fallback
    if not ipv6_matches:
        match = re.search(
            r">\s*"
            r"([0-9a-fA-F]{0,4}:"
            r"[0-9a-fA-F:]+)",
            line
        )
        if match:
            endpoints.append(
                match.group(1)
            )
    cleaned = []
    for ip in endpoints:
        ip = ip.strip(
            "[](),"
        )
        if not ip:
            continue
        if ip not in cleaned:
            cleaned.append(ip)
    return cleaned
# ============================================================
# GENERIC CAPTURE
# ============================================================
def generic_capture(
    title,
    filter_cmd,
    count=CAPTURE_COUNT,
    max_results=None
):
    # Use the per-game limit automatically when one exists.
    if max_results is None:
        max_results = GAME_LIMITS.get(title, 20)
    draw_header(title)
    print(
        f"{YELLOW}"
        f"Capturing on {CAPTURE_INTERFACE}..."
        f"{RESET}"
    )
    print(
        f"{CYAN}"
        f"Filter: {filter_cmd}"
        f"{RESET}"
    )
    print(
        f"{YELLOW}"
        f"Capture count: {count}"
        f"{RESET}"
    )
    print(
        f"{YELLOW}"
        f"Display limit: {max_results}"
        f"{RESET}\n"
    )
    # --------------------------------------------------------
    # Interface check
    # --------------------------------------------------------
    try:
        subprocess.check_output(
            [
                "ip",
                "link",
                "show",
                CAPTURE_INTERFACE
            ],
            stderr=subprocess.STDOUT
        )
    except (
        subprocess.CalledProcessError,
        FileNotFoundError
    ):
        print(
            f"{RED}"
            f"Error: Interface '{CAPTURE_INTERFACE}' "
            f"not found. Ensure VPN is active."
            f"{RESET}"
        )
        input(
            f"\n{YELLOW}"
            f"Press Enter to return to menu..."
            f"{RESET}"
        )
        return
    # --------------------------------------------------------
    # Capture file
    # --------------------------------------------------------
    dumpname = os.path.join(
        DATA_DIR,
        f"capture_{int(time.time())}.pcap"
    )
    # --------------------------------------------------------
    # Build tcpdump command
    # --------------------------------------------------------
    filter_tokens = filter_cmd.split()
    cmd = [
        "sudo",
        "tcpdump",
        "-i",
        CAPTURE_INTERFACE,
        "host",
        userip,
        "and"
    ]
    cmd.extend(filter_tokens)
    cmd.extend(
        [
            "-nn",
            "-c",
            str(count),
            "-w",
            dumpname
        ]
    )
    # --------------------------------------------------------
    # Start capture
    # --------------------------------------------------------
    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
    except Exception as e:
        print(
            f"{RED}"
            f"Failed to start tcpdump: {e}"
            f"{RESET}"
        )
        input(
            f"\n{YELLOW}"
            f"Press Enter to return to menu..."
            f"{RESET}"
        )
        return
    # --------------------------------------------------------
    # Wait quietly.
    # --------------------------------------------------------
    try:
        while proc.poll() is None:
            time.sleep(0.15)
    except KeyboardInterrupt:
        pass
    # --------------------------------------------------------
    # Read tcpdump errors
    # --------------------------------------------------------
    stderr_output = ""
    try:
        if proc.stderr:
            stderr_output = proc.stderr.read()
    except Exception:
        pass
    return_code = proc.returncode
    # --------------------------------------------------------
    # Capture errors
    # --------------------------------------------------------
    if return_code != 0:
        if "Permission denied" in stderr_output:
            print(
                f"{RED}"
                f"Error: sudo privileges are required "
                f"for tcpdump."
                f"{RESET}"
            )
        elif "No such device" in stderr_output:
            print(
                f"{RED}"
                f"Error: interface '{CAPTURE_INTERFACE}' "
                f"does not exist."
                f"{RESET}"
            )
        elif stderr_output.strip():
            print(
                f"{RED}"
                f"tcpdump error:"
                f"{RESET}"
            )
            print(
                stderr_output.strip()
            )
    # --------------------------------------------------------
    # Analyze capture
    # --------------------------------------------------------
    ips = []
    if os.path.exists(dumpname):
        analyze_cmd = [
            "tcpdump",
            "-nn",
            "-r",
            dumpname
        ]
        try:
            analysis = subprocess.run(
                analyze_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30
            )
            for line in analysis.stdout.splitlines():
                for ip in extract_endpoints(line):
                    if not is_private_or_local_ip(ip):
                        ips.append(ip)
        except Exception as e:
            print(
                f"{YELLOW}"
                f"Unable to analyze capture: {e}"
                f"{RESET}"
            )
    # --------------------------------------------------------
    # Deduplicate
    # --------------------------------------------------------
    unique_ips = []
    for ip in ips:
        if ip not in unique_ips:
            unique_ips.append(ip)
    # ========================================================
    # ORIGINAL IP TABLE SIZE
    # ========================================================
    if unique_ips:
        print(
            f"\n{GREEN}"
            f"Found {len(unique_ips)} unique endpoint(s)!"
            f"{RESET}"
        )
        print(
            f"{CYAN}"
            f"IP ADDRESS      || COUNTRY        || "
            f"STATE/REGION   || CITY           || ISP"
            f"{RESET}"
        )
        print(
            f"{GREEN}"
            f"{'=' * 100}"
            f"{RESET}"
        )
        shown = 0
        junk = 0
        skip_junk = title == "ROCKET LEAGUE"
        # Filter junk first so official/cloud IPs do not eat the display limit.
        for ip in unique_ips:
            if shown >= max_results:
                break
            if not skip_junk and any(ip.startswith(p) for p in JUNK_PREFIXES):
                junk += 1
                continue
            loc = lookup_ip(ip)
            if loc:
                country, region, city, isp = loc
                if not skip_junk and is_junk_endpoint(ip, isp):
                    junk += 1
                    continue
                print(
                    f"{WHITE}"
                    f"{ip.ljust(15)} || "
                    f"{country.ljust(14)} || "
                    f"{region.ljust(14)} || "
                    f"{city.ljust(14)} || "
                    f"{isp.ljust(14)}"
                    f"{RESET}"
                )
                shown += 1
            else:
                print(
                    f"{WHITE}"
                    f"{ip.ljust(15)} || "
                    f"Unknown Location Data"
                    f"{RESET}"
                )
                shown += 1
        if junk:
            print(
                f"\n{YELLOW}"
                f"Filtered {junk} official/cloud/publisher endpoint(s)."
                f"{RESET}"
            )
        if shown == 0:
            print(
                f"{YELLOW}"
                f"No player endpoints left after junk filter."
                f"{RESET}"
            )
    else:
        print(
            f"\n{RED}"
            f"No traffic captured for this filter."
            f"{RESET}"
        )
    # --------------------------------------------------------
    # Remove temporary pcap
    # --------------------------------------------------------
    try:
        if os.path.exists(dumpname):
            os.remove(dumpname)
    except Exception:
        pass
    input(
        f"\n{YELLOW}"
        f"Press Enter to return to menu..."
        f"{RESET}"
    )
# ============================================================
# COMMUNICATION / VOICE
# ============================================================
def fb_call():
    generic_capture(
        "FACEBOOK/META CALL",
        "udp dst port 3478"
    )
def wa_call():
    generic_capture(
        "WHATSAPP CALL",
        "udp dst port 3478"
    )
def discord_voice():
    generic_capture(
        "DISCORD VOICE",
        "udp portrange 50000-65535"
    )
# ============================================================
# PLAYSTATION / XBOX / NINTENDO
# ============================================================
def ps_party():
    generic_capture(
        "PLAYSTATION PARTY",
        "udp port 61788"
    )
def playstation_multiplayer():
    generic_capture(
        "PLAYSTATION MULTIPLAYER",
        "udp portrange 3478-3480"
    )
def xbox_multiplayer():
    generic_capture(
        "XBOX MULTIPLAYER",
        "udp port 3074"
    )
def nintendo_online():
    generic_capture(
        "NINTENDO ONLINE",
        "udp portrange 1024-65535"
    )
# ============================================================
# CALL OF DUTY
# ============================================================
def bo2_lobby():
    # Original working BO2 filter retained.
    generic_capture(
        "BLACK OPS 2 ZOMBIES",
        "udp port 3074"
    )
def call_of_duty():
    generic_capture(
        "CALL OF DUTY MULTIPLAYER",
        "udp port 3074"
    )
def bo3_zombies():
    generic_capture(
        "BLACK OPS 3 ZOMBIES",
        "udp and (port 3074 or port 3075 or portrange 27014-27050)"
    )
def bo3_multiplayer():
    generic_capture(
        "BLACK OPS 3 MULTIPLAYER",
        "udp and (port 3074 or port 3075 or portrange 27014-27050)"
    )
# ============================================================
# STEAM / VALVE
# ============================================================
def steam_valve():
    generic_capture(
        "STEAM/VALVE GAMES",
        "udp portrange 27000-27030"
    )
def steam_p2p():
    generic_capture(
        "STEAM P2P",
        "udp portrange 27000-27100"
    )
def source_engine():
    generic_capture(
        "SOURCE ENGINE",
        "udp portrange 27000-27050"
    )
def quake():
    generic_capture(
        "QUAKE",
        "udp port 27960"
    )
# ============================================================
# MINECRAFT
# ============================================================
def minecraft():
    generic_capture(
        "MINECRAFT SERVER",
        "tcp port 25565"
    )
def minecraft_bedrock():
    generic_capture(
        "MINECRAFT BEDROCK",
        "udp port 19132"
    )
# ============================================================
# EA / BATTLEFIELD
# ============================================================
def battlefield():
    generic_capture(
        "BATTLEFIELD",
        "udp port 3659"
    )
def fifa_ea_fc():
    generic_capture(
        "EA SPORTS FC / FIFA",
        "udp port 3659"
    )
def ea_p2p():
    generic_capture(
        "EA P2P",
        "udp port 3659"
    )
# ============================================================
# OTHER MULTIPLAYER / P2P
# ============================================================
def rocket_league():
    generic_capture(
        "ROCKET LEAGUE",
        "udp and (portrange 7000-9100 or port 15016)"
    )
def rust():
    generic_capture(
        "RUST",
        "udp portrange 28015-28016"
    )
def valheim():
    generic_capture(
        "VALHEIM",
        "udp portrange 2456-2458"
    )
def terraria():
    generic_capture(
        "TERRARIA",
        "tcp port 7777"
    )
def factorio():
    generic_capture(
        "FACTORIO",
        "udp port 34197"
    )
# ============================================================
# ARK: SURVIVAL EVOLVED / ASCENDED
# ============================================================
def ark_survival_evolved():
    generic_capture(
        "ARK SURVIVAL EVOLVED",
        "udp and (port 7777 or port 7778 or port 27015)"
    )
def ark_survival_ascended():
    generic_capture(
        "ARK SURVIVAL ASCENDED",
        "udp and (port 7777 or port 7778 or port 7779 or port 27015)"
    )
# ============================================================
# MORE P2P / MULTIPLAYER
# ============================================================
def fortnite():
    generic_capture(
        "FORTNITE",
        "udp and (portrange 9000-9100 or portrange 5795-5845)"
    )
def apex_legends():
    generic_capture(
        "APEX LEGENDS",
        "udp portrange 37000-40000"
    )
def valorant():
    generic_capture(
        "VALORANT",
        "udp portrange 7000-8000"
    )
def gta_fivem():
    generic_capture(
        "GTA ONLINE / FIVEM",
        "udp and (port 6672 or port 30120 or portrange 30110-30130)"
    )
def rainbow_six():
    generic_capture(
        "RAINBOW SIX SIEGE",
        "udp and (port 6015 or portrange 10080-10090)"
    )
def pubg():
    generic_capture(
        "PUBG",
        "udp portrange 7085-7995"
    )
def destiny2():
    generic_capture(
        "DESTINY 2",
        "udp and (port 3097 or port 27015)"
    )
def sea_of_thieves():
    generic_capture(
        "SEA OF THIEVES",
        "udp portrange 30000-30099"
    )
def palworld():
    generic_capture(
        "PALWORLD",
        "udp port 8211"
    )
def enshrouded():
    generic_capture(
        "ENSHROUDED",
        "udp port 15636"
    )
def dayz_arma():
    generic_capture(
        "DAYZ / ARMA",
        "udp and (port 2302 or port 2303 or port 2305)"
    )
def project_zomboid():
    generic_capture(
        "PROJECT ZOMBOID",
        "udp port 16261"
    )
def seven_days():
    generic_capture(
        "7 DAYS TO DIE",
        "udp and (port 26900 or port 26901 or port 26902)"
    )
def conan_exiles():
    generic_capture(
        "CONAN EXILES",
        "udp and (port 7777 or port 7778 or port 27015)"
    )
def dont_starve():
    generic_capture(
        "DONT STARVE TOGETHER",
        "udp port 10999"
    )
def stardew():
    generic_capture(
        "STARDEW VALLEY",
        "tcp port 24642"
    )
def dead_by_daylight():
    generic_capture(
        "DEAD BY DAYLIGHT",
        "udp port 7777"
    )
def phasmophobia():
    generic_capture(
        "PHASMOPHOBIA",
        "udp port 7777"
    )
def sons_of_the_forest():
    generic_capture(
        "SONS OF THE FOREST",
        "udp and (port 8766 or port 27015 or port 27016)"
    )
def v_rising():
    generic_capture(
        "V RISING",
        "udp port 9876"
    )
def helldivers2():
    generic_capture(
        "HELLDIVERS 2",
        "udp portrange 7000-8000"
    )
def league_of_legends():
    generic_capture(
        "LEAGUE OF LEGENDS",
        "udp portrange 5000-5500"
    )
def overwatch():
    generic_capture(
        "OVERWATCH",
        "udp and (port 1119 or port 3724 or port 6113)"
    )
def war_thunder():
    generic_capture(
        "WAR THUNDER",
        "udp portrange 7850-7950"
    )
def no_mans_sky():
    generic_capture(
        "NO MANS SKY",
        "udp and (port 3333 or port 3334)"
    )
def fallout76():
    generic_capture(
        "FALLOUT 76",
        "udp portrange 30000-30099"
    )
# ============================================================
# BROAD GAME TRAFFIC
# ============================================================
def broad_udp_games():
    generic_capture(
        "BROAD UDP GAME TRAFFIC",
        "udp portrange 1024-65535"
    )
def broad_tcp_games():
    generic_capture(
        "BROAD TCP GAME TRAFFIC",
        "tcp portrange 1024-65535"
    )
# ============================================================
# MENU PAGES
# ============================================================
PAGES = [
    [
        ("1", "Facebook/Meta Call", fb_call),
        ("2", "WhatsApp Call", wa_call),
        ("3", "Discord Voice", discord_voice),
        ("4", "PlayStation Party", ps_party),
        ("5", "Xbox Multiplayer", xbox_multiplayer),
    ],
    [
        ("6", "PlayStation Multiplayer", playstation_multiplayer),
        ("7", "Nintendo Online", nintendo_online),
        ("8", "Black Ops 2 Zombies", bo2_lobby),
        ("9", "Call of Duty Multiplayer", call_of_duty),
        ("10", "Black Ops 3 Zombies", bo3_zombies),
        ("11", "Black Ops 3 Multiplayer", bo3_multiplayer),
        ("12", "Steam/Valve Games", steam_valve),
    ],
    [
        ("13", "Steam P2P", steam_p2p),
        ("14", "Source Engine", source_engine),
        ("15", "Minecraft Server", minecraft),
        ("16", "Minecraft Bedrock", minecraft_bedrock),
        ("17", "Battlefield", battlefield),
    ],
    [
        ("18", "EA Sports FC / FIFA", fifa_ea_fc),
        ("19", "EA P2P", ea_p2p),
        ("20", "Rocket League", rocket_league),
        ("21", "Rust", rust),
        ("22", "Valheim", valheim),
    ],
    [
        ("23", "Terraria", terraria),
        ("24", "Factorio", factorio),
        ("25", "Quake", quake),
        ("26", "Broad UDP Games", broad_udp_games),
        ("27", "Broad TCP Games", broad_tcp_games),
    ],
    [
        ("28", "ARK: Survival Evolved", ark_survival_evolved),
        ("29", "ARK: Survival Ascended", ark_survival_ascended),
        ("30", "Fortnite", fortnite),
        ("31", "Apex Legends", apex_legends),
        ("32", "Valorant", valorant),
    ],
    [
        ("33", "GTA Online / FiveM", gta_fivem),
        ("34", "Rainbow Six Siege", rainbow_six),
        ("35", "PUBG", pubg),
        ("36", "Destiny 2", destiny2),
        ("37", "Sea of Thieves", sea_of_thieves),
    ],
    [
        ("38", "Palworld", palworld),
        ("39", "Enshrouded", enshrouded),
        ("40", "DayZ / Arma", dayz_arma),
        ("41", "Project Zomboid", project_zomboid),
        ("42", "7 Days to Die", seven_days),
    ],
    [
        ("43", "Conan Exiles", conan_exiles),
        ("44", "Don't Starve Together", dont_starve),
        ("45", "Stardew Valley", stardew),
        ("46", "Dead by Daylight", dead_by_daylight),
        ("47", "Phasmophobia", phasmophobia),
    ],
    [
        ("48", "Sons of the Forest", sons_of_the_forest),
        ("49", "V Rising", v_rising),
        ("50", "Helldivers 2", helldivers2),
        ("51", "League of Legends", league_of_legends),
        ("52", "Overwatch", overwatch),
    ],
    [
        ("53", "War Thunder", war_thunder),
        ("54", "No Man's Sky", no_mans_sky),
        ("55", "Fallout 76", fallout76),
    ],
]
# ============================================================
# MAIN MENU
# ============================================================
current_page = 0
running = True
while running:
    try:
        clear_screen()
        shared_banner()
        print(
            f"{WHITE}"
            f"Watching: "
            f"{YELLOW}{userip}"
            f"{RESET}"
            f" | "
            f"{WHITE}"
            f"Page: "
            f"{CYAN}"
            f"{current_page + 1}/{len(PAGES)}"
            f"{RESET}"
        )
        print(
            f"{GREEN}"
            f"{'=' * 46}"
            f"{RESET}"
        )
        for key, name, func in PAGES[current_page]:
            print(
                f"{CYAN}"
                f"{key.ljust(3)}"
                f"{RESET}"
                f" {WHITE}"
                f"{name}"
                f"{RESET}"
            )
        print(
            f"\n{YELLOW}"
            f"N"
            f"{RESET}"
            f" Next | "
            f"{YELLOW}"
            f"P"
            f"{RESET}"
            f" Previous | "
            f"{YELLOW}"
            f"Q"
            f"{RESET}"
            f" Quit"
        )
        cmd = input(
            f"\n{BOLD}"
            f"Choice >> "
            f"{RESET}"
        ).strip().lower()
        # ----------------------------------------------------
        # NEXT
        # ----------------------------------------------------
        if cmd == "n":
            if current_page < len(PAGES) - 1:
                current_page += 1
            else:
                current_page = 0
            continue
        # ----------------------------------------------------
        # PREVIOUS
        # ----------------------------------------------------
        elif cmd == "p":
            if current_page > 0:
                current_page -= 1
            else:
                current_page = len(PAGES) - 1
            continue
        # ----------------------------------------------------
        # ONLY MENU EXIT
        # ----------------------------------------------------
        elif cmd in ("q", "0"):
            clear_screen()
            print(
                f"{GREEN}"
                f"DEDSEC LAB - VPN PULLER"
                f"{RESET}"
            )
            print(
                f"{YELLOW}"
                f"Exiting via menu..."
                f"{RESET}"
            )
            running = False
            continue
        # ----------------------------------------------------
        # CLEAR
        # ----------------------------------------------------
        elif cmd in ("cls", "clear"):
            continue
        # ----------------------------------------------------
        # MENU SELECTION
        # ----------------------------------------------------
        else:
            found = False
            for key, name, func in PAGES[current_page]:
                if cmd == key:
                    found = True
                    try:
                        func()
                    except KeyboardInterrupt:
                        pass
                    except Exception as e:
                        print(
                            f"\n{RED}"
                            f"Capture Error: {e}"
                            f"{RESET}"
                        )
                        input(
                            f"\n{YELLOW}"
                            f"Press Enter to return to menu..."
                            f"{RESET}"
                        )
                    break
            if not found:
                print(
                    f"{RED}"
                    f"Invalid Option!"
                    f"{RESET}"
                )
                time.sleep(1)
    except KeyboardInterrupt:
        continue
    except EOFError:
        print(
            f"\n{YELLOW}"
            f"Input unavailable. Use Q from the menu to exit."
            f"{RESET}"
        )
        time.sleep(2)
        continue
    except Exception as e:
        print(
            f"{RED}"
            f"Main Loop Error: {e}"
            f"{RESET}"
        )
        time.sleep(2)
# ============================================================
# CLEAN END
# ============================================================
clear_screen()
print(
    f"{GREEN}"
    f"VPN PULLER CLOSED."
    f"{RESET}"
)

