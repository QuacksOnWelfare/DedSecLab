#!/usr/bin/env python3
import os
import json
import csv
import time
import signal
import sqlite3
import subprocess
import importlib.util
from collections import Counter
from datetime import datetime, UTC

from scapy.all import sniff, IP, TCP, UDP, ICMP

BASE_DIR = "/opt/secure-scripts/dedsec-labNEW"
PANEL_DIR = os.path.join(BASE_DIR, "root_owner", "traffic_intelligence")
DATA_DIR = os.path.join(PANEL_DIR, "data")
EXPORT_DIR = os.path.join(PANEL_DIR, "exports")
LOG_DIR = "/var/log/ddos-watch"
SUMMARY_FILE = os.path.join(LOG_DIR, "latest_summary.json")
DB_FILE = os.path.join(DATA_DIR, "ip_database.sqlite")

WATCH_PORTS = [6672, 9981]
MY_HOME_IPS = {"YOUR_HOME_IP"}  # your public IP(s) to tag as home
IGNORE_IPS = {"YOUR_VPN_EXIT_FRANCE"}
INTERVAL = 10
ALERT_PACKET_THRESHOLD = 1000
WATCH_PORT_THRESHOLD = 500
PCAP_SECONDS = 45
OPENVPN_SERVICE = "openvpn-server@server"

RESET="\033[0m"; GREEN="\033[32m"; YELLOW="\033[33m"; CYAN="\033[36m"; WHITE="\033[97m"; RED="\033[31m"; BOLD="\033[1m"; PURPLE="\033[35m"

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(EXPORT_DIR, exist_ok=True)

GEO_CACHE = {}
ISP_CACHE = {}

def clear():
    os.system("clear")

def pause():
    input(f"\n{YELLOW}Press Enter to continue...{RESET}")

def banner():
    try:
        banner_path = os.path.join(BASE_DIR, "utils", "banner.py")
        spec = importlib.util.spec_from_file_location("dedsec_banner", banner_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.dedsec_banner(GREEN, CYAN, RESET, BOLD, lambda: None)
    except Exception:
        print(f"{GREEN}{BOLD}DEDSEC Traffic Intelligence{RESET}")
        print(f"{GREEN}{'=' * 56}{RESET}")

def run(cmd):
    return subprocess.run(cmd, text=True, capture_output=True)

def shell(cmd):
    return subprocess.run(cmd, shell=True, text=True, capture_output=True).stdout.strip()

def timestamp():
    return datetime.now(UTC).strftime("%Y-%m-%d_%H-%M-%S")

def start_pcap():
    filename = f"{LOG_DIR}/attack-{timestamp()}.pcap"
    subprocess.Popen(
        ["timeout", str(PCAP_SECONDS), "tcpdump", "-i", "eth0", "-n", "-s", "160", "-w", filename, "udp or tcp"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return filename

def geo_lookup(ip):
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]

    if ip.startswith(("10.", "192.168.", "127.", "169.254.")):
        GEO_CACHE[ip] = "LOCAL"
        return "LOCAL"

    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            if 16 <= second <= 31:
                GEO_CACHE[ip] = "LOCAL"
                return "LOCAL"
        except Exception:
            pass

    try:
        result = subprocess.run(["geoiplookup", ip], text=True, capture_output=True, timeout=1)
        out = result.stdout.strip()
        loc = out.split("GeoIP Country Edition:")[-1].strip() if "GeoIP Country Edition:" in out else "Unknown"
        GEO_CACHE[ip] = loc
        return loc
    except Exception:
        GEO_CACHE[ip] = "Unknown"
        return "Unknown"

def isp_lookup(ip):
    if ip in ISP_CACHE:
        return ISP_CACHE[ip]

    if ip.startswith(("10.", "192.168.", "127.", "169.254.")):
        ISP_CACHE[ip] = "LOCAL"
        return "LOCAL"

    try:
        out = subprocess.run(["whois", ip], text=True, capture_output=True, timeout=2).stdout
        keys = ["organization:", "orgname:", "org-name:", "owner:", "netname:", "descr:"]
        for line in out.splitlines():
            lower = line.lower().strip()
            for key in keys:
                if lower.startswith(key):
                    val = line.split(":", 1)[-1].strip()
                    ISP_CACHE[ip] = val[:45] if val else "Unknown"
                    return ISP_CACHE[ip]
        ISP_CACHE[ip] = "Unknown"
        return "Unknown"
    except Exception:
        ISP_CACHE[ip] = "Unknown"
        return "Unknown"

def ip_label(ip, loc=""):
    if ip in MY_HOME_IPS:
        return "YOU"

    if ip.startswith(("10.", "192.168.", "127.", "169.254.")):
        return "LOCAL"

    cloudflare = ("104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.23.", "172.64.", "172.65.", "172.66.", "172.67.", "162.158.", "162.159.", "188.114.")
    google = ("142.250.", "142.251.", "172.217.", "172.253.", "216.58.", "108.177.", "74.125.", "209.85.", "192.178.", "173.194.", "216.239.")
    apple = ("17.",)
    aws = ("3.", "13.", "15.", "18.", "34.", "35.", "44.", "52.", "54.", "99.")
    akamai = ("2.16.", "2.17.", "2.18.", "2.19.", "23.32.", "23.33.", "23.34.", "23.35.", "23.36.", "23.37.", "95.100.", "95.101.", "104.64.", "104.65.", "104.66.", "104.67.", "104.77.", "184.24.", "184.25.", "184.26.", "184.27.")
    fastly = ("151.101.", "199.232.")
    ovh = ("135.125.", "137.74.", "145.239.", "149.202.", "151.80.", "164.132.", "176.31.", "178.32.", "188.165.", "51.38.", "51.68.", "51.75.", "51.77.", "51.89.")

    if ip.startswith(cloudflare): return "CLOUDFLARE/CDN"
    if ip.startswith(google): return "GOOGLE/CDN"
    if ip.startswith(akamai): return "AKAMAI/CDN"
    if ip.startswith(fastly): return "FASTLY/CDN"
    if ip.startswith(apple): return "APPLE/CDN"
    if ip.startswith(ovh): return "OVH/VPS"
    if ip.startswith(aws): return "AWS/CLOUD"

    text = loc.lower()
    cloud_words = ["google", "amazon", "aws", "cloudflare", "akamai", "microsoft", "apple", "fastly", "ovh", "digitalocean", "linode", "oracle", "hetzner", "leaseweb", "cdn", "hosting", "cloud"]
    vpn_words = ["vpn", "proxy", "datacenter", "data center", "server", "vps"]
    isp_words = ["telecom", "comcast", "virgin", "bt", "sky", "vodafone", "orange", "turkcell", "cantv", "telefonica", "movistar", "claro", "telmex", "verizon", "charter", "spectrum", "cox", "rogers", "bell", "t-mobile", "telekom", "iliad", "free", "wind", "tim", "o2"]

    if any(w in text for w in cloud_words): return "CLOUD/CDN"
    if any(w in text for w in vpn_words): return "VPN/VPS"
    if any(w in text for w in isp_words): return "POSSIBLE HOME/ISP"
    if loc and loc not in ("Unknown", "LOCAL", "IP Address not found"): return "POSSIBLE HOME/ISP"
    return "UNKNOWN"

def smart_label(ip, geo, network):
    base = ip_label(ip, geo)
    text = (network or "").lower()
    if "google" in text or "googl" in text: return "GOOGLE/CDN"
    if "cloudflare" in text: return "CLOUDFLARE/CDN"
    if "akamai" in text: return "AKAMAI/CDN"
    if "fastly" in text: return "FASTLY/CDN"
    if "apple" in text: return "APPLE/CDN"
    if "amazon" in text or "amazo" in text or "aws" in text or "at-88-z" in text: return "AWS/CLOUD"
    if "ovh" in text or "ripe" in text and ip.startswith("135.125."): return "OVH/VPS"
    if "hetzner" in text: return "HETZNER/VPS"
    if "digitalocean" in text: return "DIGITALOCEAN/VPS"
    return base

def label_color(label):
    if label == "YOU": return GREEN
    if label == "LOCAL": return CYAN
    if "CLOUD" in label or "CDN" in label: return PURPLE
    if "HOME" in label: return YELLOW
    if "VPS" in label: return RED
    if label == "UNKNOWN": return RED
    return WHITE

def init_ip_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS attacker_ips (
            ip TEXT PRIMARY KEY,
            label TEXT,
            geo TEXT,
            network TEXT,
            first_seen TEXT,
            last_seen TEXT,
            total_hits INTEGER DEFAULT 0,
            notes TEXT DEFAULT '',
            source TEXT DEFAULT ''
        )
    """)
    conn.commit()
    conn.close()

def save_ip_to_db(ip, hits=0, source="manual", notes=""):
    init_ip_db()
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    geo = geo_lookup(ip)
    network = isp_lookup(ip)
    label = smart_label(ip, geo, network)

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT total_hits, first_seen, notes, source FROM attacker_ips WHERE ip = ?", (ip,))
    row = cur.fetchone()

    if row:
        old_hits, first_seen, old_notes, old_source = row
        merged_notes = old_notes or notes
        merged_source = old_source if source in old_source else (old_source + "," + source if old_source else source)
        cur.execute("""
            UPDATE attacker_ips
            SET label=?, geo=?, network=?, last_seen=?, total_hits=?, notes=?, source=?
            WHERE ip=?
        """, (label, geo, network, now, int(old_hits or 0) + int(hits or 0), merged_notes, merged_source, ip))
    else:
        cur.execute("""
            INSERT INTO attacker_ips
            (ip, label, geo, network, first_seen, last_seen, total_hits, notes, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ip, label, geo, network, now, now, int(hits or 0), notes, source))
    conn.commit()
    conn.close()

def db_seen_before(ip):
    try:
        init_ip_db()
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("SELECT total_hits, source, label FROM attacker_ips WHERE ip = ?", (ip,))
        row = cur.fetchone()
        conn.close()
        if row:
            hits, source, label = row
            return True, int(hits or 0), source or "", label or ""
        return False, 0, "", ""
    except Exception:
        return False, 0, "", ""

def classify(total, watch_total, protocols, src_ips, dst_ports):
    if total == 0: return "quiet", 0
    udp = protocols.get("UDP", 0)
    udp_ratio = udp / total if total else 0
    unique_sources = len(src_ips)
    score = 0
    if total >= ALERT_PACKET_THRESHOLD: score += 35
    if watch_total >= WATCH_PORT_THRESHOLD: score += 25
    if udp_ratio >= 0.80: score += 20
    if unique_sources >= 20: score += 20
    if dst_ports.get("UDP/6672", 0) > 300: score += 15
    if dst_ports.get("UDP/9981", 0) > 300: score += 15
    if score >= 70: return "likely_ddos", score
    if score >= 40: return "suspicious_spike", score
    if score >= 20: return "heavy_normal_or_scan", score
    return "normal", score

def detect_live_attack_type(total, watch_total, protocols, src_ips, dst_ports):
    if total <= 0: return "quiet", "No traffic detected", 0
    udp = protocols.get("UDP", 0)
    unique_sources = len(src_ips)
    gta_hits = dst_ports.get("UDP/6672", 0)
    vpn_hits = dst_ports.get("UDP/9981", 0)
    udp_ratio = udp / total if total else 0
    confidence = 0
    reasons = []

    if udp_ratio >= 0.90:
        confidence += 25; reasons.append("mostly UDP")
    if gta_hits >= 300:
        confidence += 30; reasons.append("heavy UDP/6672 GTA traffic")
    if unique_sources >= 100:
        confidence += 30; reasons.append("very high source IP diversity")
    elif unique_sources >= 30:
        confidence += 20; reasons.append("high source IP diversity")
    if watch_total >= 500:
        confidence += 15; reasons.append("watch ports under pressure")
    if vpn_hits >= 300:
        confidence += 10; reasons.append("VPN port also receiving traffic")

    if confidence >= 80: return "GTA BOOTER / BOTNET UDP FLOOD", ", ".join(reasons), confidence
    if confidence >= 55: return "SUSPICIOUS GTA UDP FLOOD", ", ".join(reasons), confidence
    if confidence >= 30: return "HEAVY GTA / PEER TRAFFIC", ", ".join(reasons), confidence
    return "NORMAL / LOW TRAFFIC", ", ".join(reasons) if reasons else "low volume", confidence

def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"{RED}Could not read file:{RESET} {YELLOW}{path}{RESET}")
        print(f"{RED}{e}{RESET}")
        return None

def print_report(data):
    if not data:
        return
    status = data.get("classification", "unknown")
    color = GREEN if status not in ("likely_ddos", "suspicious_spike") else (RED if status == "likely_ddos" else YELLOW)
    print(f"{CYAN}Time:{RESET}        {YELLOW}{data.get('timestamp_utc')}{RESET}")
    print(f"{CYAN}Status:{RESET}      {color}{BOLD}{status}{RESET}")
    print(f"{CYAN}Score:{RESET}       {YELLOW}{data.get('attack_score')}{RESET}")
    print(f"{CYAN}Packets:{RESET}     {YELLOW}{data.get('total_packets')}{RESET}")
    print(f"{CYAN}Watch Hits:{RESET}  {YELLOW}{data.get('watch_port_packets')}{RESET}")
    print(f"{CYAN}PCAP:{RESET}        {YELLOW}{data.get('pcap_file')}{RESET}")

    print(f"\n{WHITE}{BOLD}Top Source IPs:{RESET}")
    for ip, count in data.get("top_source_ips", [])[:15]:
        loc = geo_lookup(ip)
        net = isp_lookup(ip)
        label = smart_label(ip, loc, net)
        color = label_color(label)
        print(f"{CYAN}- {ip:<18}{RESET} {YELLOW}{count:<6}{RESET} {color}{label:<18}{RESET} {CYAN}{loc:<24}{RESET} {WHITE}{net}{RESET}")

    print(f"\n{WHITE}{BOLD}Top Destination Ports:{RESET}")
    for port, count in data.get("top_destination_ports", [])[:15]:
        print(f"{CYAN}- {port:<12}{RESET} {YELLOW}{count}{RESET}")

    print(f"\n{WHITE}{BOLD}Protocols:{RESET}")
    for proto, count in data.get("protocols", []):
        print(f"{CYAN}- {proto:<8}{RESET} {YELLOW}{count}{RESET}")

def live_watch():
    src_ips = Counter()
    dst_ports = Counter()
    src_ports = Counter()
    protocols = Counter()
    watch_hits = Counter()
    last_alert = 0
    running = True

    def handle_packet(pkt):
        if IP not in pkt: return
        src = pkt[IP].src
        if src in IGNORE_IPS: return
        src_ips[src] += 1

        if UDP in pkt:
            proto = "UDP"; sport = pkt[UDP].sport; dport = pkt[UDP].dport
        elif TCP in pkt:
            proto = "TCP"; sport = pkt[TCP].sport; dport = pkt[TCP].dport
        elif ICMP in pkt:
            protocols["ICMP"] += 1; return
        else:
            protocols[f"IP_PROTO_{pkt[IP].proto}"] += 1; return

        protocols[proto] += 1
        src_ports[f"{proto}/{sport}"] += 1
        dst_ports[f"{proto}/{dport}"] += 1
        if sport in WATCH_PORTS or dport in WATCH_PORTS:
            watch_hits[src] += 1

    def make_report(is_alert=False, pcap=None):
        total = sum(src_ips.values())
        watch_total = sum(watch_hits.values())
        status, score = classify(total, watch_total, protocols, src_ips, dst_ports)
        report = {
            "timestamp_utc": timestamp(),
            "interval_seconds": INTERVAL,
            "classification": status,
            "attack_score": score,
            "total_packets": total,
            "watch_ports": WATCH_PORTS,
            "watch_port_packets": watch_total,
            "ignored_ips": sorted(IGNORE_IPS),
            "top_source_ips": src_ips.most_common(50),
            "top_destination_ports": dst_ports.most_common(50),
            "top_source_ports": src_ports.most_common(50),
            "protocols": protocols.most_common(),
            "top_sources_hitting_watch_ports": watch_hits.most_common(50),
            "pcap_file": pcap
        }
        name = "ALERT" if is_alert else "report"
        path = f"{LOG_DIR}/{name}-{report['timestamp_utc']}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        with open(SUMMARY_FILE, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        return report, path

    def draw(report, alert_path=None):
        clear(); banner()
        status = report["classification"]
        color = GREEN if status not in ("likely_ddos", "suspicious_spike") else (RED if status == "likely_ddos" else YELLOW)

        print(f"{WHITE}{BOLD}Live Traffic Watch:{RESET}\n")
        print(f"{CYAN}Status:{RESET}      {color}{BOLD}{status}{RESET}")
        print(f"{CYAN}Score:{RESET}       {YELLOW}{report['attack_score']}{RESET}")
        print(f"{CYAN}Packets:{RESET}     {YELLOW}{report['total_packets']}{RESET} / {INTERVAL}s")
        print(f"{CYAN}Watch Hits:{RESET}  {YELLOW}{report['watch_port_packets']}{RESET}")
        print(f"{CYAN}Ports:{RESET}       {YELLOW}{WATCH_PORTS}{RESET}")
        print(f"{CYAN}Logs:{RESET}        {YELLOW}{LOG_DIR}{RESET}")

        attack_type, attack_reason, attack_conf = detect_live_attack_type(
            report["total_packets"], report["watch_port_packets"], dict(report["protocols"]),
            dict(report["top_source_ips"]), dict(report["top_destination_ports"])
        )
        attack_color = RED if attack_conf >= 80 else (YELLOW if attack_conf >= 55 else GREEN)
        print(f"{CYAN}Attack Type:{RESET} {attack_color}{BOLD}{attack_type}{RESET}")
        print(f"{CYAN}Confidence:{RESET}  {YELLOW}{attack_conf}%{RESET}")
        print(f"{CYAN}Reason:{RESET}      {YELLOW}{attack_reason}{RESET}")

        if alert_path:
            print(f"\n{RED}{BOLD}[!] Alert saved:{RESET} {YELLOW}{alert_path}{RESET}")

        print(f"\n{WHITE}{BOLD}Top Source IPs:{RESET}")
        for ip, count in report["top_source_ips"][:10]:
            loc = geo_lookup(ip)
            net = isp_lookup(ip)
            label = smart_label(ip, loc, net)
            seen, old_hits, old_source, db_label = db_seen_before(ip)
            if db_label:
                label = db_label
            color = label_color(label)
            seen_tag = f" {RED}{BOLD}SEEN:{RESET}{YELLOW}{old_hits}{RESET}" if seen and label not in ("YOU", "LOCAL") else ""
            print(f"{CYAN}- {ip:<18}{RESET} {YELLOW}{count:<6}{RESET} {color}{label:<18}{RESET} {CYAN}{loc}{RESET}{seen_tag}")

        print(f"\n{WHITE}{BOLD}Top Destination Ports:{RESET}")
        for port, count in report["top_destination_ports"][:10]:
            print(f"{CYAN}- {port:<12}{RESET} {YELLOW}{count}{RESET}")

        print(f"\n{GREEN}{'-' * 46}{RESET}")
        print(f"{YELLOW}CTRL+C = stop watching and return to menu{RESET}")

    def stop(signum, frame):
        nonlocal running
        running = False

    old_handler = signal.signal(signal.SIGINT, stop)
    clear(); banner()
    print(f"{GREEN}[+] Starting live watcher on eth0...{RESET}")
    print(f"{YELLOW}CTRL+C to return to menu.{RESET}")
    time.sleep(1)

    import threading
    def reporter():
        nonlocal last_alert
        while running:
            time.sleep(INTERVAL)
            total = sum(src_ips.values())
            watch_total = sum(watch_hits.values())
            is_alert = total >= ALERT_PACKET_THRESHOLD or watch_total >= WATCH_PORT_THRESHOLD
            pcap = None
            if is_alert and time.time() - last_alert > 60:
                pcap = start_pcap()
                last_alert = time.time()

            report, path = make_report(is_alert=is_alert, pcap=pcap)
            if is_alert:
                try:
                    for ip, count in report.get("top_source_ips", []):
                        save_ip_to_db(ip, hits=int(count), source="auto_alert")
                except Exception:
                    pass
            draw(report, alert_path=path if is_alert else None)
            src_ips.clear(); dst_ports.clear(); src_ports.clear(); protocols.clear(); watch_hits.clear()

    t = threading.Thread(target=reporter, daemon=True)
    t.start()

    try:
        sniff(iface="ens3", filter="udp or tcp or icmp", prn=handle_packet, store=False, promisc=False, stop_filter=lambda pkt: not running)
    except KeyboardInterrupt:
        pass
    finally:
        signal.signal(signal.SIGINT, old_handler)

def view_latest():
    clear(); banner()
    print(f"{WHITE}{BOLD}Latest Summary:{RESET}\n")
    print_report(load_json(SUMMARY_FILE))
    pause()

def list_logs(prefix=None):
    files = []
    if not os.path.isdir(LOG_DIR):
        return []
    for f in os.listdir(LOG_DIR):
        if not f.endswith(".json"): continue
        if prefix and not f.startswith(prefix): continue
        files.append(f)
    files.sort(reverse=True)
    return files

def view_log_menu(prefix=None, title="Logs"):
    while True:
        clear(); banner()
        print(f"{WHITE}{BOLD}{title}:{RESET}\n")
        files = list_logs(prefix)[:30]
        if not files:
            print(f"{YELLOW}No logs found.{RESET}")
            pause(); return
        for i, name in enumerate(files, 1):
            color = RED if name.startswith("ALERT") else CYAN
            print(f"{color}{BOLD}{i}.{RESET} {WHITE}{name}{RESET}")
        print(f"{CYAN}{BOLD}0.{RESET} {WHITE}Back{RESET}")
        choice = input(f"\n{YELLOW}Select:{RESET} ").strip()
        if choice == "0": return
        if not choice.isdigit(): continue
        idx = int(choice) - 1
        if 0 <= idx < len(files):
            clear(); banner()
            print(f"{WHITE}{BOLD}{files[idx]}:{RESET}\n")
            print_report(load_json(os.path.join(LOG_DIR, files[idx])))
            pause()

def render_attack_ip_summary(files, title):
    clear(); banner()
    totals = {}
    for name in files:
        data = load_json(os.path.join(LOG_DIR, name))
        if not data: continue
        for ip, count in data.get("top_source_ips", []):
            totals[ip] = totals.get(ip, 0) + int(count)

    print(f"{WHITE}{BOLD}{title}:{RESET}\n")
    if not totals:
        print(f"{YELLOW}No IP data found.{RESET}")
        pause(); return

    for i, (ip, count) in enumerate(sorted(totals.items(), key=lambda x: x[1], reverse=True)[:50], 1):
        loc = geo_lookup(ip); net = isp_lookup(ip); label = smart_label(ip, loc, net); color = label_color(label)
        print(f"{CYAN}{i:02d}.{RESET} {WHITE}{ip:<18}{RESET} {YELLOW}{count:<8}{RESET} {color}{label:<18}{RESET} {CYAN}{loc:<24}{RESET} {WHITE}{net}{RESET}")

    print(f"\n{GREEN}{'-' * 46}{RESET}")
    print(f"{YELLOW}Files analyzed: {len(files)} ALERT log(s). Network / ASN shown at far right.{RESET}")
    pause()

def attack_ip_summary():
    while True:
        clear(); banner()
        alerts = [f for f in os.listdir(LOG_DIR) if f.startswith("ALERT") and f.endswith(".json")]
        alerts.sort(reverse=True)
        print(f"{WHITE}{BOLD}Attack IP Summary:{RESET}\n")
        print(f"{CYAN}{BOLD}1.{RESET}  {WHITE}Last Attack Only{RESET}")
        print(f"{CYAN}{BOLD}2.{RESET}  {WHITE}All Alerts Combined{RESET}")
        print(f"{CYAN}{BOLD}0.{RESET}  {WHITE}Back{RESET}")
        if alerts:
            print(f"\n{CYAN}Latest ALERT:{RESET} {YELLOW}{alerts[0]}{RESET}")
            print(f"{CYAN}Total ALERT logs:{RESET} {YELLOW}{len(alerts)}{RESET}")
        else:
            print(f"\n{YELLOW}No ALERT logs found.{RESET}")
        choice = input(f"\n{YELLOW}Select:{RESET} ").strip()
        if choice == "0": return
        if not alerts: pause(); return
        if choice == "1": render_attack_ip_summary([alerts[0]], "Last Attack IP Summary")
        elif choice == "2": render_attack_ip_summary(alerts, "All Alerts Combined IP Summary")

def clear_logs():
    clear(); banner()
    confirm = input(f"{RED}Delete all traffic logs and pcaps? Type YES:{RESET} ").strip()
    if confirm != "YES":
        print(f"{YELLOW}Cancelled.{RESET}"); pause(); return
    deleted = 0
    for f in os.listdir(LOG_DIR):
        if f.endswith(".json") or f.endswith(".pcap"):
            try:
                os.remove(os.path.join(LOG_DIR, f)); deleted += 1
            except Exception:
                pass
    print(f"{GREEN}Deleted {deleted} files.{RESET}")
    pause()

def openvpn_status():
    clear(); banner()
    print(f"{WHITE}{BOLD}OpenVPN Status:{RESET}\n")
    result = run(["systemctl", "status", OPENVPN_SERVICE, "--no-pager"])
    print(result.stdout or result.stderr)
    print(f"\n{WHITE}{BOLD}Listening Ports:{RESET}\n")
    result = run(["ss", "-tulnp"])
    for line in result.stdout.splitlines():
        if "openvpn" in line or ":9981" in line:
            print(f"{YELLOW}{line}{RESET}")
    pause()

def restart_openvpn():
    clear(); banner()
    print(f"{YELLOW}Restarting OpenVPN...{RESET}")
    run(["systemctl", "restart", OPENVPN_SERVICE])
    time.sleep(2)
    state = run(["systemctl", "is-active", OPENVPN_SERVICE]).stdout.strip()
    print(f"{GREEN}OpenVPN restarted successfully.{RESET}" if state == "active" else f"{RED}OpenVPN state: {state}{RESET}")
    pause()

def repair_vpn_nat():
    clear(); banner()
    print(f"{YELLOW}Applying VPN NAT/forwarding repair...{RESET}")
    run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    if run(["iptables", "-t", "nat", "-C", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE"]).returncode != 0:
        run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE"])
    if run(["iptables", "-C", "FORWARD", "-i", "tun0", "-o", "eth0", "-j", "ACCEPT"]).returncode != 0:
        run(["iptables", "-A", "FORWARD", "-i", "tun0", "-o", "eth0", "-j", "ACCEPT"])
    if run(["iptables", "-C", "FORWARD", "-i", "eth0", "-o", "tun0", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"]).returncode != 0:
        run(["iptables", "-A", "FORWARD", "-i", "eth0", "-o", "tun0", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
    run(["systemctl", "restart", OPENVPN_SERVICE])
    print(f"{GREEN}NAT repair applied and OpenVPN restarted.{RESET}")
    pause()

def tshark_exists():
    return subprocess.run(["which", "tshark"], capture_output=True).returncode == 0

def choose_pcap():
    files = [f for f in os.listdir(LOG_DIR) if f.endswith(".pcap")]
    files.sort(reverse=True)
    if not files:
        print(f"{YELLOW}No PCAP files found.{RESET}"); pause(); return None
    for i, name in enumerate(files[:20], 1):
        size = os.path.getsize(os.path.join(LOG_DIR, name)) / (1024 * 1024)
        print(f"{CYAN}{i}.{RESET} {WHITE}{name}{RESET} {YELLOW}{size:.1f} MB{RESET}")
    print(f"{CYAN}0.{RESET} Back")
    choice = input(f"\n{YELLOW}Select PCAP:{RESET} ").strip()
    if choice == "0" or not choice.isdigit(): return None
    idx = int(choice) - 1
    if idx < 0 or idx >= len(files[:20]): return None
    return os.path.join(LOG_DIR, files[idx])

def pcap_forensics():
    clear(); banner()
    if not tshark_exists():
        print(f"{RED}TShark is not installed.{RESET}")
        print(f"{YELLOW}Install it with: apt install tshark -y{RESET}")
        pause(); return
    print(f"{WHITE}{BOLD}PCAP Forensics / Attack Fingerprint:{RESET}\n")
    pcap = choose_pcap()
    if not pcap: return
    sample = input(f"\n{YELLOW}Packets to sample [50000]:{RESET} ").strip()
    sample = int(sample) if sample.isdigit() else 50000

    clear(); banner()
    print(f"{WHITE}{BOLD}Analyzing PCAP:{RESET}")
    print(f"{YELLOW}{pcap}{RESET}")
    print(f"{CYAN}Sample size:{RESET} {YELLOW}{sample} packets{RESET}\n")

    def sh(cmd):
        return subprocess.run(cmd, shell=True, text=True, capture_output=True).stdout.strip()

    top_ips = sh(f"tshark -r '{pcap}' -c {sample} -T fields -e ip.src | sort | uniq -c | sort -nr | head -20")
    unique_ips = sh(f"tshark -r '{pcap}' -c {sample} -T fields -e ip.src | sort -u | wc -l")
    top_dst_ports = sh(f"tshark -r '{pcap}' -c {sample} -T fields -e udp.dstport -e tcp.dstport | sort | uniq -c | sort -nr | head -20")
    proto_nums = sh(f"tshark -r '{pcap}' -c {sample} -T fields -e ip.proto | sort | uniq -c | sort -nr")
    udp_lengths = sh(f"tshark -r '{pcap}' -c {sample} -Y udp -T fields -e udp.length | sort | uniq -c | sort -nr | head -20")

    try: unique_count = int(unique_ips.strip())
    except Exception: unique_count = 0

    score = 0
    if "17" in proto_nums: score += 30
    if "6672" in top_dst_ports: score += 30
    if unique_count >= 100: score += 25
    elif unique_count >= 30: score += 15
    if " 1" in udp_lengths or " 9" in udp_lengths: score += 10

    verdict, color = ("LIKELY GTA UDP BOOTER / BOTNET FLOOD", RED) if score >= 75 else (("SUSPICIOUS UDP FLOOD", YELLOW) if score >= 50 else ("LOW / UNCLEAR", GREEN))

    print(f"{WHITE}{BOLD}Attack Fingerprint:{RESET}\n")
    print(f"{CYAN}Verdict:{RESET}       {color}{BOLD}{verdict}{RESET}")
    print(f"{CYAN}Score:{RESET}         {YELLOW}{score}/100{RESET}")
    print(f"{CYAN}Unique IPs:{RESET}    {YELLOW}{unique_count}{RESET}")
    print(f"\n{WHITE}{BOLD}Protocol Numbers:{RESET}\n{YELLOW}{proto_nums or 'N/A'}{RESET}")
    print(f"\n{WHITE}{BOLD}Top Source IPs:{RESET}\n{YELLOW}{top_ips or 'N/A'}{RESET}")
    print(f"\n{WHITE}{BOLD}Top Destination Ports:{RESET}\n{YELLOW}{top_dst_ports or 'N/A'}{RESET}")
    print(f"\n{WHITE}{BOLD}Top UDP Packet Lengths:{RESET}\n{YELLOW}{udp_lengths or 'N/A'}{RESET}")
    pause()

def system_security_check():
    clear(); banner()
    print(f"{WHITE}{BOLD}System Security Check:{RESET}\n")
    score = 0; findings = []
    listening = shell("ss -tulnp")
    established = shell("ss -tupn state established")
    processes = shell("ps aux --sort=-%cpu | head -20")
    tmp_exec = shell("find /tmp /var/tmp /dev/shm -type f -perm /111 2>/dev/null | head -10")

    suspicious_ports = ["4444", "5555", "1337", "31337", "6667", "9001", "12345"]
    suspicious_words = ["xmrig", "miner", "kdevtmpfsi", "kinsing", "mirai", "bash -i", "netcat"]
    for port in suspicious_ports:
        if f":{port}" in listening:
            score += 25; findings.append(f"Suspicious listening port: {port}")
    combined = (listening + "\n" + processes).lower()
    for word in suspicious_words:
        if word in combined:
            score += 20; findings.append(f"Suspicious keyword/process: {word}")
    if tmp_exec:
        score += 10; findings.append("Executable files found in tmp/shm")
    if "openvpn" not in listening.lower():
        score += 15; findings.append("OpenVPN not detected as listening")

    established_rows = [x for x in established.splitlines() if x.strip() and not x.startswith("Netid")]
    external = []
    for line in established_rows:
        parts = line.split()
        if len(parts) >= 5:
            peer_ip = parts[4].rsplit(":", 1)[0].strip("[]")
            if not peer_ip.startswith(("127.", "10.", "192.168.", "169.254.")):
                external.append(line)
    if len(external) > 5:
        score += 20; findings.append(f"Multiple external established connections: {len(external)}")

    status = f"{RED}{BOLD}SUSPICIOUS{RESET}" if score >= 50 else (f"{YELLOW}{BOLD}NEEDS REVIEW{RESET}" if score >= 20 else f"{GREEN}{BOLD}CLEAN{RESET}")
    print(f"{CYAN}System Status:{RESET} {status}")
    print(f"{CYAN}Risk Score:{RESET}    {YELLOW}{score}/100{RESET}\n")

    if findings:
        print(f"{WHITE}{BOLD}Findings:{RESET}")
        for item in findings: print(f"{YELLOW}- {item}{RESET}")
    else:
        print(f"{GREEN}No obvious malware/RAT indicators found.{RESET}")

    print(f"\n{WHITE}{BOLD}Important Listening Services:{RESET}")
    for line in listening.splitlines():
        lower = line.lower()
        if "openvpn" in lower or ":9981" in line or "sshd" in lower or ":22" in line:
            print(f"{CYAN}- {' '.join(line.split())[:150]}{RESET}")

    print(f"\n{WHITE}{BOLD}Established Connections:{RESET}")
    if established_rows:
        for line in established_rows[:12]:
            parts = line.split()
            proto = parts[0] if len(parts) > 0 else "?"
            local = parts[3] if len(parts) > 3 else "?"
            peer = parts[4] if len(parts) > 4 else "?"
            proc = " ".join(parts[5:]) if len(parts) > 5 else "?"
            peer_ip = peer.rsplit(":", 1)[0].strip("[]")
            loc = geo_lookup(peer_ip); net = isp_lookup(peer_ip); label = smart_label(peer_ip, loc, net); color = label_color(label)
            print(f"{CYAN}- {proto:<4}{RESET} {WHITE}{local:<24}{RESET} -> {YELLOW}{peer:<24}{RESET}")
            print(f"      {color}{label:<18}{RESET} {CYAN}{loc:<24}{RESET} {WHITE}{net}{RESET}")
            print(f"      {WHITE}{proc[:120]}{RESET}")
    else:
        print(f"{YELLOW}- None{RESET}")

    print(f"\n{WHITE}{BOLD}Top CPU Processes:{RESET}")
    for line in processes.splitlines()[1:8]:
        print(f"{CYAN}- {' '.join(line.split())[:140]}{RESET}")
    pause()

def import_logs_to_db(files, source_label):
    imported = 0
    for name in files:
        data = load_json(os.path.join(LOG_DIR, name))
        if not data:
            continue
        for ip, count in data.get("top_source_ips", []):
            save_ip_to_db(ip, hits=int(count), source=source_label)
            imported += 1
    return imported

def view_ip_database():
    init_ip_db(); clear(); banner()
    conn = sqlite3.connect(DB_FILE); cur = conn.cursor()
    cur.execute("SELECT ip,total_hits,label,geo,network,first_seen,last_seen FROM attacker_ips ORDER BY total_hits DESC LIMIT 500")
    rows = cur.fetchall(); conn.close()
    print(f"{WHITE}{BOLD}IP Database:{RESET}\n")
    if not rows:
        print(f"{YELLOW}No saved IPs yet.{RESET}"); pause(); return
    print(f"{CYAN}{'IP':<18} {'Hits':<8} {'Label':<18} {'Geo':<24} {'Network / ASN'}{RESET}")
    print(f"{GREEN}{'-' * 100}{RESET}")
    for ip, hits, label, geo, network, first_seen, last_seen in rows:
        color = label_color(label or "UNKNOWN")
        print(f"{WHITE}{ip:<18}{RESET} {YELLOW}{hits:<8}{RESET} {color}{(label or 'UNKNOWN'):<18}{RESET} {CYAN}{(geo or 'Unknown'):<24}{RESET} {WHITE}{network or 'Unknown'}{RESET}")
    print(f"\n{GREEN}{'-' * 100}{RESET}")
    print(f"{YELLOW}Showing top 500 saved IPs by total hits.{RESET}")
    pause()

def add_ip_manually():
    clear(); banner()
    print(f"{WHITE}{BOLD}Add IP Manually:{RESET}\n")
    ip = input(f"{YELLOW}IP address:{RESET} ").strip()
    if not ip:
        print(f"{RED}No IP entered.{RESET}"); pause(); return
    notes = input(f"{YELLOW}Notes optional:{RESET} ").strip()
    save_ip_to_db(ip, hits=0, source="manual", notes=notes)
    print(f"\n{GREEN}Saved IP:{RESET} {YELLOW}{ip}{RESET}")
    pause()

def export_ip_database():
    init_ip_db()
    export_file = os.path.join(EXPORT_DIR, f"ip_database_export-{timestamp()}.csv")
    conn = sqlite3.connect(DB_FILE); cur = conn.cursor()
    cur.execute("SELECT ip,label,geo,network,first_seen,last_seen,total_hits,notes,source FROM attacker_ips ORDER BY total_hits DESC")
    rows = cur.fetchall(); conn.close()
    with open(export_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "label", "geo", "network", "first_seen", "last_seen", "total_hits", "notes", "source"])
        writer.writerows(rows)
    clear(); banner()
    print(f"{GREEN}Export complete:{RESET}\n{YELLOW}{export_file}{RESET}")
    pause()

def ip_database_menu():
    while True:
        clear(); banner()
        logs = [
            f for f in os.listdir(LOG_DIR)
            if f.endswith(".json") and (f.startswith("ALERT") or f.startswith("report"))
        ]
        logs.sort(reverse=True)

        alerts = [f for f in logs if f.startswith("ALERT")]
        reports = [f for f in logs if f.startswith("report")]

        print(f"{WHITE}{BOLD}IP Database:{RESET}\n")
        print(f"{CYAN}{BOLD}1.{RESET}  {WHITE}View IP Table{RESET}")
        print(f"{CYAN}{BOLD}2.{RESET}  {WHITE}Import Latest Report / Attack{RESET}")
        print(f"{CYAN}{BOLD}3.{RESET}  {WHITE}Import All Reports + Alerts{RESET}")
        print(f"{CYAN}{BOLD}4.{RESET}  {WHITE}Add IP Manually{RESET}")
        print(f"{CYAN}{BOLD}5.{RESET}  {WHITE}Export CSV{RESET}")
        print(f"{CYAN}{BOLD}0.{RESET}  {WHITE}Back{RESET}")

        print(f"\n{CYAN}Database:{RESET} {YELLOW}{DB_FILE}{RESET}")
        print(f"{CYAN}Reports found:{RESET} {YELLOW}{len(reports)}{RESET}")
        print(f"{CYAN}Alerts found:{RESET}  {YELLOW}{len(alerts)}{RESET}")

        if logs:
            print(f"{CYAN}Latest log:{RESET}   {YELLOW}{logs[0]}{RESET}")

        choice = input(f"\n{YELLOW}Select:{RESET} ").strip()

        if choice == "0":
            return
        elif choice == "1":
            view_ip_database()
        elif choice == "2":
            if logs:
                count = import_logs_to_db([logs[0]], "latest_log")
                print(f"{GREEN}Imported {count} IP entries from:{RESET} {YELLOW}{logs[0]}{RESET}")
                pause()
            else:
                print(f"{YELLOW}No report or alert logs found.{RESET}")
                pause()
        elif choice == "3":
            if logs:
                count = import_logs_to_db(logs, "all_logs")
                print(f"{GREEN}Imported {count} IP entries from {len(logs)} logs.{RESET}")
                pause()
            else:
                print(f"{YELLOW}No report or alert logs found.{RESET}")
                pause()
        elif choice == "4":
            add_ip_manually()
        elif choice == "5":
            export_ip_database()

def main_menu():
    while True:
        clear(); banner()
        status_label = f"{GREEN}[SAFE]{RESET}"
        try:
            latest = load_json(SUMMARY_FILE)
            if latest:
                cls = latest.get("classification", "")
                if cls == "likely_ddos": status_label = f"{RED}[UNDER ATTACK]{RESET}"
                elif cls in ("suspicious_spike", "heavy_normal_or_scan"): status_label = f"{YELLOW}[WATCHING]{RESET}"
        except Exception:
            pass

        print(f"{WHITE}{BOLD}Traffic Intelligence Panel {status_label}{RESET}\n")
        print(f"{CYAN}{BOLD}1.{RESET}  {WHITE}Live Watch Traffic{RESET}")
        print(f"{CYAN}{BOLD}2.{RESET}  {WHITE}View Latest Summary{RESET}")
        print(f"{CYAN}{BOLD}3.{RESET}  {WHITE}View All Reports{RESET}")
        print(f"{CYAN}{BOLD}4.{RESET}  {WHITE}View Alerts Only{RESET}")
        print(f"{CYAN}{BOLD}5.{RESET}  {WHITE}Attack IP Summary{RESET}")
        print(f"{CYAN}{BOLD}6.{RESET}  {WHITE}Clear Logs / PCAPs{RESET}")
        print(f"{CYAN}{BOLD}7.{RESET}  {WHITE}OpenVPN Status{RESET}")
        print(f"{CYAN}{BOLD}8.{RESET}  {WHITE}Restart OpenVPN{RESET}")
        print(f"{CYAN}{BOLD}9.{RESET}  {WHITE}Repair VPN Internet / NAT{RESET}")
        print(f"{CYAN}{BOLD}10.{RESET} {WHITE}PCAP Forensics / Attack Fingerprint{RESET}")
        print(f"{CYAN}{BOLD}11.{RESET} {WHITE}System Security Check{RESET}")
        print(f"{CYAN}{BOLD}12.{RESET} {WHITE}IP Database{RESET}")
        print(f"{CYAN}{BOLD}0.{RESET}  {WHITE}Exit{RESET}")
        print(f"\n{GREEN}{'-' * 46}{RESET}")
        choice = input(f"{YELLOW}Select:{RESET} ").strip()

        if choice == "1": live_watch()
        elif choice == "2": view_latest()
        elif choice == "3": view_log_menu(prefix="report", title="All Reports")
        elif choice == "4": view_log_menu(prefix="ALERT", title="Alerts")
        elif choice == "5": attack_ip_summary()
        elif choice == "6": clear_logs()
        elif choice == "7": openvpn_status()
        elif choice == "8": restart_openvpn()
        elif choice == "9": repair_vpn_nat()
        elif choice == "10": pcap_forensics()
        elif choice == "11": system_security_check()
        elif choice == "12": ip_database_menu()
        elif choice == "0": break
        else:
            print(f"{RED}Invalid option.{RESET}"); pause()

if __name__ == "__main__":
    main_menu()
