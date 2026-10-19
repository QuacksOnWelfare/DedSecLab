#!/usr/bin/env python3
"""
DEDSEC DNS Ad Blocker - daemon (run as root / systemd)

Binds ONLY to OpenVPN tun address YOUR_LAB_VPN_IP:53.
Accepts queries only from 10.8.0.0/24.

Per-client enable list:
  /opt/secure-scripts/dedsec-labNEW/adblock_state/enabled_clients.json

If a client IP is NOT in the enabled list, queries are forwarded
with no filtering (adblock off for that user).

Custom per-client blocks/allows:
  adblock_state/custom_blocks/<sha256>.json
  adblock_state/custom_allows/<sha256>.json
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import signal
import socket
import sys
import threading
import time
import urllib.request
from pathlib import Path

from dnslib import DNSRecord, QTYPE, RR, A, AAAA

# ============================================================
# CONFIG
# ============================================================

BASE_DIR = Path("/opt/secure-scripts/dedsec-labNEW")
STATE_DIR = BASE_DIR / "adblock_state"
ENABLED_FILE = STATE_DIR / "enabled_clients.json"
CUSTOM_BLOCKS_DIR = STATE_DIR / "custom_blocks"
CUSTOM_ALLOWS_DIR = STATE_DIR / "custom_allows"
STATS_FILE = STATE_DIR / "stats.json"
RECENT_FILE = STATE_DIR / "recent_blocks.json"

LISTEN_IP = "YOUR_LAB_VPN_IP"
LISTEN_PORT = 53
VPN_NETWORK = ipaddress.ip_network("10.8.0.0/24")
SERVER_VPN_IP = "YOUR_LAB_VPN_IP"

UPSTREAM_SERVERS = [
    ("1.1.1.1", 53),
    ("1.0.0.1", 53),
    ("8.8.8.8", 53),
]

# StevenBlack unified hosts (adware + malware) - broad coverage
BLOCKLIST_URLS = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    # Optional extra tracking list (safe hosts format)
    "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
]

BLOCKLIST_REFRESH = 6 * 60 * 60
STATE_RELOAD = 5  # seconds - pick up enable/disable + custom rules
RECENT_MAX = 200

# ============================================================
# GLOBALS
# ============================================================

BLOCKED: set[str] = set()
BLOCKLIST_LOCK = threading.RLock()

ENABLED_CLIENTS: set[str] = set()
CUSTOM_BLOCKS: dict[str, set[str]] = {}  # client_ip -> domains
CUSTOM_ALLOWS: dict[str, set[str]] = {}
STATE_LOCK = threading.RLock()

STATS = {
    "blocked": 0,
    "allowed": 0,
    "dropped": 0,
    "started": time.time(),
}
RECENT: list[dict] = []
STATS_LOCK = threading.RLock()

running = True


def client_hash(vpn_ip: str) -> str:
    return hashlib.sha256(vpn_ip.encode("utf-8")).hexdigest()[:32]


def ensure_dirs() -> None:
    for d in (STATE_DIR, CUSTOM_BLOCKS_DIR, CUSTOM_ALLOWS_DIR):
        d.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(d, 0o770)
        except PermissionError:
            pass


# ============================================================
# STATE LOAD
# ============================================================

def load_enabled() -> None:
    global ENABLED_CLIENTS
    try:
        if ENABLED_FILE.exists():
            data = json.loads(ENABLED_FILE.read_text(encoding="utf-8"))
            clients = set()
            if isinstance(data, dict):
                clients = set(data.get("clients") or [])
            elif isinstance(data, list):
                clients = set(data)
            clients = {c for c in clients if _valid_client_ip(c)}
            with STATE_LOCK:
                ENABLED_CLIENTS = clients
        else:
            with STATE_LOCK:
                ENABLED_CLIENTS = set()
    except Exception as e:
        print(f"[!] load_enabled: {e}")


def load_custom_for_all() -> None:
    blocks: dict[str, set[str]] = {}
    allows: dict[str, set[str]] = {}
    # We store by hash; map back via enabled list + scan is awkward.
    # Files are named by hash; menu also writes parallel index.
    index_file = STATE_DIR / "client_index.json"
    ip_by_hash: dict[str, str] = {}
    try:
        if index_file.exists():
            ip_by_hash = json.loads(index_file.read_text(encoding="utf-8"))
    except Exception:
        ip_by_hash = {}

    for path in CUSTOM_BLOCKS_DIR.glob("*.json"):
        h = path.stem
        ip = ip_by_hash.get(h)
        if not ip:
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            domains = set(x.lower().rstrip(".") for x in (data.get("domains") or []) if x)
            blocks[ip] = domains
        except Exception:
            pass

    for path in CUSTOM_ALLOWS_DIR.glob("*.json"):
        h = path.stem
        ip = ip_by_hash.get(h)
        if not ip:
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            domains = set(x.lower().rstrip(".") for x in (data.get("domains") or []) if x)
            allows[ip] = domains
        except Exception:
            pass

    with STATE_LOCK:
        CUSTOM_BLOCKS.clear()
        CUSTOM_BLOCKS.update(blocks)
        CUSTOM_ALLOWS.clear()
        CUSTOM_ALLOWS.update(allows)


def state_reloader() -> None:
    while running:
        try:
            load_enabled()
            load_custom_for_all()
            _persist_stats()
        except Exception as e:
            print(f"[!] state reload: {e}")
        time.sleep(STATE_RELOAD)


def _valid_client_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        if addr not in VPN_NETWORK:
            return False
        if str(addr) == SERVER_VPN_IP:
            return False
        return True
    except ValueError:
        return False


def _persist_stats() -> None:
    try:
        with STATS_LOCK:
            payload = {
                **STATS,
                "blocklist_size": len(BLOCKED),
                "enabled_clients": sorted(ENABLED_CLIENTS),
                "uptime_sec": int(time.time() - STATS["started"]),
            }
            recent = list(RECENT[-RECENT_MAX:])
        STATS_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        RECENT_FILE.write_text(json.dumps(recent, indent=2), encoding="utf-8")
    except Exception:
        pass


# ============================================================
# BLOCKLIST
# ============================================================

def _parse_hosts_text(data: str) -> set[str]:
    new_blocked: set[str] = set()
    for line in data.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        address = parts[0].strip()
        domain = parts[1].lower().rstrip(".")
        if address not in ("0.0.0.0", "127.0.0.1", "::"):
            continue
        if domain in (
            "localhost",
            "localhost.localdomain",
            "local",
            "broadcasthost",
        ):
            continue
        if "." not in domain or len(domain) > 253:
            continue
        new_blocked.add(domain)
    return new_blocked


def download_blocklist() -> None:
    print("[*] Downloading ad-block lists...")
    combined: set[str] = set()
    for url in BLOCKLIST_URLS:
        try:
            request = urllib.request.Request(
                url,
                headers={"User-Agent": "DEDSEC-DNS-AdBlock/2.0"},
            )
            with urllib.request.urlopen(request, timeout=45) as response:
                data = response.read().decode("utf-8", errors="ignore")
            part = _parse_hosts_text(data)
            print(f"[+] {url.split('/')[-1]}: {len(part):,} domains")
            combined |= part
        except Exception as e:
            print(f"[!] Failed {url}: {e}")

    if not combined:
        print("[!] Downloaded blocklist empty - keeping previous.")
        return

    with BLOCKLIST_LOCK:
        BLOCKED.clear()
        BLOCKED.update(combined)
    print(f"[+] Total blocked domains: {len(combined):,}")


def blocklist_updater() -> None:
    while running:
        try:
            download_blocklist()
        except Exception as e:
            print(f"[!] Blocklist updater: {e}")
        time.sleep(BLOCKLIST_REFRESH)


def is_blocked_domain(domain: str, client_ip: str) -> bool:
    domain = domain.lower().rstrip(".")

    with STATE_LOCK:
        allows = CUSTOM_ALLOWS.get(client_ip) or set()
        customs = CUSTOM_BLOCKS.get(client_ip) or set()

    # Whitelist wins
    if _domain_match(domain, allows):
        return False
    if _domain_match(domain, customs):
        return True

    with BLOCKLIST_LOCK:
        return _domain_match(domain, BLOCKED)


def _domain_match(domain: str, blocked: set[str]) -> bool:
    if domain in blocked:
        return True
    parts = domain.split(".")
    for i in range(1, len(parts) - 1):
        parent = ".".join(parts[i:])
        if parent in blocked:
            return True
    return False


# ============================================================
# DNS
# ============================================================

def is_vpn_client(address: str) -> bool:
    try:
        return ipaddress.ip_address(address) in VPN_NETWORK
    except ValueError:
        return False


def client_adblock_on(client_ip: str) -> bool:
    with STATE_LOCK:
        return client_ip in ENABLED_CLIENTS


def forward_dns(data: bytes) -> bytes:
    last_error = None
    for upstream in UPSTREAM_SERVERS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(4)
        try:
            sock.sendto(data, upstream)
            response, _ = sock.recvfrom(4096)
            return response
        except Exception as e:
            last_error = e
        finally:
            sock.close()
    raise RuntimeError(f"All upstream DNS failed: {last_error}")


def handle_query(data: bytes, client: tuple, server_socket: socket.socket) -> None:
    client_ip = client[0]

    if not is_vpn_client(client_ip) or client_ip == SERVER_VPN_IP:
        with STATS_LOCK:
            STATS["dropped"] += 1
        return

    try:
        request = DNSRecord.parse(data)
        if not request.questions:
            return

        question = request.questions[0]
        domain = str(question.qname).rstrip(".")
        qtype = QTYPE[question.qtype]

        # Adblock only if this client enabled it
        if client_adblock_on(client_ip) and is_blocked_domain(domain, client_ip):
            with STATS_LOCK:
                STATS["blocked"] += 1
                RECENT.append(
                    {
                        "ts": time.time(),
                        "client": client_ip,
                        "domain": domain,
                        "qtype": qtype,
                    }
                )
                if len(RECENT) > RECENT_MAX * 2:
                    del RECENT[: len(RECENT) - RECENT_MAX]

            print(f"[BLOCK] {domain} ({qtype}) <- {client_ip}")
            reply = request.reply()
            if qtype == "A":
                reply.add_answer(
                    RR(
                        rname=question.qname,
                        rtype=QTYPE.A,
                        rclass=1,
                        ttl=60,
                        rdata=A("0.0.0.0"),
                    )
                )
            elif qtype == "AAAA":
                reply.add_answer(
                    RR(
                        rname=question.qname,
                        rtype=QTYPE.AAAA,
                        rclass=1,
                        ttl=60,
                        rdata=AAAA("::"),
                    )
                )
            server_socket.sendto(reply.pack(), client)
            return

        # Allow / forward
        with STATS_LOCK:
            STATS["allowed"] += 1
        response = forward_dns(data)
        server_socket.sendto(response, client)

    except Exception as e:
        print(f"[!] DNS error from {client_ip}: {e}")


def shutdown_handler(signum, frame) -> None:
    global running
    print("\n[*] Shutting down...")
    running = False


# ============================================================
# MAIN
# ============================================================

def main() -> None:
    global running

    if os.geteuid() != 0:
        print("[!] Daemon must run as root (bind port 53).")
        sys.exit(1)

    ensure_dirs()
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    print()
    print("=" * 64)
    print(" DEDSEC OpenVPN DNS Ad Blocker (daemon)")
    print("=" * 64)
    print(f"Listen     : {LISTEN_IP}:{LISTEN_PORT}")
    print(f"VPN net    : {VPN_NETWORK}")
    print(f"State dir  : {STATE_DIR}")
    print()

    download_blocklist()
    load_enabled()
    load_custom_for_all()

    threading.Thread(target=blocklist_updater, daemon=True).start()
    threading.Thread(target=state_reloader, daemon=True).start()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((LISTEN_IP, LISTEN_PORT))
    except OSError as e:
        print(f"[!] Bind failed {LISTEN_IP}:{LISTEN_PORT}: {e}")
        print("    Is another DNS service using this address?")
        sys.exit(1)

    print(f"[+] DNS server on {LISTEN_IP}:{LISTEN_PORT}")
    print("[+] Per-client enable via menu (enabled_clients.json)")
    print()

    while running:
        try:
            sock.settimeout(1.0)
            try:
                data, client = sock.recvfrom(4096)
            except socket.timeout:
                continue
            threading.Thread(
                target=handle_query,
                args=(data, client, sock),
                daemon=True,
            ).start()
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[!] Server loop: {e}")

    sock.close()
    _persist_stats()
    print("[*] Stopped.")


if __name__ == "__main__":
    main()
