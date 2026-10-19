#!/usr/bin/env python3

import socket
import threading
import time
import urllib.request
import ipaddress
import signal
import sys

from dnslib import DNSRecord, QTYPE, RR, A, AAAA


# ============================================================
# CONFIGURATION
# ============================================================

# YOUR OpenVPN tun0 address
LISTEN_IP = "YOUR_LAB_VPN_IP"

# DNS port
LISTEN_PORT = 53

# Only OpenVPN clients from this network are accepted
VPN_NETWORK = ipaddress.ip_network("10.8.0.0/24")

# Upstream DNS servers.
# These are used only after a domain passes the blocklist.
UPSTREAM_SERVERS = [
    ("1.1.1.1", 53),
    ("1.0.0.1", 53),
]

# Public hosts-based ad-blocking list
BLOCKLIST_URL = (
    "https://raw.githubusercontent.com/"
    "StevenBlack/hosts/master/hosts"
)

# Update blocklist every 6 hours
BLOCKLIST_REFRESH = 6 * 60 * 60


# ============================================================
# GLOBAL STATE
# ============================================================

BLOCKED = set()
BLOCKLIST_LOCK = threading.RLock()

running = True


# ============================================================
# BLOCKLIST
# ============================================================

def download_blocklist():
    print("[*] Downloading ad-block list...")

    try:
        request = urllib.request.Request(
            BLOCKLIST_URL,
            headers={
                "User-Agent": "OpenVPN-tun0-DNS-AdBlocker/1.0"
            }
        )

        with urllib.request.urlopen(
            request,
            timeout=30
        ) as response:

            data = response.read().decode(
                "utf-8",
                errors="ignore"
            )

        new_blocked = set()

        for line in data.splitlines():

            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            parts = line.split()

            if len(parts) < 2:
                continue

            address = parts[0].strip()
            domain = parts[1].lower().rstrip(".")

            # Only accept normal hosts-file blocking entries
            if address not in (
                "0.0.0.0",
                "127.0.0.1",
                "::",
            ):
                continue

            # Ignore local/system names
            if domain in (
                "localhost",
                "localhost.localdomain",
                "local",
                "broadcasthost",
            ):
                continue

            if "." not in domain:
                continue

            # Basic domain sanity check
            if len(domain) > 253:
                continue

            new_blocked.add(domain)

        if not new_blocked:
            print(
                "[!] Downloaded blocklist was empty."
                " Keeping previous list."
            )
            return

        with BLOCKLIST_LOCK:
            BLOCKED.clear()
            BLOCKED.update(new_blocked)

        print(
            f"[+] Loaded {len(new_blocked):,} blocked domains"
        )

    except Exception as e:

        print(
            f"[!] Blocklist update failed: {e}"
        )


def blocklist_updater():

    while running:

        try:
            download_blocklist()

        except Exception as e:

            print(
                f"[!] Blocklist updater error: {e}"
            )

        time.sleep(BLOCKLIST_REFRESH)


# ============================================================
# DOMAIN CHECK
# ============================================================

def is_blocked(domain):

    domain = domain.lower().rstrip(".")

    with BLOCKLIST_LOCK:

        # Exact domain
        if domain in BLOCKED:
            return True

        parts = domain.split(".")

        # Check parent domains
        #
        # example:
        #
        # ads.example.com
        #
        # checks:
        # ads.example.com
        # example.com
        #
        for i in range(1, len(parts) - 1):

            parent = ".".join(parts[i:])

            if parent in BLOCKED:
                return True

    return False


# ============================================================
# VPN CLIENT VALIDATION
# ============================================================

def is_vpn_client(address):

    try:

        client_ip = ipaddress.ip_address(
            address
        )

        return client_ip in VPN_NETWORK

    except ValueError:

        return False


# ============================================================
# UPSTREAM DNS
# ============================================================

def forward_dns(data):

    last_error = None

    for upstream in UPSTREAM_SERVERS:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        )

        sock.settimeout(5)

        try:

            sock.sendto(
                data,
                upstream
            )

            response, _ = sock.recvfrom(4096)

            return response

        except Exception as e:

            last_error = e

        finally:

            sock.close()

    raise RuntimeError(
        f"All upstream DNS servers failed: {last_error}"
    )


# ============================================================
# DNS QUERY HANDLER
# ============================================================

def handle_query(
    data,
    client,
    server_socket
):

    client_ip = client[0]

    # --------------------------------------------------------
    # SECURITY:
    #
    # Only accept DNS queries from the OpenVPN subnet.
    # --------------------------------------------------------

    if not is_vpn_client(client_ip):

        print(
            f"[DROP] DNS request from "
            f"non-VPN address {client_ip}"
        )

        return

    try:

        request = DNSRecord.parse(data)

        if not request.questions:
            return

        question = request.questions[0]

        domain = str(
            question.qname
        ).rstrip(".")

        qtype = QTYPE[
            question.qtype
        ]

        # ----------------------------------------------------
        # BLOCK
        # ----------------------------------------------------

        if is_blocked(domain):

            print(
                f"[BLOCK] {domain} "
                f"({qtype}) "
                f"<- {client_ip}"
            )

            reply = request.reply()

            # IPv4 request
            if qtype == "A":

                reply.add_answer(
                    RR(
                        rname=question.qname,
                        rtype=QTYPE.A,
                        rclass=1,
                        ttl=60,
                        rdata=A("0.0.0.0")
                    )
                )

            # IPv6 request
            elif qtype == "AAAA":

                reply.add_answer(
                    RR(
                        rname=question.qname,
                        rtype=QTYPE.AAAA,
                        rclass=1,
                        ttl=60,
                        rdata=AAAA("::")
                    )
                )

            # For other record types, return an empty
            # successful response.
            server_socket.sendto(
                reply.pack(),
                client
            )

            return

        # ----------------------------------------------------
        # ALLOW
        # ----------------------------------------------------

        print(
            f"[ALLOW] {domain} "
            f"({qtype}) "
            f"<- {client_ip}"
        )

        response = forward_dns(data)

        server_socket.sendto(
            response,
            client
        )

    except Exception as e:

        print(
            f"[!] DNS request error "
            f"from {client_ip}: {e}"
        )


# ============================================================
# SIGNAL HANDLING
# ============================================================

def shutdown_handler(
    signum,
    frame
):

    global running

    print()
    print("[*] Shutting down...")

    running = False

    sys.exit(0)


signal.signal(
    signal.SIGTERM,
    shutdown_handler
)

signal.signal(
    signal.SIGINT,
    shutdown_handler
)


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 64)
    print(" OpenVPN tun0 DNS Ad Blocker")
    print("=" * 64)
    print()
    print(
        f"Listen address : {LISTEN_IP}"
    )
    print(
        f"Listen port    : {LISTEN_PORT}"
    )
    print(
        f"VPN network    : {VPN_NETWORK}"
    )
    print(
        "Upstream DNS   : 1.1.1.1 / 1.0.0.1"
    )
    print()
    print(
        "IMPORTANT:"
    )
    print(
        "DNS service is bound ONLY to "
        f"{LISTEN_IP}:{LISTEN_PORT}"
    )
    print(
        "Only clients from "
        f"{VPN_NETWORK} are accepted."
    )
    print()

    # --------------------------------------------------------
    # Download initial blocklist
    # --------------------------------------------------------

    download_blocklist()

    # --------------------------------------------------------
    # Start blocklist updater
    # --------------------------------------------------------

    updater = threading.Thread(
        target=blocklist_updater,
        daemon=True
    )

    updater.start()

    # --------------------------------------------------------
    # Create UDP DNS socket
    # --------------------------------------------------------

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    sock.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    # IMPORTANT:
    #
    # Bind ONLY to tun0's IP.
    #
    # NOT:
    # 0.0.0.0
    #
    # Therefore the service does not listen on the
    # public Internet interface.
    # --------------------------------------------------------

    sock.bind(
        (
            LISTEN_IP,
            LISTEN_PORT
        )
    )

    print(
        f"[+] DNS server started on "
        f"{LISTEN_IP}:{LISTEN_PORT}"
    )

    print(
        "[+] Waiting for OpenVPN clients..."
    )

    print()

    # --------------------------------------------------------
    # DNS server loop
    # --------------------------------------------------------

    while running:

        try:

            data, client = sock.recvfrom(
                4096
            )

            thread = threading.Thread(
                target=handle_query,
                args=(
                    data,
                    client,
                    sock
                ),
                daemon=True
            )

            thread.start()

        except KeyboardInterrupt:

            break

        except Exception as e:

            print(
                f"[!] DNS server error: {e}"
            )

    sock.close()


if __name__ == "__main__":

    main()

