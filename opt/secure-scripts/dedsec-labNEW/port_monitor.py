#!/usr/bin/env python3

import os
import sys
import time
import signal
import socket
import subprocess
import threading
import json
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

import requests

try:
    from scapy.all import sniff, IP, TCP, UDP
except ImportError:
    print("[!] Scapy is not installed.")
    print("[!] Install with:")
    print("    sudo apt install python3-scapy python3-requests")
    sys.exit(1)


# ============================================================
# CONFIGURATION
# ============================================================

WEBHOOK_URL = "https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN"

# None = automatically select the default interface
INTERFACE = None

# ------------------------------------------------------------
# Detection
# ------------------------------------------------------------

# Number of UNIQUE ports required inside the detection window.
TCP_PORT_THRESHOLD = 15
TCP_PROBE_THRESHOLD = 10
UDP_PORT_THRESHOLD = 20

# Detection window in seconds.
DETECTION_WINDOW = 20

# How long an alerted incident must be quiet before resolving.
RESOLVE_AFTER = 30

# Maximum number of ports displayed in Discord.
MAX_DISPLAY_PORTS = 50

# ------------------------------------------------------------
# UDP response tracking
# ------------------------------------------------------------

# Remember outbound UDP flows for this many seconds.
UDP_FLOW_TIMEOUT = 30

# ------------------------------------------------------------
# Ignore list
# ------------------------------------------------------------

WHITELIST = {
    # "1.2.3.4",
}


# ============================================================
# FILES
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

PID_FILE = os.path.join(
    BASE_DIR,
    "port_monitor.pid"
)

OUTPUT_LOG = os.path.join(
    BASE_DIR,
    "port_monitor.out"
)

SCAN_LOG = os.path.join(
    BASE_DIR,
    "port_scan.log"
)

SERVICE_NAME = "port-monitor.service"

SERVICE_PATH = (
    f"/etc/systemd/system/{SERVICE_NAME}"
)


# ============================================================
# BANNER
# ============================================================

BANNER = r"""
██████╗ ███████╗██████╗ ███████╗███████╗ ██████╗
██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝
██║  ██║█████╗  ██║  ██║███████╗█████╗  ██║
██║  ██║██╔══╝  ██║  ██║╚════██║██╔══╝  ██║
██████╔╝███████╗██████╔╝███████║███████╗╚██████╗
╚═════╝ ╚══════╝╚═════╝ ╚══════╝╚══════╝ ╚═════╝

Secure Terminal Access Launcher
════════════════════════════════════════════════════════
"""


# ============================================================
# GLOBAL STATE
# ============================================================

running = True

lock = threading.Lock()

incidents = {}

# Outbound UDP flows:
#
# key =
# (
#   local_ip,
#   local_port,
#   remote_ip,
#   remote_port
# )
#
# value = timestamp

udp_outbound_flows = {}

# Global inbound TCP probe timestamps.
# Used to detect distributed scanning across multiple source IPs.
tcp_global_probe_times = []

# IP addresses assigned to this VPS.
LOCAL_IPS = set()


# ============================================================
# TERMINAL
# ============================================================

def clear_screen():
    os.system(
        "clear"
        if os.name != "nt"
        else "cls"
    )


def pause():
    input(
        "\nPress ENTER to return to the menu..."
    )


def banner():
    print(BANNER)


# ============================================================
# TIME
# ============================================================

def utc_now():
    return datetime.now(timezone.utc)


def utc_string():
    return utc_now().strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


def duration_string(seconds):

    seconds = int(seconds)

    days, seconds = divmod(
        seconds,
        86400
    )

    hours, seconds = divmod(
        seconds,
        3600
    )

    minutes, seconds = divmod(
        seconds,
        60
    )

    parts = []

    if days:
        parts.append(
            f"{days}d"
        )

    if hours:
        parts.append(
            f"{hours}h"
        )

    if minutes:
        parts.append(
            f"{minutes}m"
        )

    parts.append(
        f"{seconds}s"
    )

    return " ".join(parts)


# ============================================================
# LOCAL IP DETECTION
# ============================================================

def get_local_ips():

    addresses = {
        "127.0.0.1",
        "::1"
    }

    # Hostname addresses
    try:

        hostname = socket.gethostname()

        _, _, host_addresses = (
            socket.gethostbyname_ex(hostname)
        )

        addresses.update(
            host_addresses
        )

    except Exception:
        pass

    # Interface addresses
    try:

        result = subprocess.run(
            [
                "ip",
                "-o",
                "addr",
                "show"
            ],
            capture_output=True,
            text=True,
            check=False
        )

        for line in result.stdout.splitlines():

            parts = line.split()

            if "inet" in parts:

                index = parts.index(
                    "inet"
                )

                if index + 1 < len(parts):

                    address = (
                        parts[index + 1]
                        .split("/")[0]
                    )

                    addresses.add(
                        address
                    )

            if "inet6" in parts:

                index = parts.index(
                    "inet6"
                )

                if index + 1 < len(parts):

                    address = (
                        parts[index + 1]
                        .split("/")[0]
                    )

                    addresses.add(
                        address
                    )

    except Exception:
        pass

    return addresses


def refresh_local_ips():

    global LOCAL_IPS

    LOCAL_IPS = get_local_ips()

    print(
        "[*] Local IP addresses:",
        flush=True
    )

    for address in sorted(LOCAL_IPS):

        print(
            f"    {address}",
            flush=True
        )


def is_local_ip(ip):

    return ip in LOCAL_IPS


# ============================================================
# PID MANAGEMENT
# ============================================================

def read_pid():

    if not os.path.exists(PID_FILE):
        return None

    try:

        with open(
            PID_FILE,
            "r"
        ) as f:

            return int(
                f.read().strip()
            )

    except Exception:

        return None


def write_pid():

    with open(
        PID_FILE,
        "w"
    ) as f:

        f.write(
            str(os.getpid())
        )


def remove_pid():

    try:

        if os.path.exists(
            PID_FILE
        ):

            current_pid = read_pid()

            # Don't remove another monitor's PID file.
            if (
                current_pid is None
                or current_pid == os.getpid()
            ):

                os.remove(
                    PID_FILE
                )

    except Exception:

        pass


def process_exists(pid):

    if not pid:
        return False

    try:

        os.kill(
            pid,
            0
        )

        return True

    except ProcessLookupError:

        return False

    except PermissionError:

        return True

    except Exception:

        return False


def monitor_running():

    pid = read_pid()

    if (
        pid
        and process_exists(pid)
    ):

        return True, pid

    if pid:
        remove_pid()

    return False, None


# ============================================================
# LOGGING
# ============================================================

def write_scan_log(data):

    try:

        with open(
            SCAN_LOG,
            "a"
        ) as f:

            f.write(
                json.dumps(
                    data,
                    separators=(
                        ",",
                        ":"
                    )
                )
                + "\n"
            )

    except Exception as e:

        print(
            f"[!] Log error: {e}",
            flush=True
        )


# ============================================================
# UDP FLOW TRACKING
# ============================================================

def cleanup_udp_flows():

    now = time.time()

    for key in list(
        udp_outbound_flows.keys()
    ):

        if (
            now
            - udp_outbound_flows[key]
            > UDP_FLOW_TIMEOUT
        ):

            del udp_outbound_flows[key]


def remember_udp_outbound(
    source_ip,
    source_port,
    destination_ip,
    destination_port
):

    key = (
        source_ip,
        source_port,
        destination_ip,
        destination_port
    )

    udp_outbound_flows[key] = time.time()


def is_udp_response(
    source_ip,
    source_port,
    destination_ip,
    destination_port
):

    # If VPS previously sent:
    #
    # VPS:12345 -> remote:53
    #
    # then:
    #
    # remote:53 -> VPS:12345
    #
    # is probably a response.

    reverse_key = (
        destination_ip,
        destination_port,
        source_ip,
        source_port
    )

    return (
        reverse_key
        in udp_outbound_flows
    )


# ============================================================
# GLOBAL TCP PROBE TRACKING
# ============================================================

def record_global_tcp_probe():
    now = time.time()

    tcp_global_probe_times.append(now)

    cutoff = now - DETECTION_WINDOW

    while (
        tcp_global_probe_times
        and tcp_global_probe_times[0] < cutoff
    ):
        tcp_global_probe_times.pop(0)

    return len(tcp_global_probe_times)


# ============================================================
# INCIDENT MANAGEMENT
# ============================================================

def incident_key(
    source_ip,
    target_ip,
    protocol
):

    return (
        f"{source_ip}:"
        f"{target_ip}:"
        f"{protocol}"
    )


def get_incident(
    source_ip,
    target_ip,
    protocol
):

    key = incident_key(
        source_ip,
        target_ip,
        protocol
    )

    if key not in incidents:

        incidents[key] = {

            "source_ip": source_ip,

            "target_ip": target_ip,

            "protocol": protocol,

            "started": utc_now(),

            "last_seen": utc_now(),

            "tcp_ports": set(),

            "udp_ports": set(),

            "recent_ports": {},

            "total_probes": 0,

            "alerted": False,

            "discord_message_id": None
        }

    return key, incidents[key]


def copy_incident(
    incident
):

    copied = dict(
        incident
    )

    copied["tcp_ports"] = set(
        incident["tcp_ports"]
    )

    copied["udp_ports"] = set(
        incident["udp_ports"]
    )

    copied["recent_ports"] = dict(
        incident["recent_ports"]
    )

    copied["probe_times"] = list(
        incident.get("probe_times", [])
    )

    return copied


# ============================================================
# SCAN ANALYSIS
# ============================================================

def prune_recent_ports(
    incident
):

    now = time.time()

    for port in list(
        incident["recent_ports"].keys()
    ):

        if (
            now
            - incident["recent_ports"][port]
            > DETECTION_WINDOW
        ):

            del incident[
                "recent_ports"
            ][port]


def sequential_score(
    ports
):

    if len(ports) < 3:
        return 0

    ordered = sorted(
        ports
    )

    sequential = 0

    for i in range(
        1,
        len(ordered)
    ):

        if (
            ordered[i]
            == ordered[i - 1] + 1
        ):

            sequential += 1

    return sequential


def scan_confidence(
    incident
):

    if incident["protocol"] == "TCP":

        ports = incident[
            "tcp_ports"
        ]

        threshold = TCP_PORT_THRESHOLD

    else:

        ports = incident[
            "udp_ports"
        ]

        threshold = UDP_PORT_THRESHOLD

    count = len(
        ports
    )

    if count >= threshold * 2:
        return "HIGH"

    if count >= threshold:
        return "MEDIUM"

    return "LOW"


# ============================================================
# DISCORD
# ============================================================

def discord_request(
    method,
    url,
    payload
):

    try:

        response = requests.request(
            method,
            url,
            json=payload,
            timeout=10
        )

        if response.status_code not in (
            200,
            204
        ):

            print(
                f"[!] Discord HTTP "
                f"{response.status_code}",
                flush=True
            )

            if response.text:

                print(
                    f"[!] Discord response: "
                    f"{response.text[:500]}",
                    flush=True
                )

            return None

        if response.text:

            try:

                return response.json()

            except ValueError:

                return None

        return None

    except Exception as e:

        print(
            f"[!] Discord error: {e}",
            flush=True
        )

        return None


def webhook_base_url():

    if not WEBHOOK_URL:
        return ""

    parts = urlsplit(
        WEBHOOK_URL
    )

    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path,
            "",
            ""
        )
    )


def format_ports(
    ports
):

    ports = sorted(
        ports
    )

    if not ports:
        return "None"

    if len(ports) <= MAX_DISPLAY_PORTS:

        return ", ".join(
            str(port)
            for port in ports
        )

    return (
        ", ".join(
            str(port)
            for port in ports[
                :MAX_DISPLAY_PORTS
            ]
        )
        + f" ... (+"
        + str(
            len(ports)
            - MAX_DISPLAY_PORTS
        )
        + " more)"
    )


def build_embed(
    incident,
    resolved=False
):

    started = incident[
        "started"
    ]

    last_seen = incident[
        "last_seen"
    ]

    duration = (
        last_seen
        - started
    ).total_seconds()

    confidence = scan_confidence(
        incident
    )

    if resolved:

        title = "Port Scan Resolved"

        description = (
            "No further scan-like "
            "activity has been observed."
        )

        color = 0x2ECC71

    else:

        title = "Port Scan Detected"

        description = (
            "Scan-like network activity "
            "has been detected against "
            "this server."
        )

        color = 0xE67E22

    protocol_text = incident[
        "protocol"
    ]

    unique_ports = (
        len(incident["tcp_ports"])
        + len(incident["udp_ports"])
    )

    return {

        "title": title,

        "description": description,

        "color": color,

        "fields": [

            {
                "name": "Server",
                "value": "`VPS`",
                "inline": True
            },

            {
                "name": "Affected IP",
                "value": (
                    f"`{incident['target_ip']}`"
                ),
                "inline": True
            },

            {
                "name": "Protocol",
                "value": (
                    f"`{protocol_text}`"
                ),
                "inline": True
            },

            {
                "name": "Source IP",
                "value": (
                    f"`{incident['source_ip']}`"
                ),
                "inline": False
            },

            {
                "name": "Confidence",
                "value": (
                    f"`{confidence}`"
                ),
                "inline": True
            },

            {
                "name": "Time Started",
                "value": (
                    f"`{started.strftime('%Y-%m-%d %H:%M:%S UTC')}`"
                ),
                "inline": True
            },

            {
                "name": (
                    "Time Ended"
                    if resolved
                    else "Last Activity"
                ),
                "value": (
                    f"`{last_seen.strftime('%Y-%m-%d %H:%M:%S UTC')}`"
                ),
                "inline": True
            },

            {
                "name": "Duration",
                "value": (
                    f"`{duration_string(duration)}`"
                ),
                "inline": True
            },

            {
                "name": "TCP Ports",
                "value": (
                    f"`{format_ports(incident['tcp_ports'])}`"
                ),
                "inline": False
            },

            {
                "name": "UDP Ports",
                "value": (
                    f"`{format_ports(incident['udp_ports'])}`"
                ),
                "inline": False
            },

            {
                "name": "Unique Ports",
                "value": (
                    f"`{unique_ports}`"
                ),
                "inline": True
            },

            {
                "name": "Total Probes",
                "value": (
                    f"`{incident['total_probes']}`"
                ),
                "inline": True
            }
        ],

        "footer": {
            "text": "PORT MONITOR"
        },

        "timestamp": utc_now().isoformat()
    }


def create_discord_message(
    incident
):

    if (
        not WEBHOOK_URL
        or WEBHOOK_URL.startswith(
            "YOUR_"
        )
    ):

        print(
            "[!] Discord webhook "
            "is not configured.",
            flush=True
        )

        return None

    payload = {

        "embeds": [
            build_embed(
                incident,
                resolved=False
            )
        ]
    }

    url = WEBHOOK_URL

    if "?" in url:
        url += "&wait=true"
    else:
        url += "?wait=true"

    result = discord_request(
        "POST",
        url,
        payload
    )

    if result:

        return result.get(
            "id"
        )

    return None


def update_discord_message(
    incident
):

    message_id = incident.get(
        "discord_message_id"
    )

    if not message_id:
        return

    if (
        not WEBHOOK_URL
        or WEBHOOK_URL.startswith(
            "YOUR_"
        )
    ):
        return

    payload = {

        "embeds": [
            build_embed(
                incident,
                resolved=True
            )
        ]
    }

    base_url = webhook_base_url()

    url = (
        base_url
        + "/messages/"
        + str(message_id)
    )

    discord_request(
        "PATCH",
        url,
        payload
    )


def send_test_webhook():

    if (
        not WEBHOOK_URL
        or WEBHOOK_URL.startswith(
            "YOUR_"
        )
    ):

        print(
            "[!] Configure WEBHOOK_URL first."
        )

        return False

    embed = {

        "title": "Port Monitor Test",

        "description": (
            "The VPS port-monitor "
            "Discord webhook is working."
        ),

        "color": 0x3498DB,

        "fields": [

            {
                "name": "Status",
                "value": "`ONLINE`",
                "inline": True
            },

            {
                "name": "Time",
                "value": (
                    f"`{utc_string()}`"
                ),
                "inline": True
            }

        ],

        "footer": {
            "text": "PORT MONITOR"
        }
    }

    result = discord_request(
        "POST",
        WEBHOOK_URL,
        {
            "embeds": [embed]
        }
    )

    return result is not None


# ============================================================
# PACKET PROCESSING
# ============================================================

def process_packet(
    packet
):

    if not packet.haslayer(
        IP
    ):
        return

    source_ip = packet[
        IP
    ].src

    target_ip = packet[
        IP
    ].dst

    now = time.time()

    with lock:

        cleanup_udp_flows()

        # ----------------------------------------------------
        # TCP
        # ----------------------------------------------------

        if packet.haslayer(
            TCP
        ):

            tcp = packet[
                TCP
            ]

            # Only inspect traffic actually destined for
            # an IP assigned to this VPS.
            #
            # This prevents outbound connections created by
            # the VPS from being classified as scans.

            if not is_local_ip(
                target_ip
            ):
                return

            # Incoming TCP SYN without ACK is a possible
            # connection attempt.

            if (
                tcp.flags & 0x02
                and not (
                    tcp.flags & 0x10
                )
            ):

                if source_ip in WHITELIST:
                    return

                # Don't treat traffic originating from one
                # of the VPS's own addresses as an attack.

                if is_local_ip(
                    source_ip
                ):
                    return

                protocol = "TCP"

                destination_port = int(
                    tcp.dport
                )

                key, incident = get_incident(
                    source_ip,
                    target_ip,
                    protocol
                )

                incident[
                    "last_seen"
                ] = utc_now()

                incident[
                    "total_probes"
                ] += 1

                global_tcp_probes = (
                    record_global_tcp_probe()
                )

                incident.setdefault(
                    "probe_times",
                    []
                ).append(now)

                incident["probe_times"] = [
                    t
                    for t in incident["probe_times"]
                    if now - t <= DETECTION_WINDOW
                ]

                incident[
                    "tcp_ports"
                ].add(
                    destination_port
                )

                incident[
                    "recent_ports"
                ][
                    destination_port
                ] = now

                write_scan_log({

                    "timestamp":
                        utc_now().isoformat(),

                    "source_ip":
                        source_ip,

                    "target_ip":
                        target_ip,

                    "protocol":
                        "TCP",

                    "source_port":
                        int(tcp.sport),

                    "destination_port":
                        destination_port
                })

                print(
                    f"[TCP] "
                    f"{source_ip} -> "
                    f"{target_ip}:"
                    f"{destination_port}",
                    flush=True
                )

                prune_recent_ports(
                    incident
                )

                unique_ports = len(
                    incident[
                        "recent_ports"
                    ]
                )

                tcp_probe_trigger = (
                    global_tcp_probes
                    >= TCP_PROBE_THRESHOLD
                )

                tcp_port_trigger = (
                    unique_ports
                    >= TCP_PORT_THRESHOLD
                )

                if (
                    (tcp_port_trigger or tcp_probe_trigger)
                    and not incident[
                        "alerted"
                    ]
                ):

                    incident[
                        "alerted"
                    ] = True

                    print(
                        f"[ALERT] TCP threshold reached: "
                        f"global={global_tcp_probes}, "
                        f"source={source_ip} -> {target_ip}",
                        flush=True
                    )

                    print(
                        f"[ALERT] TCP threshold reached: "
                        f"{source_ip} -> {target_ip} "
                        f"({len(incident.get('probe_times', []))} probes, "
                        f"{unique_ports} unique ports)",
                        flush=True
                    )

                    incident_copy = (
                        copy_incident(
                            incident
                        )
                    )

                    threading.Thread(
                        target=
                        send_detection_alert,

                        args=(
                            key,
                            incident_copy
                        ),

                        daemon=True
                    ).start()

            return

        # ----------------------------------------------------
        # UDP
        # ----------------------------------------------------

        if packet.haslayer(
            UDP
        ):

            udp = packet[
                UDP
            ]

            source_port = int(
                udp.sport
            )

            destination_port = int(
                udp.dport
            )

            # ------------------------------------------------
            # OUTBOUND UDP
            # ------------------------------------------------
            #
            # If the source IP belongs to the VPS, remember
            # this flow and do not treat it as an incoming
            # probe.

            if is_local_ip(
                source_ip
            ):

                remember_udp_outbound(
                    source_ip,
                    source_port,
                    target_ip,
                    destination_port
                )

                return

            # ------------------------------------------------
            # INBOUND UDP
            # ------------------------------------------------

            # Only process packets actually destined for the
            # VPS.

            if not is_local_ip(
                target_ip
            ):
                return

            # If this is a response to a UDP flow initiated
            # by the VPS, don't treat it as a scan.

            if is_udp_response(
                source_ip,
                source_port,
                target_ip,
                destination_port
            ):

                return

            if source_ip in WHITELIST:
                return

            protocol = "UDP"

            key, incident = get_incident(
                source_ip,
                target_ip,
                protocol
            )

            incident[
                "last_seen"
            ] = utc_now()

            incident[
                "total_probes"
            ] += 1

            incident[
                "udp_ports"
            ].add(
                destination_port
            )

            incident[
                "recent_ports"
            ][
                destination_port
            ] = now

            write_scan_log({

                "timestamp":
                    utc_now().isoformat(),

                "source_ip":
                    source_ip,

                "target_ip":
                    target_ip,

                "protocol":
                    "UDP",

                "source_port":
                    source_port,

                "destination_port":
                    destination_port
            })

            print(
                f"[UDP] "
                f"{source_ip} -> "
                f"{target_ip}:"
                f"{destination_port}",
                flush=True
            )

            prune_recent_ports(
                incident
            )

            unique_ports = len(
                incident[
                    "recent_ports"
                ]
            )

            # UDP requires a higher confidence threshold
            # because normal UDP traffic is noisier.

            if (
                unique_ports
                >= UDP_PORT_THRESHOLD
                and not incident[
                    "alerted"
                ]
            ):

                incident[
                    "alerted"
                ] = True

                incident_copy = (
                    copy_incident(
                        incident
                    )
                )

                threading.Thread(
                    target=
                    send_detection_alert,

                    args=(
                        key,
                        incident_copy
                    ),

                    daemon=True
                ).start()


# ============================================================
# ALERT THREAD
# ============================================================

def send_detection_alert(
    key,
    incident_copy
):

    print(
        f"[DISCORD] Sending alert for "
        f"{incident_copy['source_ip']} -> "
        f"{incident_copy['target_ip']}",
        flush=True
    )

    message_id = (
        create_discord_message(
            incident_copy
        )
    )

    if not message_id:
        print(
            "[DISCORD] Alert send failed.",
            flush=True
        )
    else:
        print(
            f"[DISCORD] Alert sent. Message ID: {message_id}",
            flush=True
        )

    if message_id:

        with lock:

            if key in incidents:

                incidents[key][
                    "discord_message_id"
                ] = message_id


# ============================================================
# CLEANUP
# ============================================================

def cleanup_thread():

    global running

    while running:

        time.sleep(5)

        now = utc_now()

        to_resolve = []

        with lock:

            cleanup_udp_flows()

            for key in list(
                incidents.keys()
            ):

                incident = incidents[
                    key
                ]

                quiet_for = (
                    now
                    - incident[
                        "last_seen"
                    ]
                ).total_seconds()

                if (
                    incident[
                        "alerted"
                    ]
                    and
                    quiet_for
                    >= RESOLVE_AFTER
                ):

                    to_resolve.append(
                        copy_incident(
                            incident
                        )
                    )

                    del incidents[
                        key
                    ]

        for incident in to_resolve:

            print(
                "[RESOLVED] "
                + incident[
                    "source_ip"
                ],
                flush=True
            )

            threading.Thread(
                target=
                update_discord_message,

                args=(
                    incident,
                ),

                daemon=True
            ).start()


# ============================================================
# SIGNALS
# ============================================================

def handle_signal(
    signum,
    frame
):

    global running

    running = False

    remove_pid()

    sys.exit(0)


# ============================================================
# MONITOR
# ============================================================

def monitor():

    global running

    running = True

    refresh_local_ips()

    write_pid()

    signal.signal(
        signal.SIGTERM,
        handle_signal
    )

    signal.signal(
        signal.SIGINT,
        handle_signal
    )

    print(
        "==========================================",
        flush=True
    )

    print(
        "       VPS PORT SCAN MONITOR",
        flush=True
    )

    print(
        "==========================================",
        flush=True
    )

    print(
        f"[*] Started: {utc_string()}",
        flush=True
    )

    print(
        f"[*] TCP threshold: "
        f"{TCP_PORT_THRESHOLD} unique ports",
        flush=True
    )

    print(
        f"[*] TCP probe threshold: "
        f"{TCP_PROBE_THRESHOLD} probes",
        flush=True
    )

    print(
        f"[*] UDP threshold: "
        f"{UDP_PORT_THRESHOLD} unique ports",
        flush=True
    )

    print(
        f"[*] Detection window: "
        f"{DETECTION_WINDOW}s",
        flush=True
    )

    print(
        f"[*] Resolve after: "
        f"{RESOLVE_AFTER}s",
        flush=True
    )

    print(
        f"[*] Scan log: "
        f"{SCAN_LOG}",
        flush=True
    )

    cleanup = threading.Thread(
        target=cleanup_thread,
        daemon=True
    )

    cleanup.start()

    try:

        # Capture both directions because outbound UDP
        # traffic is needed for response tracking.

        sniff(
            iface=INTERFACE,

            filter="tcp or udp",

            prn=process_packet,

            store=False
        )

    except Exception as e:

        print(
            f"[!] Monitor error: {e}",
            flush=True
        )

    finally:

        remove_pid()


# ============================================================
# SERVICE MANAGEMENT
# ============================================================

def require_root():

    if os.geteuid() != 0:

        print(
            "[!] Root privileges required."
        )

        print(
            "    sudo ./port_monitor.py"
        )

        return False

    return True


def start_monitor():

    running_status, pid = (
        monitor_running()
    )

    if running_status:

        print(
            f"[!] Already running "
            f"(PID {pid})."
        )

        return

    print(
        "[*] Starting monitor..."
    )

    try:

        with open(
            OUTPUT_LOG,
            "a"
        ) as output:

            subprocess.Popen(

                [
                    sys.executable,
                    os.path.abspath(
                        __file__
                    ),
                    "--monitor"
                ],

                stdin=subprocess.DEVNULL,

                stdout=output,

                stderr=subprocess.STDOUT,

                start_new_session=True
            )

        time.sleep(1)

        running_status, pid = (
            monitor_running()
        )

        if running_status:

            print(
                f"[+] Started "
                f"(PID {pid})."
            )

        else:

            print(
                "[!] Failed to start."
            )

            print(
                f"[!] Check {OUTPUT_LOG}"
            )

    except Exception as e:

        print(
            f"[!] Start error: {e}"
        )


def stop_monitor():

    running_status, pid = (
        monitor_running()
    )

    if not running_status:

        print(
            "[!] Monitor is stopped."
        )

        return

    print(
        f"[*] Stopping PID {pid}..."
    )

    try:

        os.kill(
            pid,
            signal.SIGTERM
        )

        for _ in range(20):

            time.sleep(
                0.25
            )

            if not process_exists(
                pid
            ):

                break

        if process_exists(
            pid
        ):

            print(
                "[!] Failed to stop."
            )

        else:

            remove_pid()

            print(
                "[+] Monitor stopped."
            )

    except Exception as e:

        print(
            f"[!] Stop error: {e}"
        )


def restart_monitor():

    print(
        "[*] Restarting..."
    )

    stop_monitor()

    time.sleep(1)

    start_monitor()


def show_status():

    running_status, pid = (
        monitor_running()
    )

    print()
    print(
        "========== STATUS =========="
    )

    if running_status:

        print(
            "Status: RUNNING"
        )

        print(
            f"PID:    {pid}"
        )

    else:

        print(
            "Status: STOPPED"
        )

    print(
        "Webhook: "
        + (
            "CONFIGURED"
            if WEBHOOK_URL
            and not WEBHOOK_URL.startswith(
                "YOUR_"
            )
            else "NOT CONFIGURED"
        )
    )

    print(
        "Startup: "
        + (
            "ENABLED"
            if os.path.exists(
                SERVICE_PATH
            )
            else "DISABLED"
        )
    )

    print(
        "============================"
    )


# ============================================================
# SYSTEMD
# ============================================================

def install_startup():

    if not require_root():
        return

    script_path = os.path.abspath(
        __file__
    )

    service = f"""[Unit]
Description=VPS Port Scan Monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={sys.executable} {script_path} --monitor
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""

    try:

        with open(
            SERVICE_PATH,
            "w"
        ) as f:

            f.write(
                service
            )

        subprocess.run(
            [
                "systemctl",
                "daemon-reload"
            ],
            check=True
        )

        subprocess.run(
            [
                "systemctl",
                "enable",
                SERVICE_NAME
            ],
            check=True
        )

        print(
            "[+] Startup enabled."
        )

        print(
            "[+] Monitor will start "
            "after reboot."
        )

    except Exception as e:

        print(
            f"[!] Startup error: {e}"
        )


def disable_startup():

    if not require_root():
        return

    try:

        subprocess.run(
            [
                "systemctl",
                "disable",
                SERVICE_NAME
            ],
            check=False
        )

        subprocess.run(
            [
                "systemctl",
                "stop",
                SERVICE_NAME
            ],
            check=False
        )

        if os.path.exists(
            SERVICE_PATH
        ):

            os.remove(
                SERVICE_PATH
            )

        subprocess.run(
            [
                "systemctl",
                "daemon-reload"
            ],
            check=True
        )

        print(
            "[+] Startup disabled."
        )

    except Exception as e:

        print(
            f"[!] Error: {e}"
        )


# ============================================================
# LOG VIEWERS
# ============================================================

def view_output_log():

    if not os.path.exists(
        OUTPUT_LOG
    ):

        print(
            "[!] No output log yet."
        )

        return

    print(
        "[*] Live monitor output."
    )

    print(
        "[*] CTRL+C returns here."
    )

    try:

        subprocess.run(
            [
                "tail",
                "-f",
                OUTPUT_LOG
            ]
        )

    except KeyboardInterrupt:

        pass


def view_scan_log():

    if not os.path.exists(
        SCAN_LOG
    ):

        print(
            "[!] No scan log yet."
        )

        return

    print(
        "[*] Last 50 packets:"
    )

    print(
        "------------------------------------------"
    )

    subprocess.run(
        [
            "tail",
            "-n",
            "50",
            SCAN_LOG
        ]
    )


# ============================================================
# CONFIGURATION
# ============================================================

def show_configuration():

    print()
    print(
        "========== CONFIGURATION =========="
    )

    print(
        f"Interface:          "
        f"{INTERFACE or 'Default'}"
    )

    print(
        f"TCP threshold:      "
        f"{TCP_PORT_THRESHOLD}"
    )

    print(
        f"UDP threshold:      "
        f"{UDP_PORT_THRESHOLD}"
    )

    print(
        f"Detection window:   "
        f"{DETECTION_WINDOW}s"
    )

    print(
        f"Resolve after:      "
        f"{RESOLVE_AFTER}s"
    )

    print(
        f"UDP flow timeout:   "
        f"{UDP_FLOW_TIMEOUT}s"
    )

    print(
        "Webhook:            "
        + (
            "Configured"
            if WEBHOOK_URL
            and not WEBHOOK_URL.startswith(
                "YOUR_"
            )
            else "NOT configured"
        )
    )

    print(
        "Startup:            "
        + (
            "Enabled"
            if os.path.exists(
                SERVICE_PATH
            )
            else "Disabled"
        )
    )

    print(
        "===================================="
    )


# ============================================================
# MENU
# ============================================================

def menu():

    while True:

        clear_screen()

        banner()

        running_status, pid = (
            monitor_running()
        )

        if running_status:

            status = (
                "\033[92m● RUNNING\033[0m "
                f"(PID {pid})"
            )

        else:

            status = (
                "\033[91m● STOPPED\033[0m"
            )

        startup = (
            "\033[92mENABLED\033[0m"
            if os.path.exists(
                SERVICE_PATH
            )
            else "\033[91mDISABLED\033[0m"
        )

        print(
            f"Monitor: {status}"
        )

        print(
            f"Startup: {startup}"
        )

        print()

        print(
            "  [1] Start Monitor"
        )

        print(
            "  [2] Stop Monitor"
        )

        print(
            "  [3] Restart Monitor"
        )

        print(
            "  [4] Monitor Status"
        )

        print(
            "  [5] Run at Startup"
        )

        print(
            "  [6] Disable Startup"
        )

        print(
            "  [7] Test Discord Webhook"
        )

        print(
            "  [8] Live Monitor Log"
        )

        print(
            "  [9] View Scan Log"
        )

        print(
            " [10] Configuration"
        )

        print(
            " [11] Exit"
        )

        print()
        print(
            "════════════════════════════════════════════════════════"
        )

        choice = input(
            " Select an option: "
        ).strip()

        if choice == "1":

            clear_screen()
            banner()

            start_monitor()

            pause()

        elif choice == "2":

            clear_screen()
            banner()

            stop_monitor()

            pause()

        elif choice == "3":

            clear_screen()
            banner()

            restart_monitor()

            pause()

        elif choice == "4":

            clear_screen()
            banner()

            show_status()

            pause()

        elif choice == "5":

            clear_screen()
            banner()

            install_startup()

            pause()

        elif choice == "6":

            clear_screen()
            banner()

            disable_startup()

            pause()

        elif choice == "7":

            clear_screen()
            banner()

            print(
                "[*] Sending Discord test..."
            )

            if send_test_webhook():

                print(
                    "[+] Test sent."
                )

            else:

                print(
                    "[!] Test failed."
                )

            pause()

        elif choice == "8":

            clear_screen()
            banner()

            view_output_log()

        elif choice == "9":

            clear_screen()
            banner()

            view_scan_log()

            pause()

        elif choice == "10":

            clear_screen()
            banner()

            show_configuration()

            pause()

        elif choice == "11":

            clear_screen()

            print(
                "[*] Exiting."
            )

            break

        else:

            print(
                "[!] Invalid option."
            )

            time.sleep(1)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    if (
        len(sys.argv) > 1
        and sys.argv[1]
        == "--monitor"
    ):

        monitor()

    else:

        if os.geteuid() != 0:

            print(
                "[!] Run with:"
            )

            print(
                "    sudo ./port_monitor.py"
            )

            sys.exit(1)

        menu()
