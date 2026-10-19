#!/usr/bin/env python3

"""
DEDSEC CRAWLER
Network Intelligence & Asset Discovery

v0.2 SSH Terminal Edition

Designed for authorized security assessment and asset inventory.

Features:
    - SSH-friendly terminal interface
    - Centered CRAWLER banner
    - SQLite asset database
    - TCP service discovery
    - Basic HTTP/HTTPS/SSH fingerprinting
    - Device classification
    - Search query language
    - Scan history
    - JSON/CSV export
    - Ctrl-C / Ctrl-Z protection
    - Clean exit through menu option 0

Example searches:

    device:router
    device:nas port:443
    service:nginx
    os:linux
    vendor:ubiquiti
    port:22 country:GB
"""

import csv
import json
import os
import re
import signal
import socket
import sqlite3
import ssl
import sys
import termios
import time
import tty
from datetime import datetime
from urllib.parse import urlparse

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TimeElapsedColumn,
)


# ============================================================
# CONFIG
# ============================================================

APP_NAME = "CRAWLER"
VERSION = "0.2.0"

DB_FILE = os.path.join("data", "crawler.db")

SOCKET_TIMEOUT = 1.5

DEFAULT_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    135,
    139,
    143,
    443,
    445,
    465,
    587,
    993,
    995,
    1433,
    1521,
    3306,
    3389,
    5432,
    5900,
    6379,
    8080,
    8443,
]

console = Console()

# Used when the user presses Ctrl-C / Ctrl-Z.
RETURN_TO_MENU = False


# ============================================================
# SIGNAL HANDLING
# ============================================================

def signal_handler(signum, frame):
    """
    Normal terminal signals return the user to the menu.

    SIGKILL cannot be caught by any program.
    SSH disconnects also terminate the session externally.
    """

    global RETURN_TO_MENU

    RETURN_TO_MENU = True

    console.print(
        "\n\n[yellow]Command cancelled.[/yellow]"
    )

    raise KeyboardInterrupt


def install_signal_handlers():
    signal.signal(signal.SIGINT, signal_handler)

    # Ctrl-Z on Unix/Linux/macOS.
    if hasattr(signal, "SIGTSTP"):
        signal.signal(signal.SIGTSTP, signal_handler)


# ============================================================
# DATABASE
# ============================================================

def get_db():
    os.makedirs("data", exist_ok=True)

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row

    return conn


def init_database():

    conn = get_db()

    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            ip TEXT NOT NULL UNIQUE,
            hostname TEXT,
            reverse_dns TEXT,

            device TEXT,
            os TEXT,
            vendor TEXT,
            country TEXT,
            region TEXT,
            city TEXT,
            isp TEXT,
            asn TEXT,

            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            asset_id INTEGER NOT NULL,

            port INTEGER NOT NULL,
            protocol TEXT DEFAULT 'tcp',

            state TEXT NOT NULL,

            service TEXT,
            version TEXT,
            banner TEXT,

            http_status TEXT,
            http_server TEXT,
            http_title TEXT,

            tls_subject TEXT,
            tls_issuer TEXT,

            timestamp TEXT NOT NULL,

            FOREIGN KEY(asset_id)
                REFERENCES assets(id)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            target TEXT NOT NULL,

            started TEXT NOT NULL,
            finished TEXT,

            hosts_found INTEGER DEFAULT 0,
            ports_found INTEGER DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_assets_ip
            ON assets(ip);

        CREATE INDEX IF NOT EXISTS idx_assets_device
            ON assets(device);

        CREATE INDEX IF NOT EXISTS idx_assets_os
            ON assets(os);

        CREATE INDEX IF NOT EXISTS idx_assets_vendor
            ON assets(vendor);

        CREATE INDEX IF NOT EXISTS idx_assets_country
            ON assets(country);

        CREATE INDEX IF NOT EXISTS idx_observations_port
            ON observations(port);

        CREATE INDEX IF NOT EXISTS idx_observations_service
            ON observations(service);
        """
    )

    conn.commit()
    conn.close()


# ============================================================
# TERMINAL / BANNER
# ============================================================

def terminal_width():

    try:
        return os.get_terminal_size().columns
    except OSError:
        return 80


def center_text(text):

    width = terminal_width()

    result = []

    for line in text.splitlines():

        padding = max(
            0,
            (width - len(line)) // 2
        )

        result.append(
            (" " * padding) + line
        )

    return "\n".join(result)


def show_banner():

    clear_screen()

    crawler = r"""
 ██████╗██████╗  █████╗ ██╗    ██╗██╗     ███████╗██████╗
██╔════╝██╔══██╗██╔══██╗██║    ██║██║     ██╔════╝██╔══██╗
██║     ██████╔╝███████║██║ █╗ ██║██║     █████╗  ██████╔╝
██║     ██╔══██╗██╔══██║██║███╗██║██║     ██╔══╝  ██╔══██╗
╚██████╗██║  ██║██║  ██║╚███╔███╔╝███████╗███████╗██║  ██║
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝
"""

    subtitle = """
NETWORK INTELLIGENCE  •  ASSET DISCOVERY  •  FINGERPRINTING
"""

    console.print()

    console.print(
        center_text(crawler),
        style="bold cyan",
    )

    console.print(
        center_text(subtitle),
        style="bold magenta",
    )

    console.print(
        center_text(f"v{VERSION}  •  SSH TERMINAL EDITION"),
        style="dim cyan",
    )

    console.print()


def clear_screen():

    os.system(
        "cls" if os.name == "nt" else "clear"
    )


def pause():

    console.print()

    try:
        console.input(
            "[dim]Press ENTER to return to menu...[/dim]"
        )

    except KeyboardInterrupt:
        return


def panel_title(name):

    console.print()

    console.print(
        Panel(
            f"[bold cyan]{name}[/bold cyan]",
            border_style="magenta",
            box=box.ROUNDED,
        )
    )


# ============================================================
# ASSET FUNCTIONS
# ============================================================

def resolve_target(target):

    target = target.strip()

    if "://" in target:

        parsed = urlparse(target)

        target = (
            parsed.hostname
            or target
        )

    try:

        ip = socket.gethostbyname(
            target
        )

        return ip, target

    except socket.gaierror:

        return None, None


def reverse_dns(ip):

    try:

        return socket.gethostbyaddr(
            ip
        )[0]

    except Exception:

        return ""


def get_or_create_asset(ip, hostname=None):

    conn = get_db()

    now = datetime.now().isoformat(
        timespec="seconds"
    )

    row = conn.execute(
        """
        SELECT id
        FROM assets
        WHERE ip = ?
        """,
        (ip,),
    ).fetchone()

    if row:

        asset_id = row["id"]

        conn.execute(
            """
            UPDATE assets

            SET hostname =
                    COALESCE(?, hostname),

                last_seen = ?

            WHERE id = ?
            """,
            (
                hostname,
                now,
                asset_id,
            ),
        )

    else:

        cur = conn.execute(
            """
            INSERT INTO assets (
                ip,
                hostname,
                reverse_dns,
                first_seen,
                last_seen
            )

            VALUES (?, ?, ?, ?, ?)
            """,
            (
                ip,
                hostname,
                reverse_dns(ip),
                now,
                now,
            ),
        )

        asset_id = cur.lastrowid

    conn.commit()
    conn.close()

    return asset_id


# ============================================================
# PORT / SERVICE DETECTION
# ============================================================

SERVICE_MAP = {

    21: "ftp",
    22: "ssh",
    23: "telnet",

    25: "smtp",
    53: "dns",

    80: "http",
    110: "pop3",
    135: "msrpc",
    139: "netbios",

    143: "imap",

    443: "https",
    445: "smb",

    465: "smtps",
    587: "smtp",

    993: "imaps",
    995: "pop3s",

    1433: "mssql",
    1521: "oracle",
    3306: "mysql",

    3389: "rdp",

    5432: "postgresql",

    5900: "vnc",

    6379: "redis",

    8080: "http",
    8443: "https",
}


def detect_service(port):

    return SERVICE_MAP.get(
        port,
        "unknown"
    )


def check_port(ip, port):

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    sock.settimeout(
        SOCKET_TIMEOUT
    )

    try:

        return (
            sock.connect_ex(
                (ip, port)
            ) == 0
        )

    except OSError:

        return False

    finally:

        sock.close()


# ============================================================
# BANNER / HTTP / SSH
# ============================================================

def clean_banner(data):

    try:

        value = data.decode(
            "utf-8",
            errors="replace",
        )

    except Exception:

        return ""

    value = value.replace(
        "\x00",
        ""
    )

    value = value.replace(
        "\r",
        " "
    )

    value = value.replace(
        "\n",
        " "
    )

    return " ".join(
        value.split()
    )[:500]


def grab_ssh(ip, port):

    try:

        sock = socket.create_connection(
            (ip, port),
            timeout=SOCKET_TIMEOUT,
        )

        sock.settimeout(2)

        data = sock.recv(512)

        sock.close()

        return clean_banner(data)

    except OSError:

        return ""


def grab_http(
    ip,
    port,
    tls=False,
):

    sock = None

    try:

        sock = socket.create_connection(
            (ip, port),
            timeout=SOCKET_TIMEOUT,
        )

        if tls:

            context = (
                ssl.create_default_context()
            )

            context.check_hostname = False

            context.verify_mode = (
                ssl.CERT_NONE
            )

            sock = context.wrap_socket(
                sock,
                server_hostname=ip,
            )

        request = (
            "HEAD / HTTP/1.1\r\n"
            f"Host: {ip}\r\n"
            "User-Agent: Crawler/0.2\r\n"
            "Connection: close\r\n"
            "\r\n"
        )

        sock.sendall(
            request.encode()
        )

        data = sock.recv(4096)

        return clean_banner(data)

    except OSError:

        return ""

    finally:

        if sock:

            try:
                sock.close()
            except OSError:
                pass


def extract_http_info(banner):

    info = {
        "status": "",
        "server": "",
        "title": "",
    }

    status = re.search(
        r"HTTP/\d(?:\.\d)?\s+(\d+)",
        banner,
        re.I,
    )

    server = re.search(
        r"Server:\s*([^\s]+)",
        banner,
        re.I,
    )

    if status:

        info["status"] = (
            status.group(1)
        )

    if server:

        info["server"] = (
            server.group(1)
        )

    return info


# ============================================================
# DEVICE CLASSIFICATION
# ============================================================

def classify_device(
    ports,
    services,
    banners,
):
    """
    Basic heuristic classifier.

    This intentionally produces broad categories.
    More sophisticated vendor/device fingerprints
    can be added later.
    """

    service_set = set(
        services
    )

    banner_text = (
        " ".join(banners)
        .lower()
    )

    # NAS / storage
    if (
        "smb" in service_set
        or "netbios" in service_set
    ):

        return "nas"

    # Router / gateway clues
    if (
        "telnet" in service_set
        and "http" in service_set
    ):

        return "router"

    if (
        "http" in service_set
        and (
            "router" in banner_text
            or "gateway" in banner_text
            or "mikrotik" in banner_text
            or "ubiquiti" in banner_text
            or "openwrt" in banner_text
        )
    ):

        return "router"

    # Web server
    if (
        "http" in service_set
        or "https" in service_set
    ):

        return "web_server"

    # Database
    database_services = {
        "mysql",
        "mssql",
        "postgresql",
        "oracle",
        "redis",
    }

    if service_set.intersection(
        database_services
    ):

        return "database"

    # SSH server
    if "ssh" in service_set:

        return "server"

    return "unknown"


def detect_os(
    services,
    banners,
):
    """
    Conservative OS fingerprinting.

    Only returns an OS when a clear clue exists.
    """

    text = (
        " ".join(banners)
        .lower()
    )

    if (
        "openssh" in text
        or "ubuntu" in text
        or "debian" in text
        or "centos" in text
        or "alpine" in text
    ):

        return "linux"

    if (
        "microsoft" in text
        or "windows" in text
        or "iis" in text
    ):

        return "windows"

    return ""


def detect_vendor(
    banners,
):
    text = (
        " ".join(banners)
        .lower()
    )

    vendors = {
        "ubiquiti": "ubiquiti",
        "mikrotik": "mikrotik",
        "cisco": "cisco",
        "juniper": "juniper",
        "fortinet": "fortinet",
        "palo alto": "palo_alto",
        "synology": "synology",
        "qnap": "qnap",
        "netgear": "netgear",
        "d-link": "dlink",
        "tp-link": "tp-link",
    }

    for clue, vendor in vendors.items():

        if clue in text:

            return vendor

    return ""


# ============================================================
# OBSERVATIONS
# ============================================================

def save_observation(
    asset_id,
    port,
    service,
    banner="",
    http_info=None,
):

    conn = get_db()

    now = datetime.now().isoformat(
        timespec="seconds"
    )

    http_info = (
        http_info
        or {}
    )

    conn.execute(
        """
        INSERT INTO observations (
            asset_id,
            port,
            protocol,
            state,
            service,
            banner,
            http_status,
            http_server,
            http_title,
            timestamp
        )

        VALUES (
            ?,
            ?,
            'tcp',
            'open',
            ?,
            ?,
            ?,
            ?,
            ?,
            ?
        )
        """,
        (
            asset_id,
            port,
            service,
            banner,
            http_info.get(
                "status",
                "",
            ),
            http_info.get(
                "server",
                "",
            ),
            http_info.get(
                "title",
                "",
            ),
            now,
        ),
    )

    conn.commit()
    conn.close()


def update_asset_fingerprint(
    asset_id,
    device,
    os_name,
    vendor,
):

    conn = get_db()

    conn.execute(
        """
        UPDATE assets

        SET device = ?,
            os = ?,
            vendor = ?,
            last_seen = ?

        WHERE id = ?
        """,
        (
            device,
            os_name,
            vendor,
            datetime.now().isoformat(
                timespec="seconds"
            ),
            asset_id,
        ),
    )

    conn.commit()
    conn.close()


# ============================================================
# SCANNER
# ============================================================

def scan_target(target):

    panel_title(
        "AUTHORIZED TARGET SCANNER"
    )

    console.print(
        "[yellow]"
        "Only scan systems/networks you are "
        "authorized to assess."
        "[/yellow]"
    )

    ip, hostname = resolve_target(
        target
    )

    if not ip:

        console.print(
            "[red]Target could not be resolved.[/red]"
        )

        return

    console.print(
        f"\n[cyan]Target:[/cyan] {target}"
    )

    console.print(
        f"[cyan]IP:[/cyan] {ip}"
    )

    rdns = reverse_dns(ip)

    if rdns:

        console.print(
            f"[cyan]Reverse DNS:[/cyan] {rdns}"
        )

    asset_id = get_or_create_asset(
        ip,
        hostname,
    )

    started = datetime.now().isoformat(
        timespec="seconds"
    )

    conn = get_db()

    scan = conn.execute(
        """
        INSERT INTO scans (
            target,
            started
        )

        VALUES (?, ?)
        """,
        (
            target,
            started,
        ),
    )

    scan_id = scan.lastrowid

    conn.commit()
    conn.close()

    open_ports = []

    try:

        with Progress(
            SpinnerColumn(),
            TextColumn(
                "[cyan]{task.description}"
            ),
            BarColumn(),
            TextColumn(
                "{task.completed}/{task.total}"
            ),
            TimeElapsedColumn(),
        ) as progress:

            task = progress.add_task(
                "Discovering TCP services",
                total=len(DEFAULT_PORTS),
            )

            for port in DEFAULT_PORTS:

                if check_port(
                    ip,
                    port,
                ):

                    open_ports.append(
                        port
                    )

                progress.advance(
                    task
                )

    except KeyboardInterrupt:

        return

    services = []
    banners = []

    results = []

    for port in open_ports:

        service = detect_service(
            port
        )

        banner = ""

        http_info = {}

        if service == "ssh":

            banner = grab_ssh(
                ip,
                port,
            )

        elif service == "http":

            banner = grab_http(
                ip,
                port,
                tls=False,
            )

            http_info = (
                extract_http_info(
                    banner
                )
            )

        elif service == "https":

            banner = grab_http(
                ip,
                port,
                tls=True,
            )

            http_info = (
                extract_http_info(
                    banner
                )
            )

        else:

            try:

                sock = socket.create_connection(
                    (
                        ip,
                        port,
                    ),
                    timeout=1,
                )

                sock.settimeout(1)

                data = sock.recv(512)

                sock.close()

                banner = clean_banner(
                    data
                )

            except OSError:

                pass

        services.append(
            service
        )

        banners.append(
            banner
        )

        save_observation(
            asset_id,
            port,
            service,
            banner,
            http_info,
        )

        results.append(
            (
                port,
                service,
                banner,
            )
        )

    device = classify_device(
        open_ports,
        services,
        banners,
    )

    os_name = detect_os(
        services,
        banners,
    )

    vendor = detect_vendor(
        banners,
    )

    update_asset_fingerprint(
        asset_id,
        device,
        os_name,
        vendor,
    )

    table = Table(
        title="DISCOVERED SERVICES",
        box=box.ROUNDED,
        border_style="cyan",
    )

    table.add_column(
        "PORT",
        style="bold cyan",
    )

    table.add_column(
        "STATE",
        style="green",
    )

    table.add_column(
        "SERVICE",
        style="magenta",
    )

    table.add_column(
        "BANNER",
        style="white",
    )

    for port, service, banner in results:

        if len(banner) > 60:

            banner = (
                banner[:57]
                + "..."
            )

        table.add_row(
            str(port),
            "OPEN",
            service,
            banner or "-",
        )

    console.print()

    if results:

        console.print(table)

    else:

        console.print(
            "[yellow]"
            "No open ports found in the default port set."
            "[/yellow]"
        )

    console.print()

    fingerprint_table = Table(
        title="FINGERPRINT",
        box=box.ROUNDED,
        border_style="magenta",
    )

    fingerprint_table.add_column(
        "FIELD",
        style="cyan",
    )

    fingerprint_table.add_column(
        "VALUE",
        style="green",
    )

    fingerprint_table.add_row(
        "Device",
        device,
    )

    fingerprint_table.add_row(
        "OS",
        os_name or "unknown",
    )

    fingerprint_table.add_row(
        "Vendor",
        vendor or "unknown",
    )

    fingerprint_table.add_row(
        "Open Ports",
        str(len(open_ports)),
    )

    console.print(
        fingerprint_table
    )

    finished = datetime.now().isoformat(
        timespec="seconds"
    )

    conn = get_db()

    conn.execute(
        """
        UPDATE scans

        SET finished = ?,
            hosts_found = 1,
            ports_found = ?

        WHERE id = ?
        """,
        (
            finished,
            len(open_ports),
            scan_id,
        ),
    )

    conn.commit()
    conn.close()


# ============================================================
# SEARCH ENGINE
# ============================================================

SEARCH_FIELDS = {
    "ip",
    "hostname",
    "port",
    "service",
    "device",
    "os",
    "vendor",
    "country",
    "region",
    "city",
    "isp",
    "asn",
}


def parse_search(query):

    """
    Parse:

        device:router
        device:nas port:443
        service:nginx
        os:linux
        vendor:ubiquiti
        port:22 country:GB

    """

    pattern = (
        r'(\w+):("[^"]+"|\S+)'
    )

    matches = re.findall(
        pattern,
        query,
        re.I,
    )

    return [
        (
            key.lower(),
            value.strip('"')
        )
        for key, value in matches
    ]


def run_search(query):

    conditions = []
    params = []

    terms = parse_search(
        query
    )

    if not terms:

        return [], "No valid search fields."

    for key, value in terms:

        if key not in SEARCH_FIELDS:

            return [], (
                f"Unknown field: {key}"
            )

        if key == "port":

            if not value.isdigit():

                return [], (
                    "Port must be numeric."
                )

            conditions.append(
                "o.port = ?"
            )

            params.append(
                int(value)
            )

        elif key == "ip":

            conditions.append(
                "a.ip = ?"
            )

            params.append(
                value
            )

        elif key == "hostname":

            conditions.append(
                "LOWER(a.hostname) LIKE ?"
            )

            params.append(
                f"%{value.lower()}%"
            )

        elif key == "service":

            conditions.append(
                "LOWER(o.service) = ?"
            )

            params.append(
                value.lower()
            )

        elif key == "device":

            conditions.append(
                "LOWER(a.device) = ?"
            )

            params.append(
                value.lower()
            )

        elif key == "os":

            conditions.append(
                "LOWER(a.os) = ?"
            )

            params.append(
                value.lower()
            )

        elif key == "vendor":

            conditions.append(
                "LOWER(a.vendor) = ?"
            )

            params.append(
                value.lower()
            )

        elif key in {
            "country",
            "region",
            "city",
            "isp",
            "asn",
        }:

            conditions.append(
                f"LOWER(a.{key}) = ?"
            )

            params.append(
                value.lower()
            )

    sql = f"""
        SELECT DISTINCT

            a.ip,
            a.hostname,
            a.device,
            a.os,
            a.vendor,
            a.country,

            o.port,
            o.service,

            o.timestamp

        FROM assets a

        JOIN observations o
            ON a.id = o.asset_id

        WHERE {" AND ".join(conditions)}

        ORDER BY
            a.ip,
            o.port
    """

    conn = get_db()

    rows = conn.execute(
        sql,
        params,
    ).fetchall()

    conn.close()

    return rows, None


def search_assets():

    panel_title(
        "CRAWLER SEARCH"
    )

    console.print(
        """
[dim]Search your collected asset database.

Examples:

  device:router
  device:nas port:443
  service:nginx
  os:linux
  vendor:ubiquiti
  port:22 country:GB

Multiple fields are combined with AND.
[/dim]
"""
    )

    query = console.input(
        "[bold cyan]crawler/search> [/bold cyan]"
    ).strip()

    if query.lower() in {
        "x",
        "exit",
        "back",
        "q",
    }:

        return

    rows, error = run_search(
        query
    )

    if error:

        console.print(
            f"[red]{error}[/red]"
        )

        return

    table = Table(
        title=f"SEARCH - {query}",
        box=box.ROUNDED,
        border_style="cyan",
    )

    table.add_column(
        "IP",
        style="cyan",
    )

    table.add_column(
        "HOST",
    )

    table.add_column(
        "DEVICE",
        style="magenta",
    )

    table.add_column(
        "OS",
        style="yellow",
    )

    table.add_column(
        "VENDOR",
        style="blue",
    )

    table.add_column(
        "PORT",
        style="green",
    )

    table.add_column(
        "SERVICE",
        style="bold",
    )

    for row in rows:

        table.add_row(
            row["ip"],
            row["hostname"] or "-",
            row["device"] or "-",
            row["os"] or "-",
            row["vendor"] or "-",
            str(row["port"]),
            row["service"] or "-",
        )

    console.print()

    if rows:

        console.print(table)

        console.print(
            f"\n[green]"
            f"{len(rows)} matching observation(s)."
            f"[/green]"
        )

    else:

        console.print(
            "[yellow]No matching assets found.[/yellow]"
        )


# ============================================================
# DASHBOARD
# ============================================================

def dashboard():

    panel_title(
        "CRAWLER DASHBOARD"
    )

    conn = get_db()

    assets = conn.execute(
        """
        SELECT COUNT(*) AS n
        FROM assets
        """
    ).fetchone()["n"]

    observations = conn.execute(
        """
        SELECT COUNT(*) AS n
        FROM observations
        """
    ).fetchone()["n"]

    scans = conn.execute(
        """
        SELECT COUNT(*) AS n
        FROM scans
        """
    ).fetchone()["n"]

    conn.close()

    table = Table(
        box=box.ROUNDED,
        border_style="cyan",
    )

    table.add_column(
        "METRIC",
        style="cyan",
    )

    table.add_column(
        "VALUE",
        style="bold green",
    )

    table.add_row(
        "Assets",
        str(assets),
    )

    table.add_row(
        "Observations",
        str(observations),
    )

    table.add_row(
        "Scans",
        str(scans),
    )

    console.print(table)


# ============================================================
# HISTORY
# ============================================================

def scan_history():

    panel_title(
        "SCAN HISTORY"
    )

    conn = get_db()

    rows = conn.execute(
        """
        SELECT *
        FROM scans

        ORDER BY id DESC

        LIMIT 50
        """
    ).fetchall()

    conn.close()

    table = Table(
        box=box.ROUNDED,
        border_style="cyan",
    )

    table.add_column(
        "ID",
        style="yellow",
    )

    table.add_column(
        "TARGET",
        style="cyan",
    )

    table.add_column(
        "STARTED",
    )

    table.add_column(
        "FINISHED",
    )

    table.add_column(
        "PORTS",
        style="green",
    )

    for row in rows:

        table.add_row(
            str(row["id"]),
            row["target"],
            row["started"],
            row["finished"] or "-",
            str(row["ports_found"]),
        )

    console.print(table)


# ============================================================
# EXPORT
# ============================================================

def export_results():

    panel_title(
        "EXPORT"
    )

    console.print(
        "[1] JSON\n"
        "[2] CSV\n"
        "[x] Back"
    )

    choice = console.input(
        "\n[cyan]export> [/cyan]"
    ).strip().lower()

    if choice in {
        "x",
        "back",
        "q",
    }:

        return

    if choice not in {
        "1",
        "2",
    }:

        console.print(
            "[red]Invalid option.[/red]"
        )

        return

    os.makedirs(
        "exports",
        exist_ok=True,
    )

    conn = get_db()

    rows = conn.execute(
        """
        SELECT

            a.ip,
            a.hostname,
            a.reverse_dns,

            a.device,
            a.os,
            a.vendor,
            a.country,
            a.region,
            a.city,
            a.isp,
            a.asn,

            o.port,
            o.service,
            o.banner,

            o.http_status,
            o.http_server,
            o.http_title,

            o.timestamp

        FROM assets a

        JOIN observations o
            ON a.id = o.asset_id

        ORDER BY
            a.ip,
            o.port
        """
    ).fetchall()

    conn.close()

    stamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    if choice == "1":

        filename = (
            f"exports/crawler_{stamp}.json"
        )

        data = [
            dict(row)
            for row in rows
        ]

        with open(
            filename,
            "w",
            encoding="utf-8",
        ) as f:

            json.dump(
                data,
                f,
                indent=2,
            )

    else:

        filename = (
            f"exports/crawler_{stamp}.csv"
        )

        with open(
            filename,
            "w",
            newline="",
            encoding="utf-8",
        ) as f:

            if rows:

                writer = csv.DictWriter(
                    f,
                    fieldnames=rows[0].keys(),
                )

                writer.writeheader()

                for row in rows:

                    writer.writerow(
                        dict(row)
                    )

    console.print(
        f"\n[green]Export complete:[/green] "
        f"{filename}"
    )


# ============================================================
# MENU
# ============================================================

def main_menu():

    while True:

        show_banner()

        conn = get_db()

        assets = conn.execute(
            """
            SELECT COUNT(*) AS n
            FROM assets
            """
        ).fetchone()["n"]

        conn.close()

        status = Table(
            box=box.ROUNDED,
            border_style="green",
            show_header=False,
        )

        status.add_column(
            width=24
        )

        status.add_column(
            width=30
        )

        status.add_row(
            "DATABASE",
            "[green]● ONLINE[/green]",
        )

        status.add_row(
            "CRAWLER ENGINE",
            "[green]● READY[/green]",
        )

        status.add_row(
            "FINGERPRINT ENGINE",
            "[green]● READY[/green]",
        )

        status.add_row(
            "ASSETS",
            f"[cyan]{assets}[/cyan]",
        )

        console.print(
            status
        )

        console.print()

        menu = Table(
            box=box.ROUNDED,
            border_style="cyan",
            show_header=False,
        )

        menu.add_column(
            "KEY",
            style="bold yellow",
            width=8,
        )

        menu.add_column(
            "FUNCTION",
            style="white",
        )

        menu.add_row(
            "1",
            "🔎  Search Assets",
        )

        menu.add_row(
            "2",
            "🎯  Scan Authorized Target",
        )

        menu.add_row(
            "3",
            "🌐  Network / CIDR",
        )

        menu.add_row(
            "4",
            "🖥   Device Search",
        )

        menu.add_row(
            "5",
            "📡  Service Search",
        )

        menu.add_row(
            "6",
            "📊  Dashboard",
        )

        menu.add_row(
            "7",
            "🕐  Scan History",
        )

        menu.add_row(
            "8",
            "💾  Export",
        )

        menu.add_row(
            "9",
            "⚙   Settings",
        )

        menu.add_row(
            "0",
            "✕   Exit Crawler",
        )

        console.print(menu)

        console.print(
            "\n[dim]"
            "Ctrl-C / Ctrl-Z / x = return to menu"
            "[/dim]"
        )

        try:

            choice = console.input(
                "\n[bold cyan]"
                "crawler@dedsec:~$ "
                "[/bold cyan]"
            ).strip().lower()

        except KeyboardInterrupt:

            continue

        if choice in {
            "x",
            "exit",
            "quit",
            "q",
        }:

            # Important:
            # x does NOT exit the application.
            # It simply keeps the user at the menu.
            console.print(
                "\n[yellow]"
                "Use option 0 to exit Crawler."
                "[/yellow]"
            )

            time.sleep(1)

            continue

        if choice == "1":

            try:

                search_assets()

            except KeyboardInterrupt:

                pass

            pause()

        elif choice == "2":

            try:

                target = console.input(
                    "\n[cyan]"
                    "Authorized target> "
                    "[/cyan]"
                ).strip()

                if target:

                    scan_target(
                        target
                    )

            except KeyboardInterrupt:

                console.print(
                    "\n[yellow]"
                    "Scan cancelled."
                    "[/yellow]"
                )

            pause()

        elif choice == "3":

            panel_title(
                "NETWORK / CIDR"
            )

            console.print(
                "[yellow]"
                "Controlled network scanning will be "
                "enabled in the next scanner module."
                "[/yellow]"
            )

            console.print(
                "\n[dim]"
                "This module will support explicitly "
                "authorized CIDR scopes."
                "[/dim]"
            )

            pause()

        elif choice == "4":

            try:

                search_assets()

            except KeyboardInterrupt:

                pass

            pause()

        elif choice == "5":

            try:

                search_assets()

            except KeyboardInterrupt:

                pass

            pause()

        elif choice == "6":

            dashboard()
            pause()

        elif choice == "7":

            scan_history()
            pause()

        elif choice == "8":

            export_results()
            pause()

        elif choice == "9":

            panel_title(
                "SETTINGS"
            )

            console.print(
                f"Database: {DB_FILE}"
            )

            console.print(
                f"Socket timeout: "
                f"{SOCKET_TIMEOUT}s"
            )

            console.print(
                f"Default ports: "
                f"{len(DEFAULT_PORTS)}"
            )

            pause()

        elif choice == "0":

            clear_screen()

            console.print(
                Panel(
                    "[bold cyan]"
                    "CRAWLER"
                    "[/bold cyan]\n\n"
                    "[green]"
                    "Session terminated cleanly."
                    "[/green]",
                    border_style="cyan",
                    box=box.DOUBLE,
                )
            )

            return

        else:

            console.print(
                "[red]Unknown menu option.[/red]"
            )

            time.sleep(1)


# ============================================================
# MAIN
# ============================================================

def main():

    init_database()

    install_signal_handlers()

    try:

        main_menu()

    except KeyboardInterrupt:

        # Never let a normal Ctrl-C kill the
        # application from the top level.
        main_menu()


if __name__ == "__main__":

    main()
