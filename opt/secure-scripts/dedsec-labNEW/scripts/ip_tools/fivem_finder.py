#!/usr/bin/env python3
"""
DedSec Lab - FiveM Server Finder
Search public Cfx listings, look up by CFX code, or join by IP:port.
Ctrl+C returns to the menu. Exit only from option 0.
"""
from __future__ import annotations

import json
import os
import platform
import re
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
except ImportError:
    print("Missing dependency: requests")
    print("    pip install requests")
    sys.exit(1)

# ============================================================
# Config
# ============================================================
STREAM_URLS = (
    "https://servers-frontend.fivem.net/api/servers/streamRedir/",
    "https://servers-frontend.fivem.net/api/servers/streamRedir",
    "https://frontend.cfx-services.net/api/servers/streamRedir/",
    "https://frontend.cfx-services.net/api/servers/streamRedir",
    "https://servers-live.fivem.net/api/servers/",
)
SINGLE_URLS = (
    "https://servers-frontend.fivem.net/api/servers/single/{code}",
    "https://frontend.cfx-services.net/api/servers/single/{code}",
    "https://servers-frontend.fivem.net/api/servers/single/{code}/",
)
INFO_PATHS = ("/info.json", "/dynamic.json")
REQUEST_TIMEOUT = 18
STREAM_TIMEOUT = 45
MAX_RESULTS = 25
DEFAULT_PORT = 30120
HEADERS = {
    "User-Agent": "Mozilla/5.0 DedSecLab-FiveMFinder/1.0",
    "Accept": "application/json, application/octet-stream, */*",
}

LAST_RESULTS: List[Dict[str, Any]] = []

# ============================================================
# Colours / UI
# ============================================================
RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
DIM = "\033[2m"
WHITE = "\033[97m"


def color(text: str, c: str) -> str:
    return f"{c}{text}{RESET}"


def enable_colors() -> None:
    if platform.system() == "Windows":
        os.system("")


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def pause(msg: str = "Press Enter to return to menu...") -> None:
    try:
        input(color(msg, DIM))
    except (KeyboardInterrupt, EOFError):
        print()


def banner() -> None:
    clear_screen()
    print(color(r"""
██████╗ ███████╗██████╗ ███████╗███████╗ ██████╗
██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝
██║  ██║█████╗  ██║  ██║███████╗█████╗  ██║
██║  ██║██╔══╝  ██║  ██║╚════██║██╔══╝  ██║
██████╔╝███████╗██████╔╝███████║███████╗╚██████╗
╚═════╝ ╚══════╝╚═════╝ ╚══════╝╚══════╝ ╚═════╝
""", CYAN))
    print(color("  DEDSEC LAB  ·  FIVEM SERVER FINDER", BOLD + CYAN))
    print(color("  Search by name  ·  CFX code", DIM))
    print(color("════════════════════════════════════════════════════════", CYAN))


def strip_colors(text: str) -> str:
    return re.sub(r"\^[0-9]", "", text or "")


def ask(prompt: str) -> Optional[str]:
    try:
        value = input(color(prompt, WHITE)).strip()
        return value
    except (KeyboardInterrupt, EOFError):
        print()
        return None


# ============================================================
# Network helpers
# ============================================================
def http_get(url: str, timeout: int = REQUEST_TIMEOUT, stream: bool = False):
    return requests.get(url, headers=HEADERS, timeout=timeout, stream=stream)


def parse_host_port(raw: str) -> Optional[Tuple[str, int]]:
    raw = (raw or "").strip()
    raw = raw.replace("fivem://connect/", "").replace("connect ", "")
    raw = raw.split("/")[0]
    if not raw:
        return None
    if raw.count(":") == 1:
        host, port_s = raw.rsplit(":", 1)
        if host and port_s.isdigit():
            return host, int(port_s)
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", raw):
        return raw, DEFAULT_PORT
    return None


def extract_cfx_code(raw: str) -> str:
    raw = (raw or "").strip()
    m = re.search(r"(?:cfx\.re/join/|join/)([A-Za-z0-9]+)", raw, re.I)
    if m:
        return m.group(1).lower()
    if re.fullmatch(r"[A-Za-z0-9]{4,12}", raw):
        return raw.lower()
    return ""


def endpoints_from_data(data: Dict[str, Any]) -> List[str]:
    eps = data.get("connectEndPoints") or []
    out = []
    for item in eps:
        s = str(item).strip()
        if s and not s.startswith("cfx.re"):
            out.append(s)
    return out


def summarise_server(entry: Dict[str, Any]) -> Dict[str, Any]:
    data = entry.get("Data") or entry.get("data") or entry
    code = str(entry.get("EndPoint") or entry.get("endpoint") or "").strip()
    hostname = strip_colors(str(data.get("hostname") or data.get("sv_hostname") or "Unknown"))
    clients = data.get("clients", data.get("clientsCount", "?"))
    slots = data.get("svMaxclients") or data.get("sv_maxclients") or "?"
    gametype = strip_colors(str(data.get("gametype") or data.get("gamename") or ""))
    mapname = strip_colors(str(data.get("mapname") or ""))
    eps = endpoints_from_data(data)
    vars_ = data.get("vars") or {}
    locale = vars_.get("locale") or ""
    project = strip_colors(str(vars_.get("sv_projectName") or ""))
    return {
        "code": code,
        "name": hostname,
        "project": project,
        "players": f"{clients}/{slots}",
        "gametype": gametype,
        "map": mapname,
        "locale": locale,
        "endpoints": eps,
        "join": f"cfx.re/join/{code}" if code else "",
    }


def print_server(idx: Optional[int], item: Dict[str, Any]) -> None:
    prefix = f"[{idx}] " if idx is not None else ""
    print(color(f"{prefix}{item['name']}", BOLD + WHITE))
    if item.get("project") and item["project"] != item["name"]:
        print(f"    Project : {item['project']}")
    print(f"    Players : {item['players']}")
    if item.get("gametype"):
        print(f"    Type    : {item['gametype']}")
    if item.get("map"):
        print(f"    Map     : {item['map']}")
    if item.get("locale"):
        print(f"    Locale  : {item['locale']}")
    if item.get("code"):
        print(color(f"    CFX     : cfx.re/join/{item['code']}", CYAN))
    if item.get("endpoints"):
        print(color(f"    IP:PORT : {item['endpoints'][0]}", GREEN))
        for extra in item["endpoints"][1:]:
            print(f"              {extra}")
    else:
        print(color("    IP:PORT : hidden / cfx-only", YELLOW))
    print()


# ============================================================
# Lookups
# ============================================================
def lookup_cfx(code: str) -> Optional[Dict[str, Any]]:
    code = extract_cfx_code(code)
    if not code:
        return None
    last_err = None
    for tmpl in SINGLE_URLS:
        try:
            r = http_get(tmpl.format(code=code))
            if r.status_code == 200:
                payload = r.json()
                if isinstance(payload, dict):
                    payload.setdefault("EndPoint", code)
                    return summarise_server(payload)
            last_err = f"HTTP {r.status_code}"
        except Exception as e:
            last_err = str(e)
    print(color(f"[!] CFX lookup failed ({last_err})", RED))
    return None


def _scan_stream_body(resp, query_l: str, limit: int) -> List[Dict[str, Any]]:
    found: List[Dict[str, Any]] = []
    buf = ""
    ctype = (resp.headers.get("content-type") or "").lower()
    # JSON array
    if "application/json" in ctype and not resp.headers.get("transfer-encoding"):
        try:
            data = resp.json()
            rows = data if isinstance(data, list) else [data]
            for obj in rows:
                if not isinstance(obj, dict):
                    continue
                item = summarise_server(obj)
                blob = " ".join(
                    [
                        item.get("name", ""),
                        item.get("project", ""),
                        item.get("code", ""),
                        " ".join(item.get("endpoints") or []),
                    ]
                ).lower()
                if query_l in blob:
                    found.append(item)
                    if len(found) >= limit:
                        return found
        except Exception:
            pass
        return found
    for chunk in resp.iter_content(chunk_size=8192, decode_unicode=True):
        if not chunk:
            continue
        if isinstance(chunk, bytes):
            chunk = chunk.decode("utf-8", "ignore")
        buf += chunk
        while "\n" in buf:
            line, buf = buf.split("\n", 1)
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue
            item = summarise_server(obj)
            blob = " ".join(
                [
                    item.get("name", ""),
                    item.get("project", ""),
                    item.get("code", ""),
                    " ".join(item.get("endpoints") or []),
                ]
            ).lower()
            if query_l in blob:
                found.append(item)
                if len(found) >= limit:
                    return found
    return found


def search_stream(query: str, limit: int = MAX_RESULTS) -> List[Dict[str, Any]]:
    query_l = query.lower().strip()
    print(color("[*] Searching public FiveM list...", DIM))

    # If they pasted a CFX code by mistake, resolve it directly
    code = extract_cfx_code(query)
    if code and query_l.replace(" ", "") == code:
        item = lookup_cfx(code)
        return [item] if item else []

    last_err = None
    for url in STREAM_URLS:
        try:
            print(color(f"    try {url}", DIM))
            with http_get(url, timeout=STREAM_TIMEOUT, stream=True) as r:
                if r.status_code == 404:
                    last_err = f"404 {url}"
                    continue
                r.raise_for_status()
                found = _scan_stream_body(r, query_l, limit)
                if found:
                    return found
                last_err = f"no name matches on {url}"
        except KeyboardInterrupt:
            print(color("\n[*] Search cancelled.", YELLOW))
            return []
        except Exception as e:
            last_err = str(e)
            continue

    print(color(f"[!] Public name-search feed is down ({last_err}).", YELLOW))
    print(color("    Use option 2 with the server CFX code instead.", YELLOW))
    print(color("    Example: cfx.re/join/xxxxxx  (from their Discord / listing).", DIM))
    return []


def probe_direct(host: str, port: int) -> Dict[str, Any]:
    base = f"http://{host}:{port}"
    info: Dict[str, Any] = {}
    dynamic: Dict[str, Any] = {}
    for path, bucket in (("/info.json", info), ("/dynamic.json", dynamic)):
        try:
            r = requests.get(base + path, headers=HEADERS, timeout=6)
            if r.ok:
                bucket.update(r.json() if r.headers.get("content-type", "").find("json") >= 0 or True else {})
        except Exception:
            pass
    name = strip_colors(str(dynamic.get("hostname") or info.get("vars", {}).get("sv_projectName") or "Direct server"))
    clients = dynamic.get("clients", "?")
    slots = dynamic.get("sv_maxclients") or info.get("vars", {}).get("sv_maxClients") or "?"
    return {
        "code": "",
        "name": name,
        "project": "",
        "players": f"{clients}/{slots}",
        "gametype": strip_colors(str(dynamic.get("gametype") or "")),
        "map": strip_colors(str(dynamic.get("mapname") or "")),
        "locale": "",
        "endpoints": [f"{host}:{port}"],
        "join": f"{host}:{port}",
    }


def launch_fivem(target: str) -> None:
    target = target.strip()
    if target.startswith("cfx.re"):
        uri = f"fivem://connect/{target}"
    elif ":" in target:
        uri = f"fivem://connect/{target}"
    else:
        uri = f"fivem://connect/cfx.re/join/{target}"
    print(color(f"[*] Launch URI: {uri}", CYAN))
    print(color("    In FiveM F8 console you can also type:", DIM))
    if target.startswith("cfx.re") or ":" not in target:
        print(color(f"    connect {target if target.startswith('cfx.re') else 'cfx.re/join/' + target}", GREEN))
    else:
        print(color(f"    connect {target}", GREEN))
    try:
        system = platform.system()
        if system == "Windows":
            os.startfile(uri)  # type: ignore[attr-defined]
        elif system == "Darwin":
            subprocess.Popen(["open", uri])
        else:
            subprocess.Popen(["xdg-open", uri])
        print(color("[+] Asked the OS to open FiveM.", GREEN))
    except Exception as e:
        print(color(f"[!] Could not auto-launch FiveM: {e}", YELLOW))
        print(color("    Copy the connect line into the F8 console.", DIM))


def pick_from_results() -> Optional[Dict[str, Any]]:
    if not LAST_RESULTS:
        print(color("[!] No saved results. Search first.", YELLOW))
        return None
    raw = ask("Select number (or blank to cancel): ")
    if raw is None or raw == "":
        return None
    if not raw.isdigit():
        print(color("[!] Enter a number from the list.", RED))
        return None
    idx = int(raw)
    if idx < 1 or idx > len(LAST_RESULTS):
        print(color("[!] Out of range.", RED))
        return None
    return LAST_RESULTS[idx - 1]


def connect_item(item: Dict[str, Any]) -> None:
    if item.get("endpoints"):
        launch_fivem(item["endpoints"][0])
    elif item.get("code"):
        launch_fivem(f"cfx.re/join/{item['code']}")
    else:
        print(color("[!] No IP:port or CFX code on this result.", RED))


# ============================================================
# Menu actions
# ============================================================
def action_search() -> None:
    global LAST_RESULTS
    q = ask("Server name / keyword: ")
    if not q:
        return
    LAST_RESULTS = search_stream(q)
    banner()
    print(color("  SEARCH RESULTS", BOLD + MAGENTA))
    print(color("--------------------------------------------------", DIM))
    print()
    if not LAST_RESULTS:
        print(color("[*] No matches (list is huge - try a more unique name).", YELLOW))
        pause()
        return
    print(color(f"[+] {len(LAST_RESULTS)} match(es)", GREEN))
    print()
    for i, item in enumerate(LAST_RESULTS, 1):
        print_server(i, item)
    pause()


def action_cfx() -> None:
    global LAST_RESULTS
    raw = ask("CFX code or cfx.re/join/xxxxxx: ")
    if not raw:
        return
    item = lookup_cfx(raw)
    banner()
    print(color("  CFX LOOKUP", BOLD + MAGENTA))
    print(color("--------------------------------------------------", DIM))
    print()
    if not item:
        print(color("[!] Server not found.", RED))
        pause()
        return
    LAST_RESULTS = [item]
    print_server(1, item)
    pause()


def action_direct() -> None:
    raw = ask(f"Server IP[:port] (default port {DEFAULT_PORT}): ")
    if not raw:
        return
    parsed = parse_host_port(raw)
    if not parsed:
        print(color("[!] Use 1.2.3.4 or 1.2.3.4:30120", RED))
        pause()
        return
    host, port = parsed
    print(color(f"[*] Probing {host}:{port} ...", DIM))
    item = probe_direct(host, port)
    print()
    print_server(None, item)
    pause()


def action_last() -> None:
    banner()
    print(color("  LAST RESULTS", BOLD + MAGENTA))
    print(color("--------------------------------------------------", DIM))
    print()
    if not LAST_RESULTS:
        print(color("[!] Nothing stored yet.", YELLOW))
        pause()
        return
    for i, item in enumerate(LAST_RESULTS, 1):
        print_server(i, item)
    pause()


def action_help() -> None:
    banner()
    print(color("How to use", BOLD + CYAN))
    print("  1. Search by server name - shows IP:PORT when the list is up.")
    print("  2. Paste a CFX code (cfx.re/join/abc123) - shows IP:PORT.")
    print("  3. Paste an IP or IP:port to probe info.json.")
    print()
    print("  FiveM F8 console:")
    print(color("    connect 1.2.3.4:30120", GREEN))
    print(color("    connect cfx.re/join/abc123", GREEN))
    print()
    print("  This tool only uses the public Cfx server list and the")
    print("  server's own info.json. Ctrl+C returns to this menu.")
    print("  Use option 0 to exit cleanly.")
    pause()


def menu() -> None:
    while True:
        banner()
        print(color("  PAGE 1 · FIND", BOLD + MAGENTA))
        print()
        print("   1. Search servers by name")
        print("   2. Lookup CFX code")
        print("   3. Last results")
        print("   4. Help")
        print()
        print(color("   0. Exit", DIM))
        print(color("  Ctrl+C returns here", DIM))
        print(color("--------------------------------------------------", DIM))
        choice = ask("Select option: ")
        if choice is None:
            continue
        try:
            if choice == "1":
                action_search()
            elif choice == "2":
                action_cfx()
            elif choice == "3":
                action_last()
            elif choice == "4":
                action_help()
            elif choice in ("0", "q", "quit", "exit"):
                print(color("\nExiting...", DIM))
                break
            else:
                print(color("[!] Unknown option.", YELLOW))
                time.sleep(0.7)
        except KeyboardInterrupt:
            print(color("\n[*] Back to menu.", YELLOW))
            time.sleep(0.3)


def main() -> int:
    enable_colors()
    try:
        menu()
    except KeyboardInterrupt:
        print(color("\nExiting...", DIM))
    return 0


if __name__ == "__main__":
    sys.exit(main())
