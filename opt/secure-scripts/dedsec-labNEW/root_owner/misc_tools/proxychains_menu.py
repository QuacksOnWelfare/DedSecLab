#!/usr/bin/env python3
"""
proxychains_menu.py
Manage proxychains-ng on Linux and run commands through it over an active VPN.

Designed to be launched from an SSH wrapper / menu.py. The wrapper should pass
the current VPN egress IP so this script can verify the tunnel is up before
proxying traffic.

VPN + proxychains path
----------------------
    app  -->  proxychains (LD_PRELOAD)  -->  remote/local proxy
                 \\
                  +--> TCP to the proxy uses the default route (VPN tun)
                       so the proxy sees your VPN IP, not your home IP.

Usage
-----
    python3 proxychains_menu.py
    python3 proxychains_menu.py --vpn-ip 203.0.113.10
    VPN_IP=203.0.113.10 python3 proxychains_menu.py
    python3 proxychains_menu.py --setup
    python3 proxychains_menu.py --status
    python3 proxychains_menu.py --run -- curl https://ifconfig.me
"""

from __future__ import annotations

import argparse
import datetime as _dt
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable, Optional
from urllib.error import URLError
from urllib.request import Request, urlopen


# ---------------------------------------------------------------------------
# Appearance
# ---------------------------------------------------------------------------
class C:
    R = "\033[0m"
    B = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GRN = "\033[32m"
    YEL = "\033[33m"
    BLU = "\033[34m"
    MAG = "\033[35m"
    CYN = "\033[36m"
    WHT = "\033[37m"


def c_enabled() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def paint(code: str, text: str) -> str:
    return f"{code}{text}{C.R}" if c_enabled() else text


def ok(msg: str) -> None:
    print(paint(C.GRN, f"[+] {msg}"))


def warn(msg: str) -> None:
    print(paint(C.YEL, f"[!] {msg}"))


def err(msg: str) -> None:
    print(paint(C.RED, f"[-] {msg}"))


def info(msg: str) -> None:
    print(paint(C.CYN, f"[i] {msg}"))


def header(title: str) -> None:
    line = "─" * 64
    print()
    print(paint(C.B + C.CYN, line))
    print(paint(C.B + C.WHT, f"  {title}"))
    print(paint(C.B + C.CYN, line))


# ---------------------------------------------------------------------------
# Paths / binaries
# ---------------------------------------------------------------------------
HOME = Path(os.path.expanduser("~"))
USER_CONF_DIR = HOME / ".proxychains"
USER_CONF = USER_CONF_DIR / "proxychains.conf"
BACKUP_DIR = USER_CONF_DIR / "backups"
SYSTEM_CONFS = (
    Path("/etc/proxychains4.conf"),
    Path("/etc/proxychains.conf"),
)

CHAIN_TYPES = ("dynamic_chain", "strict_chain", "random_chain", "round_robin_chain")
PROXY_TYPES = ("socks5", "socks4", "http", "raw")
TOGGLE_KEYS = ("proxy_dns", "quiet_mode", "remote_dns_subnet")

IP_ENDPOINTS = (
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
    "https://checkip.amazonaws.com",
)


def which_proxychains() -> Optional[str]:
    for name in ("proxychains4", "proxychains"):
        path = shutil.which(name)
        if path:
            return path
    return None


def resolve_conf_path(explicit: Optional[str] = None) -> Path:
    if explicit:
        return Path(explicit).expanduser()
    env = os.environ.get("PROXYCHAINS_CONF_FILE")
    if env:
        return Path(env).expanduser()
    if USER_CONF.exists():
        return USER_CONF
    for p in SYSTEM_CONFS:
        if p.exists():
            return p
    return USER_CONF


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------
def get_public_ip(timeout: float = 6.0) -> Optional[str]:
    for url in IP_ENDPOINTS:
        try:
            req = Request(url, headers={"User-Agent": "proxychains-menu/1.0"})
            with urlopen(req, timeout=timeout) as resp:
                ip = resp.read().decode("utf-8", "replace").strip()
            if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ip):
                return ip
        except (URLError, TimeoutError, OSError, ValueError):
            continue
    return None


def get_public_ip_via_proxychains(pc_bin: str, conf: Path, timeout: int = 20) -> tuple[Optional[str], str]:
    """Return (ip, combined_output)."""
    cmd = [
        pc_bin,
        "-q",
        "-f",
        str(conf),
        "curl",
        "-sS",
        "--max-time",
        str(timeout),
        "https://api.ipify.org",
    ]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
    except FileNotFoundError:
        return None, "curl not found (install curl)"
    except subprocess.TimeoutExpired:
        return None, "timed out"
    out = ((p.stdout or "") + "\n" + (p.stderr or "")).strip()
    ip = (p.stdout or "").strip()
    if p.returncode == 0 and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ip):
        return ip, out
    return None, out or f"exit {p.returncode}"


def list_tun_ifaces() -> list[tuple[str, str]]:
    """Return [(iface, ipv4), ...] for tun/tap/wg/ppp style interfaces."""
    found: list[tuple[str, str]] = []
    try:
        p = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return found
    for line in p.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        iface = parts[1]
        cidr = parts[3]
        ip = cidr.split("/")[0]
        low = iface.lower()
        if any(low.startswith(p) for p in ("tun", "tap", "wg", "ppp", "nordlynx", "utun")):
            found.append((iface, ip))
    return found


def default_route_dev() -> Optional[str]:
    try:
        p = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"\bdev\s+(\S+)", p.stdout)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# Config model
# ---------------------------------------------------------------------------
class Proxy:
    def __init__(self, ptype: str, host: str, port: int, user: str = "", password: str = "", enabled: bool = True, raw: str = ""):
        self.type = ptype.lower()
        self.host = host
        self.port = int(port)
        self.user = user
        self.password = password
        self.enabled = enabled
        self.raw = raw

    def to_line(self) -> str:
        bits = [self.type, self.host, str(self.port)]
        if self.user:
            bits.append(self.user)
            if self.password:
                bits.append(self.password)
        line = " ".join(bits)
        return line if self.enabled else f"# {line}"

    def display(self, idx: int) -> str:
        state = paint(C.GRN, "ON ") if self.enabled else paint(C.DIM, "OFF")
        auth = f"  user={self.user}" if self.user else ""
        return f"  {idx:2d}. [{state}] {self.type:6s} {self.host}:{self.port}{auth}"


PROXY_RE = re.compile(
    r"^(?P<hash>#\s*)?(?P<type>socks5|socks4|http|raw)\s+"
    r"(?P<host>\S+)\s+(?P<port>\d+)(?:\s+(?P<user>\S+)(?:\s+(?P<pass>\S+))?)?\s*$",
    re.I,
)


class ProxyChainsConf:
    def __init__(self, path: Path):
        self.path = path
        self.lines: list[str] = []
        self.chain_type = "dynamic_chain"
        self.proxy_dns = True
        self.quiet_mode = False
        self.tcp_read_time_out = 15000
        self.tcp_connect_time_out = 8000
        self.chain_len: Optional[int] = None
        self.proxies: list[Proxy] = []

    def load(self) -> None:
        if not self.path.exists():
            self.lines = DEFAULT_TEMPLATE.splitlines(keepends=True)
            self._parse()
            return
        self.lines = self.path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        self._parse()

    def _parse(self) -> None:
        self.proxies = []
        in_list = False
        found_chain = None
        self.proxy_dns = False
        self.quiet_mode = False
        self.chain_len = None
        for line in self.lines:
            raw = line.rstrip("\n")
            stripped = raw.strip()
            low = stripped.lower()

            if stripped.startswith("[ProxyList]"):
                in_list = True
                continue

            if not in_list:
                for ct in CHAIN_TYPES:
                    if low == ct:
                        found_chain = ct
                if low == "proxy_dns":
                    self.proxy_dns = True
                if low == "quiet_mode":
                    self.quiet_mode = True
                m = re.match(r"^tcp_read_time_out\s+(\d+)", low)
                if m:
                    self.tcp_read_time_out = int(m.group(1))
                m = re.match(r"^tcp_connect_time_out\s+(\d+)", low)
                if m:
                    self.tcp_connect_time_out = int(m.group(1))
                m = re.match(r"^#?\s*chain_len\s*=\s*(\d+)", low)
                if m and not stripped.startswith("#"):
                    self.chain_len = int(m.group(1))
            else:
                if not stripped:
                    continue
                m = PROXY_RE.match(stripped)
                if m:
                    self.proxies.append(
                        Proxy(
                            ptype=m.group("type"),
                            host=m.group("host"),
                            port=int(m.group("port")),
                            user=m.group("user") or "",
                            password=m.group("pass") or "",
                            enabled=m.group("hash") is None,
                            raw=stripped,
                        )
                    )
        if found_chain:
            self.chain_type = found_chain

    def _set_flag(self, key: str, enabled: bool) -> None:
        """Comment / uncomment a top-level keyword, inserting it if missing."""
        new_lines: list[str] = []
        seen = False
        pattern = re.compile(rf"^#?\s*{re.escape(key)}\b.*$", re.I)
        for line in self.lines:
            if pattern.match(line.strip("\n").strip()) and "[ProxyList]" not in "".join(new_lines[-3:]):
                # only rewrite before [ProxyList]
                if not seen:
                    new_lines.append(f"{key}\n" if enabled else f"# {key}\n")
                    seen = True
                continue
            new_lines.append(line)
        if not seen:
            # insert before [ProxyList]
            inserted = False
            out: list[str] = []
            for line in new_lines:
                if line.strip().startswith("[ProxyList]") and not inserted:
                    out.append(f"{key}\n" if enabled else f"# {key}\n")
                    out.append("\n")
                    inserted = True
                out.append(line)
            if not inserted:
                out.append(f"{key}\n" if enabled else f"# {key}\n")
            new_lines = out
        self.lines = new_lines

    def _set_kv(self, key: str, value: str) -> None:
        pattern = re.compile(rf"^#?\s*{re.escape(key)}\b.*$", re.I)
        new_lines: list[str] = []
        seen = False
        for line in self.lines:
            if pattern.match(line.strip("\n").strip()):
                if not seen:
                    new_lines.append(f"{key} {value}\n")
                    seen = True
                continue
            new_lines.append(line)
        if not seen:
            out: list[str] = []
            for line in new_lines:
                if line.strip().startswith("[ProxyList]") and not seen:
                    out.append(f"{key} {value}\n")
                    seen = True
                out.append(line)
            new_lines = out
        self.lines = new_lines

    def apply_chain_type(self, chain: str) -> None:
        if chain not in CHAIN_TYPES:
            raise ValueError(f"unknown chain type: {chain}")
        self.chain_type = chain
        new_lines: list[str] = []
        seen_any = False
        for line in self.lines:
            s = line.strip()
            low = s.lstrip("#").strip().split()[0].lower() if s else ""
            if low in CHAIN_TYPES:
                # collapse all chain-type lines into a single active one (first occurrence)
                if not seen_any:
                    new_lines.append(f"{chain}\n")
                    seen_any = True
                # drop other chain-type lines (keep surrounding comments)
                continue
            new_lines.append(line)
        if not seen_any:
            out: list[str] = []
            for line in new_lines:
                if line.strip().startswith("[ProxyList]"):
                    out.append(f"{chain}\n\n")
                out.append(line)
            new_lines = out
        self.lines = new_lines

    def apply_settings(self) -> None:
        self.apply_chain_type(self.chain_type)
        self._set_flag("proxy_dns", self.proxy_dns)
        self._set_flag("quiet_mode", self.quiet_mode)
        self._set_kv("tcp_read_time_out", str(self.tcp_read_time_out))
        self._set_kv("tcp_connect_time_out", str(self.tcp_connect_time_out))
        self._rewrite_proxylist()

    def _rewrite_proxylist(self) -> None:
        out: list[str] = []
        in_list = False
        wrote_list = False
        for line in self.lines:
            if line.strip().startswith("[ProxyList]"):
                in_list = True
                out.append("[ProxyList]\n")
                for px in self.proxies:
                    out.append(px.to_line() + "\n")
                wrote_list = True
                continue
            if in_list:
                # drop old proxy entries / comments that look like proxies; keep other comments
                s = line.strip()
                if PROXY_RE.match(s) or s.startswith("# socks") or s.startswith("# http") or s.startswith("# raw"):
                    continue
                if s.startswith("#") or s == "":
                    # keep decorative comments after list? skip to keep file tidy
                    continue
                # unexpected non-proxy content after list - keep it
                out.append(line)
                continue
            out.append(line)
        if not wrote_list:
            out.append("\n[ProxyList]\n")
            for px in self.proxies:
                out.append(px.to_line() + "\n")
        self.lines = out

    def save(self, backup: bool = True) -> Path:
        self.apply_settings()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if backup and self.path.exists():
            BACKUP_DIR.mkdir(parents=True, exist_ok=True)
            stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
            dest = BACKUP_DIR / f"{self.path.name}.{stamp}"
            shutil.copy2(self.path, dest)
        data = "".join(self.lines)
        if not data.endswith("\n"):
            data += "\n"
        fd, tmp = tempfile.mkstemp(prefix=".pc-", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(data)
            os.replace(tmp, self.path)
            os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return self.path


DEFAULT_TEMPLATE = """\
# proxychains.conf  VER 4.x  - managed by proxychains_menu.py
#
# Traffic path when a VPN is up:
#   app -> proxychains -> proxy-server   (that TCP hop uses the VPN default route)
# The proxy therefore sees your VPN IP, not your home IP.

dynamic_chain
#strict_chain
#random_chain
#round_robin_chain

#chain_len = 2

proxy_dns
#quiet_mode

remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000

localnet 127.0.0.0/255.0.0.0

[ProxyList]
# type  host  port  [user  pass]
# socks5 127.0.0.1 9050
# socks5 127.0.0.1 1080
"""


# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
def run_cmd(cmd: list[str], check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check)


def setup(conf_path: Path) -> int:
    header("ProxyChains setup")
    pc = which_proxychains()
    if pc:
        ok(f"proxychains already installed: {pc}")
    else:
        info("proxychains not found - installing proxychains4 via apt")
        if os.geteuid() != 0 and not shutil.which("sudo"):
            err("Need root or sudo to install packages.")
            err("Install manually:  sudo apt update && sudo apt install -y proxychains4 curl")
            return 1
        apt = ["apt-get", "update"]
        inst = ["apt-get", "install", "-y", "proxychains4", "curl"]
        if os.geteuid() != 0:
            apt = ["sudo"] + apt
            inst = ["sudo"] + inst
        print(paint(C.DIM, "  running apt-get update ..."))
        r = run_cmd(apt)
        if r.returncode != 0:
            err("apt-get update failed")
            return 1
        r = run_cmd(inst)
        if r.returncode != 0:
            err("failed to install proxychains4 / curl")
            return 1
        pc = which_proxychains()
        if not pc:
            err("package installed but proxychains4 binary still not on PATH")
            return 1
        ok(f"installed {pc}")

    if not shutil.which("curl"):
        warn("curl not found - IP tests will use Python urllib only")

    USER_CONF_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    if conf_path.exists():
        info(f"config already exists: {conf_path}")
        overwrite = False
        if sys.stdin.isatty():
            ans = input("Overwrite with a clean managed template? [y/N]: ").strip().lower()
            overwrite = ans == "y"
        if overwrite:
            cfg = ProxyChainsConf(conf_path)
            cfg.lines = DEFAULT_TEMPLATE.splitlines(keepends=True)
            cfg._parse()
            cfg.save(backup=True)
            ok(f"wrote fresh template (backup kept in {BACKUP_DIR})")
        else:
            info("kept existing config")
    else:
        conf_path.parent.mkdir(parents=True, exist_ok=True)
        conf_path.write_text(DEFAULT_TEMPLATE, encoding="utf-8")
        os.chmod(conf_path, 0o644)
        ok(f"wrote {conf_path}")

    info("Default Tor line is commented out so a missing tor daemon will not break the chain.")
    info("Add proxies from the menu. Prefer socks5 + proxy_dns to avoid DNS leaks.")
    print()
    print("Wrapper hook (drop into menu.py):")
    print(paint(C.DIM, """
    import subprocess, sys
    def run_proxychains_menu(vpn_ip: str) -> None:
        script = "/path/to/proxychains_menu.py"   # <-- change me
        subprocess.run([sys.executable, script, "--vpn-ip", vpn_ip])
"""))
    ok("setup complete")
    return 0


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
class App:
    def __init__(self, vpn_ip: Optional[str], conf: Path):
        self.vpn_ip = vpn_ip
        self.conf_path = conf
        self.cfg = ProxyChainsConf(conf)
        self.cfg.load()

    def reload(self) -> None:
        self.cfg.load()

    # ----- status ----------------------------------------------------------
    def print_status(self, probe_net: bool = True) -> None:
        header("Status")
        pc = which_proxychains()
        print(f"  proxychains binary : {pc or paint(C.RED, 'NOT INSTALLED')}")
        print(f"  config file        : {self.conf_path}" + ("  (missing)" if not self.conf_path.exists() else ""))
        print(f"  chain type         : {self.cfg.chain_type}")
        print(f"  proxy_dns          : {self.cfg.proxy_dns}")
        print(f"  quiet_mode         : {self.cfg.quiet_mode}")
        print(f"  tcp timeouts       : read={self.cfg.tcp_read_time_out}  connect={self.cfg.tcp_connect_time_out}")
        enabled = [p for p in self.cfg.proxies if p.enabled]
        print(f"  proxies            : {len(enabled)} enabled / {len(self.cfg.proxies)} total")

        tuns = list_tun_ifaces()
        dev = default_route_dev()
        print(f"  default route dev  : {dev or '?'}")
        if tuns:
            print("  VPN-like ifaces    : " + ", ".join(f"{i}={ip}" for i, ip in tuns))
        else:
            print("  VPN-like ifaces    : none detected (tun/wg/ppp)")

        passed = self.vpn_ip or paint(C.YEL, "(not passed by wrapper)")
        print(f"  VPN IP from wrapper: {passed}")

        if not probe_net:
            return

        info("probing current public IP (direct, should be VPN if tunnel is up) ...")
        direct = get_public_ip()
        if direct:
            print(f"  current public IP  : {direct}")
            if self.vpn_ip:
                if direct == self.vpn_ip:
                    ok("direct egress matches wrapper VPN IP - tunnel looks good")
                else:
                    warn(f"direct egress {direct} != wrapper VPN IP {self.vpn_ip}")
                    warn("proxychains will still ride the default route; confirm the VPN is the default.")
        else:
            warn("could not fetch public IP (no net / blocked IP services)")

        if pc and enabled and self.conf_path.exists():
            info("probing public IP THROUGH proxychains ...")
            pip, raw = get_public_ip_via_proxychains(pc, self.conf_path)
            if pip:
                print(f"  proxied public IP  : {pip}")
                if self.vpn_ip and pip == self.vpn_ip:
                    warn("proxied IP equals VPN IP - proxy is not changing egress (dead proxy or bypass)")
                else:
                    ok("proxied egress differs from direct - chain is applying")
            else:
                warn(f"proxychains IP check failed: {raw[:200]}")

    # ----- proxy list ------------------------------------------------------
    def list_proxies(self) -> None:
        header(f"Proxy list  ({self.conf_path})")
        if not self.cfg.proxies:
            warn("no proxies configured")
            return
        for i, px in enumerate(self.cfg.proxies, 1):
            print(px.display(i))

    def add_proxy(self, ptype: Optional[str] = None, host: Optional[str] = None, port: Optional[int] = None, user: str = "", password: str = "") -> None:
        if not ptype:
            ptype = prompt("type [socks5/socks4/http/raw]", default="socks5").lower()
        if ptype not in PROXY_TYPES:
            err(f"invalid type {ptype}")
            return
        if not host:
            host = prompt("host / IP").strip()
        if not host:
            err("host required")
            return
        if port is None:
            raw = prompt("port", default="1080").strip()
            try:
                port = int(raw)
            except ValueError:
                err("invalid port")
                return
        if not user:
            user = prompt("username (blank = none)", default="").strip()
        if user and not password:
            password = prompt("password", default="").strip()
        self.cfg.proxies.append(Proxy(ptype, host, int(port), user, password, enabled=True))
        self.cfg.save()
        ok(f"added {ptype} {host}:{port}")

    def remove_proxy(self) -> None:
        self.list_proxies()
        if not self.cfg.proxies:
            return
        raw = prompt("number to remove (or blank to cancel)").strip()
        if not raw:
            return
        try:
            idx = int(raw)
            px = self.cfg.proxies.pop(idx - 1)
        except (ValueError, IndexError):
            err("invalid selection")
            return
        self.cfg.save()
        ok(f"removed {px.type} {px.host}:{px.port}")

    def toggle_proxy(self) -> None:
        self.list_proxies()
        if not self.cfg.proxies:
            return
        raw = prompt("number to toggle ON/OFF").strip()
        try:
            idx = int(raw)
            px = self.cfg.proxies[idx - 1]
        except (ValueError, IndexError):
            err("invalid selection")
            return
        px.enabled = not px.enabled
        self.cfg.save()
        ok(f"{px.host}:{px.port} -> {'ON' if px.enabled else 'OFF'}")

    def set_chain_type(self) -> None:
        print("  1) dynamic_chain      skip dead proxies (recommended)")
        print("  2) strict_chain       every hop must work, in order")
        print("  3) random_chain       pick at random")
        print("  4) round_robin_chain  rotate through the list")
        raw = prompt("choice", default="1").strip()
        mapping = {"1": "dynamic_chain", "2": "strict_chain", "3": "random_chain", "4": "round_robin_chain"}
        chain = mapping.get(raw, raw if raw in CHAIN_TYPES else None)
        if not chain:
            err("invalid choice")
            return
        self.cfg.chain_type = chain
        self.cfg.save()
        ok(f"chain type = {chain}")

    def toggle_proxy_dns(self) -> None:
        self.cfg.proxy_dns = not self.cfg.proxy_dns
        self.cfg.save()
        ok(f"proxy_dns = {self.cfg.proxy_dns}")

    def toggle_quiet(self) -> None:
        self.cfg.quiet_mode = not self.cfg.quiet_mode
        self.cfg.save()
        ok(f"quiet_mode = {self.cfg.quiet_mode}")

    def set_timeouts(self) -> None:
        try:
            r = int(prompt("tcp_read_time_out ms", default=str(self.cfg.tcp_read_time_out)))
            c = int(prompt("tcp_connect_time_out ms", default=str(self.cfg.tcp_connect_time_out)))
        except ValueError:
            err("numbers only")
            return
        self.cfg.tcp_read_time_out = r
        self.cfg.tcp_connect_time_out = c
        self.cfg.save()
        ok("timeouts updated")

    def import_file(self) -> None:
        path = Path(prompt("file with lines: type host port [user pass]")).expanduser()
        if not path.exists():
            err("file not found")
            return
        added = 0
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            m = PROXY_RE.match(s)
            if not m:
                warn(f"skip: {s}")
                continue
            self.cfg.proxies.append(
                Proxy(m.group("type"), m.group("host"), int(m.group("port")), m.group("user") or "", m.group("pass") or "", enabled=True)
            )
            added += 1
        self.cfg.save()
        ok(f"imported {added} proxies")

    def export_file(self) -> None:
        path = Path(prompt("export path", default=str(USER_CONF_DIR / "proxylist.txt"))).expanduser()
        path.write_text("".join(p.to_line() + "\n" for p in self.cfg.proxies if p.enabled), encoding="utf-8")
        ok(f"wrote {path}")

    def edit_raw(self) -> None:
        editor = os.environ.get("EDITOR") or shutil.which("nano") or shutil.which("vi") or "vi"
        subprocess.run([editor, str(self.conf_path)])
        self.reload()
        ok("reloaded config")

    # ----- tests / run -----------------------------------------------------
    def require_ready(self) -> Optional[str]:
        pc = which_proxychains()
        if not pc:
            err("proxychains is not installed. Run setup first (option 1 / --setup).")
            return None
        if not self.conf_path.exists():
            err(f"config missing: {self.conf_path}")
            return None
        if not any(p.enabled for p in self.cfg.proxies):
            err("no enabled proxies in the list")
            return None
        return pc

    def vpn_preflight(self) -> bool:
        if not self.vpn_ip:
            warn("wrapper did not pass a VPN IP - skipping match check")
            return True
        direct = get_public_ip()
        if not direct:
            warn("could not verify public IP")
            return True
        if direct != self.vpn_ip:
            warn(f"current public IP {direct} != expected VPN IP {self.vpn_ip}")
            ans = prompt("continue anyway?", default="n").strip().lower()
            return ans in ("y", "yes")
        ok(f"VPN confirmed ({direct})")
        return True

    def test_chain(self) -> None:
        pc = self.require_ready()
        if not pc:
            return
        if not self.vpn_preflight():
            return
        header("IP comparison")
        direct = get_public_ip()
        print(f"  wrapper VPN IP : {self.vpn_ip or '-'}")
        print(f"  direct public  : {direct or '-'}")
        pip, raw = get_public_ip_via_proxychains(pc, self.conf_path)
        print(f"  proxied public : {pip or '-'}")
        if not pip:
            err("proxied check failed:")
            print(paint(C.DIM, raw[:800]))
            return
        if self.vpn_ip and direct and direct != self.vpn_ip:
            warn("direct IP is not the VPN IP you passed - tunnel may be down")
        if pip == direct:
            warn("proxied IP == direct IP; the chain did not change egress")
        else:
            ok("chain is live - destination will see the proxy IP")

    def run_command(self, argv: Optional[list[str]] = None) -> int:
        pc = self.require_ready()
        if not pc:
            return 1
        if not self.vpn_preflight():
            return 1
        if not argv:
            raw = prompt("command to wrap (e.g. curl https://ifconfig.me)").strip()
            if not raw:
                return 1
            argv = ["bash", "-lc", raw]
        env = os.environ.copy()
        env["PROXYCHAINS_CONF_FILE"] = str(self.conf_path)
        cmd = [pc, "-f", str(self.conf_path), *argv]
        info("running: " + " ".join(cmd))
        return subprocess.call(cmd, env=env)

    def open_conf_path_menu(self) -> None:
        print(f"  current: {self.conf_path}")
        print("  1) ~/.proxychains/proxychains.conf  (recommended, no sudo)")
        print("  2) /etc/proxychains4.conf")
        print("  3) custom path")
        raw = prompt("choice", default="1").strip()
        if raw == "1":
            self.conf_path = USER_CONF
        elif raw == "2":
            self.conf_path = Path("/etc/proxychains4.conf")
        elif raw == "3":
            self.conf_path = Path(prompt("path")).expanduser()
        else:
            return
        os.environ["PROXYCHAINS_CONF_FILE"] = str(self.conf_path)
        self.cfg = ProxyChainsConf(self.conf_path)
        self.cfg.load()
        ok(f"now using {self.conf_path}")

    # ----- menu ------------------------------------------------------------
    def menu(self) -> int:
        while True:
            header("ProxyChains manager")
            vpn = self.vpn_ip or "not passed"
            print(paint(C.DIM, f"  VPN IP: {vpn}    conf: {self.conf_path}"))
            print(
                """
  1) Setup / install proxychains4
  2) Status (VPN + direct IP + proxied IP)
  3) List proxies
  4) Add proxy
  5) Remove proxy
  6) Enable / disable proxy
  7) Set chain type
  8) Toggle proxy_dns
  9) Toggle quiet_mode
 10) Set TCP timeouts
 11) Import proxy list file
 12) Export enabled proxies
 13) Edit config in $EDITOR
 14) Test chain (IP check over VPN)
 15) Run a command through proxychains
 16) Switch config file
  q) Quit
"""
            )
            choice = prompt("select").strip().lower()
            try:
                if choice in ("q", "quit", "exit"):
                    return 0
                if choice == "1":
                    setup(self.conf_path)
                    self.reload()
                elif choice == "2":
                    self.print_status(probe_net=True)
                elif choice == "3":
                    self.list_proxies()
                elif choice == "4":
                    self.add_proxy()
                elif choice == "5":
                    self.remove_proxy()
                elif choice == "6":
                    self.toggle_proxy()
                elif choice == "7":
                    self.set_chain_type()
                elif choice == "8":
                    self.toggle_proxy_dns()
                elif choice == "9":
                    self.toggle_quiet()
                elif choice == "10":
                    self.set_timeouts()
                elif choice == "11":
                    self.import_file()
                elif choice == "12":
                    self.export_file()
                elif choice == "13":
                    self.edit_raw()
                elif choice == "14":
                    self.test_chain()
                elif choice == "15":
                    self.run_command()
                elif choice == "16":
                    self.open_conf_path_menu()
                else:
                    warn("unknown selection")
            except KeyboardInterrupt:
                print()
                warn("cancelled")
            except Exception as exc:
                err(f"{type(exc).__name__}: {exc}")


def prompt(label: str, default: Optional[str] = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    try:
        val = input(paint(C.MAG, f"  {label}{suffix}: ")).strip()
    except EOFError:
        return default or ""
    return val if val else (default or "")


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Manage proxychains over a VPN. Accepts VPN IP from menu.py / SSH wrapper.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""environment:
  VPN_IP / MY_VPN_IP / WRAPPER_VPN_IP   VPN egress IP from the wrapper
  PROXYCHAINS_CONF_FILE                 config path override
""",
    )
    p.add_argument("--vpn-ip", dest="vpn_ip", help="VPN public/egress IP passed by menu.py")
    p.add_argument("--conf", help="proxychains config path")
    p.add_argument("--setup", action="store_true", help="install proxychains4 and write user config")
    p.add_argument("--status", action="store_true", help="print status and exit")
    p.add_argument("--test", action="store_true", help="IP-check the chain and exit")
    p.add_argument("--add", nargs="+", metavar="ARG", help="add proxy: TYPE HOST PORT [USER PASS]")
    p.add_argument("--list", action="store_true", help="list proxies and exit")
    p.add_argument("--run", action="store_true", help="run remaining args through proxychains (use -- )")
    p.add_argument("rest", nargs=argparse.REMAINDER, help="command after -- for --run")
    return p.parse_args(argv)


def pick_vpn_ip(args: argparse.Namespace) -> Optional[str]:
    if args.vpn_ip:
        return args.vpn_ip.strip()
    for key in ("VPN_IP", "MY_VPN_IP", "WRAPPER_VPN_IP", "VPNIP"):
        val = os.environ.get(key)
        if val:
            return val.strip()
    # positional leftover that looks like an IPv4 (wrapper might pass it bare)
    return None


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    vpn_ip = pick_vpn_ip(args)
    conf = resolve_conf_path(args.conf)

    if args.setup:
        # Always manage the user config unless --conf was given.
        setup_path = Path(args.conf).expanduser() if args.conf else USER_CONF
        return setup(setup_path)

    app = App(vpn_ip=vpn_ip, conf=conf)

    if args.add:
        parts = args.add
        if len(parts) < 3:
            err("--add TYPE HOST PORT [USER PASS]")
            return 2
        app.add_proxy(
            ptype=parts[0],
            host=parts[1],
            port=int(parts[2]),
            user=parts[3] if len(parts) > 3 else "",
            password=parts[4] if len(parts) > 4 else "",
        )
        return 0
    if args.list:
        app.list_proxies()
        return 0
    if args.status:
        app.print_status(probe_net=True)
        return 0
    if args.test:
        app.test_chain()
        return 0
    if args.run:
        cmd = args.rest
        if cmd and cmd[0] == "--":
            cmd = cmd[1:]
        if not cmd:
            err("usage: proxychains_menu.py --vpn-ip IP --run -- curl https://ifconfig.me")
            return 2
        return app.run_command(cmd)

    return app.menu()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
