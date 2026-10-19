#!/usr/bin/env python3
"""Shared VPN Discord status reporter. Used by the four region scripts."""
from __future__ import annotations

import json
import os
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from datetime import timedelta

UA = "DedSecVPN-Status/1.0"
CF_DOWN = "https://speed.cloudflare.com/__down?bytes=8000000"
CF_UP = "https://speed.cloudflare.com/__up"
PUBLIC_IP_URLS = (
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
)


def run(cmd: list[str], timeout: int = 8) -> str:
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return (r.stdout or "").strip()
    except Exception:
        return ""


def public_ip() -> str:
    ctx = ssl.create_default_context()
    for url in PUBLIC_IP_URLS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=6, context=ctx) as resp:
                ip = resp.read().decode("utf-8", "ignore").strip()
            if ip and " " not in ip and len(ip) < 48:
                return ip
        except Exception:
            continue
    return ""


def local_ipv4s() -> list[str]:
    out = run(["hostname", "-I"])
    ips = []
    for part in out.split():
        if part.count(".") == 3 and part not in ips:
            ips.append(part)
    return ips


def tun0_ip() -> str:
    out = run(["ip", "-4", "-o", "addr", "show", "dev", "tun0"])
    for tok in out.split():
        if "/" in tok and tok[0].isdigit():
            return tok.split("/", 1)[0]
    return ""


def uptime_text() -> str:
    try:
        raw = open("/proc/uptime", "r", encoding="utf-8").read().split()[0]
        secs = int(float(raw))
    except Exception:
        return "unknown"
    return str(timedelta(seconds=secs))


def service_active(name: str) -> bool:
    return run(["systemctl", "is-active", name], timeout=5).lower() == "active"


def download_mbps(seconds_cap: float = 12.0) -> float | None:
    ctx = ssl.create_default_context()
    req = urllib.request.Request(CF_DOWN, headers={"User-Agent": UA})
    started = time.monotonic()
    total = 0
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            while True:
                chunk = resp.read(64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if time.monotonic() - started >= seconds_cap:
                    break
    except Exception:
        return None
    elapsed = max(time.monotonic() - started, 0.05)
    if total < 100_000:
        return None
    return round((total * 8) / elapsed / 1_000_000, 2)


def upload_mbps(bytes_n: int = 4_000_000, seconds_cap: float = 12.0) -> float | None:
    ctx = ssl.create_default_context()
    payload = os.urandom(bytes_n)
    req = urllib.request.Request(
        CF_UP,
        data=payload,
        method="POST",
        headers={
            "User-Agent": UA,
            "Content-Type": "application/octet-stream",
        },
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            resp.read(64)
    except Exception:
        return None
    elapsed = max(time.monotonic() - started, 0.05)
    if elapsed > seconds_cap + 5:
        return None
    return round((bytes_n * 8) / elapsed / 1_000_000, 2)


def collect(expected_ip: str = "") -> dict:
    pub = public_ip()
    tun = tun0_ip()
    locals_ = local_ipv4s()
    ovpn = service_active("openvpn-server@server") or service_active("openvpn@server")
    api = service_active("dedsec-api")
    ssh = service_active("ssh") or service_active("sshd")
    online = bool(pub) and ovpn
    if expected_ip and pub and pub != expected_ip:
        # Still online, but flag unexpected public IP.
        pass
    dl = download_mbps()
    ul = upload_mbps()
    return {
        "public_ip": pub or "unknown",
        "vpn_ip": tun or "down",
        "local_ips": ", ".join(locals_) or "unknown",
        "uptime": uptime_text(),
        "download": f"{dl} Mbps" if dl is not None else "n/a",
        "upload": f"{ul} Mbps" if ul is not None else "n/a",
        "openvpn": "active" if ovpn else "down",
        "api": "active" if api else "down",
        "ssh": "active" if ssh else "down",
        "hostname": socket.gethostname(),
        "online": online,
    }


def post_webhook(url: str, payload: dict) -> None:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": UA,
        },
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        resp.read()


def build_embed(region: str, info: dict) -> dict:
    online = bool(info.get("online"))
    color = 0x2ECC71 if online else 0xE74C3C
    status = "ONLINE" if online else "OFFLINE"
    title = f"DedSec VPN · {region} · {status}"
    desc = (
        f"Hourly heartbeat from `{info.get('hostname', '?')}`."
        if online
        else f"Services failed on `{info.get('hostname', '?')}`."
    )
    fields = [
        {"name": "Public IP", "value": f"`{info.get('public_ip')}`", "inline": True},
        {"name": "VPN tun0", "value": f"`{info.get('vpn_ip')}`", "inline": True},
        {"name": "Host IPs", "value": f"`{info.get('local_ips')}`", "inline": False},
        {"name": "Download", "value": str(info.get("download")), "inline": True},
        {"name": "Upload", "value": str(info.get("upload")), "inline": True},
        {"name": "Uptime", "value": str(info.get("uptime")), "inline": True},
        {"name": "OpenVPN", "value": str(info.get("openvpn")), "inline": True},
        {"name": "API", "value": str(info.get("api")), "inline": True},
        {"name": "SSH", "value": str(info.get("ssh")), "inline": True},
    ]
    return {
        "username": f"DedSec {region}",
        "embeds": [
            {
                "title": title,
                "description": desc,
                "color": color,
                "fields": fields,
                "footer": {"text": "DedSec Lab · hourly status"},
            }
        ],
    }


def report_once(region: str, webhook: str, expected_ip: str = "") -> int:
    if "PASTE_WEBHOOK" in webhook or not webhook.startswith("https://"):
        print(f"{region}: set WEBHOOK first")
        return 2
    info = collect(expected_ip)
    post_webhook(webhook, build_embed(region, info))
    print(f"{region}: posted {'ONLINE' if info['online'] else 'OFFLINE'}")
    return 0


def loop(region: str, webhook: str, expected_ip: str = "", interval: int = 3600) -> None:
    while True:
        try:
            report_once(region, webhook, expected_ip)
        except Exception as exc:
            print(f"{region}: post failed: {exc}")
            try:
                post_webhook(
                    webhook,
                    build_embed(
                        region,
                        {
                            "public_ip": "unknown",
                            "vpn_ip": "unknown",
                            "local_ips": "unknown",
                            "uptime": uptime_text(),
                            "download": "n/a",
                            "upload": "n/a",
                            "openvpn": "unknown",
                            "api": "unknown",
                            "ssh": "unknown",
                            "hostname": socket.gethostname(),
                            "online": False,
                        },
                    ),
                )
            except Exception:
                pass
        time.sleep(interval)
