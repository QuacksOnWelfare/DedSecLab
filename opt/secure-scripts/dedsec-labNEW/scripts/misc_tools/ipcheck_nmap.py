#!/usr/bin/env python3
"""IP Surveillance nmap helper. Restricted targets only."""
from __future__ import annotations

import ipaddress
import json
import os
import signal
import subprocess
import time
from pathlib import Path

BASE = Path("/opt/secure-scripts/dedsec-labNEW")
STATE_DIR = BASE / "monitor_state"
SAVE_DIR = BASE / "ip_saves"
BLOCK_EXTRA = [
    "YOUR_VPN_EXIT_FRANCE",  # this VPS
    "YOUR_LAB_VPN_IP",
]

MODES = {
    "top1000": {
        "label": "Top 1000 ports",
        "ports": "--top-ports 1000",
        "est_ports": 1000,
    },
    "high": {
        "label": "Ports 10000-65535",
        "ports": "-p 10000-65535",
        "est_ports": 55536,
    },
}


def client_id(vpn_ip: str) -> str:
    import hashlib
    return hashlib.sha256(vpn_ip.encode()).hexdigest()[:32]


def pid_path(vpn_ip: str) -> Path:
    return STATE_DIR / f"{client_id(vpn_ip)}.nmap.pid"


def out_path(vpn_ip: str) -> Path:
    return STATE_DIR / f"{client_id(vpn_ip)}.nmap.json"


def is_blocked(ip: str) -> str | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid IP"
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
        return "private/reserved address"
    if addr in ipaddress.ip_network("10.8.0.0/24"):
        return "VPN client range"
    if ip in BLOCK_EXTRA:
        return "blocked host (this VPS / gateway)"
    return None


def saved_ips(vpn_ip: str) -> set[str]:
    path = SAVE_DIR / f"{client_id(vpn_ip)}.json"
    if not path.is_file():
        return set()
    try:
        db = json.loads(path.read_text())
    except Exception:
        return set()
    out = set()
    for e in db if isinstance(db, list) else []:
        if isinstance(e, dict) and e.get("ip"):
            out.add(str(e["ip"]).strip())
    return out


def running(vpn_ip: str) -> tuple[bool, int | None]:
    p = pid_path(vpn_ip)
    if not p.is_file():
        return False, None
    try:
        pid = int(p.read_text().strip() or "0")
    except Exception:
        return False, None
    if pid <= 0:
        return False, None
    try:
        os.kill(pid, 0)
        return True, pid
    except OSError:
        try:
            p.unlink()
        except Exception:
            pass
        return False, None


def estimate_seconds(mode: str) -> int:
    n = MODES.get(mode, MODES["top1000"])["est_ports"]
    return max(15, int(n * 0.02))


def stop(vpn_ip: str) -> dict:
    ok, pid = running(vpn_ip)
    if not ok or not pid:
        return {"ok": True, "stopped": False, "reason": "not running"}
    try:
        os.kill(pid, signal.SIGTERM)
        time.sleep(0.4)
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    except OSError:
        pass
    try:
        pid_path(vpn_ip).unlink(missing_ok=True)
    except Exception:
        pass
    return {"ok": True, "stopped": True, "pid": pid}


def start(vpn_ip: str, target: str, mode: str) -> dict:
    target = (target or "").strip()
    mode = (mode or "top1000").strip().lower()
    if mode not in MODES:
        return {"ok": False, "reason": "invalid mode"}
    why = is_blocked(target)
    if why:
        return {"ok": False, "reason": why}
    if target not in saved_ips(vpn_ip):
        return {"ok": False, "reason": "IP is not on your saved list"}
    live, pid = running(vpn_ip)
    if live:
        return {"ok": False, "reason": "scan already running", "pid": pid}

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    spec = MODES[mode]
    cmd = [
        "nmap", "-Pn", "-T3", "--open",
        "-oX", "-",  # xml on stdout parsed later if needed
    ] + spec["ports"].split() + [target]

    # simpler: normal output to a text file
    txt = STATE_DIR / f"{client_id(vpn_ip)}.nmap.txt"
    meta = {
        "target": target,
        "mode": mode,
        "label": spec["label"],
        "started": time.strftime("%Y-%m-%d %H:%M:%S"),
        "est_seconds": estimate_seconds(mode),
        "status": "running",
        "open_ports": [],
    }
    out_path(vpn_ip).write_text(json.dumps(meta, indent=2))

    logf = open(txt, "w")
    proc = subprocess.Popen(
        ["nmap", "-Pn", "-T3", "--open"] + spec["ports"].split() + [target],
        stdout=logf,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    logf.close()
    pid_path(vpn_ip).write_text(str(proc.pid))
    meta["pid"] = proc.pid
    out_path(vpn_ip).write_text(json.dumps(meta, indent=2))
    return {
        "ok": True,
        "started": True,
        "pid": proc.pid,
        "mode": mode,
        "target": target,
        "est_seconds": meta["est_seconds"],
        "label": spec["label"],
    }


def status(vpn_ip: str) -> dict:
    live, pid = running(vpn_ip)
    meta = {}
    op = out_path(vpn_ip)
    if op.is_file():
        try:
            meta = json.loads(op.read_text())
        except Exception:
            meta = {}
    txt = STATE_DIR / f"{client_id(vpn_ip)}.nmap.txt"
    text = txt.read_text() if txt.is_file() else ""
    open_ports = []
    for line in text.splitlines():
        # nmap: "22/tcp open  ssh"
        if "/tcp" in line and " open " in line:
            open_ports.append(line.strip())
        if "/udp" in line and " open " in line:
            open_ports.append(line.strip())
    meta["running"] = live
    meta["pid"] = pid
    meta["open_ports"] = open_ports
    if live:
        meta["status"] = "running"
    elif meta.get("status") == "running":
        meta["status"] = "finished"
        try:
            op.write_text(json.dumps(meta, indent=2))
        except Exception:
            pass
    return {"ok": True, **meta}
