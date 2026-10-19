#!/usr/bin/env python3
"""
DEDSEC LAB · Owner SSH Guard
Block attackers, inspect SSH logs, switch 22 ↔ 51222.
"""
from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

SSHD_CONFIG = Path("/etc/ssh/sshd_config")
SOCKET_DROPIN = Path("/etc/systemd/system/ssh.socket.d/override.conf")
BLOCKLIST_FILE = Path("/root/.dedsec-ssh-guard/blocked.txt")
HIGH_PORT = 51222
LOW_PORT = 22

RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
DIM = "\033[2m"

FAIL_RE = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}T[\d:.+-]+|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r".*?(?:Failed password|Invalid user|authentication failure).*?"
    r"(?:user (?P<user1>\S+)\s+)?"
    r"(?:for (?:invalid user )?(?P<user2>\S+)\s+)?"
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
    re.I,
)
ACCEPT_RE = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}T[\d:.+-]+|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r".*?Accepted (?P<method>password|publickey|keyboard-interactive)"
    r" for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
    re.I,
)
INVALID_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
    re.I,
)
IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def color(text, c):
    return f"{c}{text}{RESET}"


def clear():
    os.system("clear" if os.name != "nt" else "cls")


def pause(msg="Press Enter..."):
    try:
        input(color(f"\n{msg}", DIM))
    except (KeyboardInterrupt, EOFError):
        raise KeyboardInterrupt


def run(cmd, check=False, timeout=20):
    return subprocess.run(
        cmd, text=True, capture_output=True, check=check, timeout=timeout
    )


def banner(page="MONITOR"):
    clear()
    print(color("=" * 56, CYAN))
    print(color("  DEDSEC LAB  ·  OWNER  ·  SSH GUARD", BOLD + CYAN))
    print(color("=" * 56, CYAN))
    ports = current_ports()
    active = ssh_active()
    print(color(f"  ssh.service : {active}", GREEN if active == "active" else RED))
    print(color(f"  listening   : {ports or 'none'}", CYAN))
    print(color(f"  blocked IPs : {len(list_blocked())}", YELLOW))
    print(color(f"  page        : {page}", MAGENTA))
    print(color("-" * 56, DIM))


def require_root():
    if os.geteuid() != 0:
        raise SystemExit("Run as root.")


# ---------- SSH port switch ----------
def current_ports():
    ports = []
    out = run(["ss", "-tlnH"]).stdout or ""
    for line in out.splitlines():
        if re.search(r":22\b", line) and "51222" not in line.split(":")[-1][:2]:
            if ":22 " in line or line.rstrip().endswith(":22"):
                ports.append(22)
        if ":51222" in line:
            ports.append(HIGH_PORT)
    return sorted(set(ports))


def ssh_active():
    return (run(["systemctl", "is-active", "ssh"]).stdout or "").strip()


def set_sshd_port(port: int):
    text = SSHD_CONFIG.read_text(encoding="utf-8")
    text = re.sub(r"(?m)^Port[ \t]+\d+[ \t]*\n?", "", text)
    SSHD_CONFIG.write_text(f"Port {port}\n" + text.lstrip("\n"), encoding="utf-8")


def set_socket_port(port: int):
    SOCKET_DROPIN.parent.mkdir(parents=True, exist_ok=True)
    SOCKET_DROPIN.write_text(
        "[Socket]\n"
        "ListenStream=\n"
        f"ListenStream=0.0.0.0:{port}\n"
        f"ListenStream=[::]:{port}\n",
        encoding="utf-8",
    )


def open_firewall_port(port: int):
    run(["ufw", "allow", f"{port}/tcp"])
    chk = run(
        ["iptables", "-C", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"]
    )
    if chk.returncode != 0:
        run(["iptables", "-I", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"])


def apply_ssh_port(port: int):
    set_sshd_port(port)
    test = run(["sshd", "-t"])
    if test.returncode != 0:
        raise RuntimeError((test.stderr or test.stdout or "sshd -t failed").strip())
    set_socket_port(port)
    open_firewall_port(port)
    run(["systemctl", "daemon-reload"])
    r1 = run(["systemctl", "restart", "ssh.socket"])
    r2 = run(["systemctl", "restart", "ssh"])
    if r2.returncode != 0:
        raise RuntimeError((r2.stderr or r2.stdout or "ssh.service failed").strip())
    if r1.returncode != 0:
        print(color(f"socket warning: {(r1.stderr or '').strip()}", YELLOW))


# ---------- firewall / blocklist ----------
def valid_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.strip())
        return addr.version == 4 and not addr.is_loopback
    except Exception:
        return False


def is_blocked(ip: str) -> bool:
    r = run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"])
    return r.returncode == 0


def list_blocked() -> list[str]:
    out = run(["iptables", "-S", "INPUT"]).stdout or ""
    found = []
    for line in out.splitlines():
        m = re.search(r"-A INPUT -s (\d+\.\d+\.\d+\.\d+)(?:/\d+)? -j DROP", line)
        if m:
            found.append(m.group(1))
    return found


def remember_block(ip: str):
    BLOCKLIST_FILE.parent.mkdir(parents=True, exist_ok=True)
    existing = set()
    if BLOCKLIST_FILE.exists():
        existing = {x.strip() for x in BLOCKLIST_FILE.read_text().splitlines() if x.strip()}
    existing.add(ip)
    BLOCKLIST_FILE.write_text("\n".join(sorted(existing)) + "\n")


def forget_block(ip: str):
    if not BLOCKLIST_FILE.exists():
        return
    lines = [x.strip() for x in BLOCKLIST_FILE.read_text().splitlines() if x.strip() and x.strip() != ip]
    BLOCKLIST_FILE.write_text(("\n".join(lines) + "\n") if lines else "")


def block_ip(ip: str) -> str:
    ip = ip.strip()
    if not valid_ip(ip):
        return "invalid IPv4"
    if is_blocked(ip):
        remember_block(ip)
        return "already blocked"
    run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
    run(["ufw", "deny", "from", ip])
    remember_block(ip)
    return "blocked"


def unblock_ip(ip: str) -> str:
    ip = ip.strip()
    if not valid_ip(ip):
        return "invalid IPv4"
    while is_blocked(ip):
        run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
    run(["ufw", "delete", "deny", "from", ip])
    forget_block(ip)
    return "unblocked"


def persist_iptables():
    Path("/etc/iptables").mkdir(parents=True, exist_ok=True)
    saved = run(["iptables-save"])
    if saved.returncode == 0 and saved.stdout:
        Path("/etc/iptables/rules.v4").write_text(saved.stdout)
        run(["netfilter-persistent", "save"])
        return True
    return False


# ---------- logs ----------
def auth_text(hours: int = 24, extra_grep: str = "") -> str:
    chunks = []
    cmd = [
        "journalctl", "-u", "ssh", "--no-pager", "-o", "short-iso",
        f"--since={hours} hours ago",
    ]
    if extra_grep:
        cmd += ["-g", extra_grep]
    j = run(cmd, timeout=30)
    if j.stdout:
        chunks.append(j.stdout)
    for path in ("/var/log/auth.log", "/var/log/auth.log.1"):
        p = Path(path)
        if p.exists():
            try:
                chunks.append(p.read_text(errors="replace")[-400000:])
            except Exception:
                pass
    return "\n".join(chunks)


def parse_fails(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        if "sudo:" in line:
            continue
        m = FAIL_RE.search(line) or INVALID_RE.search(line)
        if not m:
            continue
        ip = m.groupdict().get("ip") or ""
        user = m.groupdict().get("user") or m.groupdict().get("user1") or m.groupdict().get("user2") or "?"
        if not ip:
            found = IP_RE.search(line)
            ip = found.group(1) if found else ""
        if not ip:
            continue
        rows.append({"ip": ip, "user": user, "line": line.strip()[:220]})
    return rows


def parse_accepts(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        m = ACCEPT_RE.search(line)
        if not m:
            continue
        rows.append({
            "ip": m.group("ip"),
            "user": m.group("user"),
            "method": m.group("method"),
            "line": line.strip()[:220],
        })
    return rows


def skip_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except Exception:
        return True


def top_attackers(fails: list[dict], n=8) -> list[tuple[str, int]]:
    return Counter(r["ip"] for r in fails if not skip_ip(r["ip"])).most_common(n)


def print_table_attackers(items):
    blocked = set(list_blocked())
    print(color(f"  {'#':<4}{'COUNT':<8}{'IP':<18}{'STATE'}", DIM))
    for i, (ip, count) in enumerate(items, 1):
        state = color("BLOCKED", RED) if ip in blocked else color("open", GREEN)
        print(f"  {i:<4}{count:<8}{ip:<18}{state}")


# ---------- screens ----------
def show_accepts():
    banner("ACCEPTED LOGINS")
    accepts = parse_accepts(auth_text(48))
    print(color(f"  last {min(25, len(accepts))} of {len(accepts)}", DIM))
    print()
    for row in accepts[-25:]:
        print(f"  {row['user']:<12} {row['method']:<10} {row['ip']}")
    pause()


def show_monitor():
    banner("MONITOR")
    text = auth_text(48)
    fails = parse_fails(text)
    accepts = parse_accepts(text)
    print(color(f"  Failed : {len(fails)}     Accepted : {len(accepts)}", DIM))
    print()
    print(color("  TOP SOURCE IPs  (VPN/private hidden)", BOLD + MAGENTA))
    top = top_attackers(fails)
    if not top:
        print(color("  none in last 48h", DIM))
    else:
        print_table_attackers(top)
    print()
    print("  1. Block list #")
    print("  2. Block typed IP")
    print("  3. Failed lines")
    print("  4. Search IP")
    print("  5. Usernames tried")
    print("  6. Accepted logins")
    print("  7. Firewall")
    print("  8. SSH port")
    print("  9. Refresh")
    print("  0. Exit")
    return top



def show_usernames():
    banner("USERNAMES TRIED")
    print(color("  OpenSSH does not log passwords - only usernames.", DIM))
    fails = parse_fails(auth_text(48))
    users = Counter((r.get("user") or "?").strip() or "?" for r in fails)
    print(color(f"  unique users: {len(users)}   attempts: {len(fails)}", YELLOW))
    print()
    print(color(f"  {'#':<4}{'COUNT':<8}USER", DIM))
    for i, (user, n) in enumerate(users.most_common(40), 1):
        print(f"  {i:<4}{n:<8}{user}")
    print()
    print(color("  last 20  IP + user", DIM))
    for row in fails[-20:]:
        print(f"  {row['ip']:<16} {row['user']}")
    pause()

def show_fails():
    banner("FAILED LOGINS")
    fails = parse_fails(auth_text(48))
    print(color(f"  showing last {min(40, len(fails))} of {len(fails)}", DIM))
    print()
    for row in fails[-40:]:
        print(color(f"  {row['ip']:<16} {row['user']:<16}", YELLOW) + DIM + row["line"][-70:] + RESET)
    pause()


def search_ip():
    banner("SEARCH")
    ip = input(color("IP to search: ", CYAN)).strip()
    if not valid_ip(ip):
        print(color("Not a valid IPv4.", RED))
        pause()
        return
    print()
    print(color(f"  blocked: {is_blocked(ip)}", YELLOW if is_blocked(ip) else GREEN))
    text = auth_text(168, extra_grep=ip)
    lines = [ln for ln in text.splitlines() if ip in ln and "sudo:" not in ln]
    print(color(f"  matching lines: {len(lines)}", CYAN))
    for ln in lines[-50:]:
        print("  " + ln[:160])
    print()
    if input(color("Block this IP? [y/N]: ", YELLOW)).strip().lower() == "y":
        print(color(block_ip(ip), GREEN))
    pause()


def firewall_page():
    while True:
        banner("FIREWALL")
        blocked = list_blocked()
        print(color("  CURRENT DROP RULES", BOLD + RED))
        if not blocked:
            print(color("  none", DIM))
        else:
            for i, ip in enumerate(blocked, 1):
                print(f"  {i:<4}{ip}")
        print()
        print("  1. Block IP")
        print("  2. Unblock IP / list number")
        print("  3. Persist iptables (survive reboot)")
        print("  4. Back")
        choice = ask()
        if choice == "4" or choice == "":
            return
        if choice == "1":
            ip = input(color("IP to block: ", CYAN)).strip()
            print(color(block_ip(ip), GREEN))
            pause()
        elif choice == "2":
            raw = input(color("IP or list #: ", CYAN)).strip()
            if raw.isdigit() and 1 <= int(raw) <= len(blocked):
                raw = blocked[int(raw) - 1]
            print(color(unblock_ip(raw), GREEN))
            pause()
        elif choice == "3":
            ok = persist_iptables()
            print(color("saved /etc/iptables/rules.v4" if ok else "save failed", GREEN if ok else RED))
            pause()


def port_page():
    while True:
        banner("SSH PORT")
        print(color("  Keep this session open while switching.", YELLOW))
        print()
        print("  1. Switch to 22          (FileZilla default)")
        print("  2. Switch to 51222       (locked down)")
        print("  3. Back")
        choice = ask()
        if choice == "3" or choice == "":
            return
        port = LOW_PORT if choice == "1" else HIGH_PORT if choice == "2" else None
        if not port:
            continue
        try:
            print(color(f"\nSwitching SSH to {port}...", YELLOW))
            apply_ssh_port(port)
            print(color(f"OK - SSH is on {port}", GREEN))
            print(color(f"New logins: ssh -p {port} root@HOST", DIM))
            print(color("This existing session stays up.", DIM))
        except Exception as e:
            print(color(f"FAILED: {e}", RED))
            print(color("Do not close this shell.", YELLOW))
        pause()


def ask():
    try:
        return input(color("\nSelect: ", CYAN)).strip()
    except (KeyboardInterrupt, EOFError):
        raise KeyboardInterrupt


def main():
    require_root()
    page = "monitor"
    top = []
    while True:
        if page == "monitor":
            top = show_monitor()
            choice = ask()
            if choice == "0":
                return
            if choice == "9" or choice == "":
                continue
            if choice == "1":
                raw = input(color("List number: ", CYAN)).strip()
                if raw.isdigit() and 1 <= int(raw) <= len(top):
                    ip = top[int(raw) - 1][0]
                    print(color(f"{ip}: {block_ip(ip)}", GREEN))
                else:
                    print(color("Bad number.", RED))
                pause()
            elif choice == "2":
                ip = input(color("IP to block: ", CYAN)).strip()
                print(color(block_ip(ip), GREEN))
                pause()
            elif choice == "3":
                show_fails()
            elif choice == "4":
                search_ip()
            elif choice == "5":
                show_usernames()
            elif choice == "6":
                show_accepts()
            elif choice == "7":
                page = "fw"
            elif choice == "8":
                page = "port"
        elif page == "fw":
            firewall_page()
            page = "monitor"
        elif page == "port":
            port_page()
            page = "monitor"


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(color("\nExiting...", YELLOW))
        sys.exit(0)
