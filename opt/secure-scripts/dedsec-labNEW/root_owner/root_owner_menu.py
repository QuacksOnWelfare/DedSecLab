#!/usr/bin/env python3
import os
import re
import sys
import json
import time
import hmac
import shutil
import getpass
import hashlib
import ipaddress
import traceback
import subprocess
import importlib.util
import signal
from datetime import datetime

BASE_DIR = os.environ.get("DEDSEC_BASE_DIR", "/opt/secure-scripts/dedsec-labNEW")
ROOT_DIR = os.path.join(BASE_DIR, "root_owner")
RULES_FILE = os.path.join(ROOT_DIR, "root_access_rules.json")
LOG_FILE = os.path.join(ROOT_DIR, "logs", "root_menu.log")
MISC_DIR = os.path.join(ROOT_DIR, "misc_tools")
DDOS_PANEL = os.path.join(ROOT_DIR, "traffic_intelligence", "traffic_intelligence.py")
DISCORD_NOTIFY_SCRIPT = os.path.join(BASE_DIR, "scripts", "system", "discord_notify.py")
# Backup dest may be overridden in sandbox tests.
BACKUP_DIR = os.environ.get("DEDSEC_BACKUP_DIR", "/root")

RESET = "\033[0m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
WHITE = "\033[97m"
RED = "\033[31m"
BOLD = "\033[1m"
DIM = "\033[2m"


def _stay_in_menu(signum, frame):
    print(f"\n{YELLOW}Use the menu to exit cleanly.{RESET}")


signal.signal(signal.SIGINT, _stay_in_menu)
signal.signal(signal.SIGTSTP, _stay_in_menu)
try:
    signal.signal(signal.SIGQUIT, _stay_in_menu)
except Exception:
    pass


class _SessionEnd(Exception):
    """Raised when stdin closes so the session ends cleanly (no spin loop)."""


# ---------------------------------------------------------------------------
# UI toolkit (same look as menu.py)
# ---------------------------------------------------------------------------
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _supports_utf8():
    enc = (sys.stdout.encoding or "").lower()
    if "utf" in enc:
        return True
    for var in ("LC_ALL", "LC_CTYPE", "LANG"):
        if "utf" in os.environ.get(var, "").lower():
            return True
    return False


UTF8 = _supports_utf8()

if UTF8:
    BX = {"tl": "\u256d", "tr": "\u256e", "bl": "\u2570", "br": "\u256f",
          "h": "\u2500", "v": "\u2502", "lt": "\u251c", "rt": "\u2524"}
    BULLET = "\u2022"
    OK_ICON, ERR_ICON, WARN_ICON, INFO_ICON = "\u2714", "\u2716", "\u26a0", "\u2139"
else:
    BX = {"tl": "+", "tr": "+", "bl": "+", "br": "+",
          "h": "-", "v": "|", "lt": "+", "rt": "+"}
    BULLET = "*"
    OK_ICON, ERR_ICON, WARN_ICON, INFO_ICON = "[OK]", "[X]", "[!]", "[i]"


def vlen(s):
    return len(_ANSI_RE.sub("", s))


def term_width():
    cols = shutil.get_terminal_size((80, 24)).columns
    return max(60, min(90, cols))


def _pad(s, width):
    gap = width - vlen(s)
    return s + (" " * gap if gap > 0 else "")


def draw_box(lines, title=None, color=None, width=None):
    color = color or CYAN
    width = width or term_width()
    inner = width - 4
    out = []
    if title:
        t = f" {title} "
        fill = width - 2 - vlen(t)
        if fill < 0:
            fill = 0
        out.append(f"{color}{BX['tl']}{BX['h']}{t}{BX['h'] * fill}{BX['tr']}{RESET}")
    else:
        out.append(f"{color}{BX['tl']}{BX['h'] * (width - 2)}{BX['tr']}{RESET}")
    for ln in lines:
        if ln == "__sep__":
            out.append(f"{color}{BX['lt']}{BX['h'] * (width - 2)}{BX['rt']}{RESET}")
            continue
        out.append(f"{color}{BX['v']}{RESET} {_pad(ln, inner)} {color}{BX['v']}{RESET}")
    out.append(f"{color}{BX['bl']}{BX['h'] * (width - 2)}{BX['br']}{RESET}")
    print("\n".join(out))


def breadcrumb(*parts):
    sep = f" {DIM}{BULLET}{RESET} "
    crumb = sep.join(f"{WHITE}{p}{RESET}" if i == len(parts) - 1
                     else f"{DIM}{p}{RESET}" for i, p in enumerate(parts))
    print(f"{CYAN}{BOLD}>{RESET} {crumb}\n")


def status_bar():
    display = os.environ.get("DEDSEC_OWNER_NAME", "owner")
    src = os.environ.get("DEDSEC_SOURCE_IP", "unknown")
    real = os.environ.get("DEDSEC_REAL_IP", "unknown")
    now = datetime.now().strftime("%H:%M")
    sep = f"  {DIM}{BULLET}{RESET}  "
    line = sep.join([
        f"{WHITE}{display}{RESET}",
        f"{RED}{BOLD}[OWNER]{RESET}",
        f"{CYAN}src {src}{RESET}",
        f"{DIM}real {real}{RESET}",
        f"{DIM}{now}{RESET}",
    ])
    draw_box([line], color=RED)


def menu(items, title=None, color=None):
    color = color or CYAN
    width = term_width()
    inner = width - 4
    lines = []
    for key, label, desc in items:
        if key == "__sep__":
            lines.append("__sep__")
            continue
        if key == "__hdr__":
            lines.append(f"{RED}{BOLD}{label}{RESET}")
            continue
        left = f"{color}{BOLD}{str(key):>2}{RESET}  {WHITE}{label}{RESET}"
        if desc:
            right = f"{DIM}{desc}{RESET}"
            gap = inner - vlen(left) - vlen(right)
            if gap < 1:
                gap = 1
            lines.append(left + (" " * gap) + right)
        else:
            lines.append(left)
    draw_box(lines, title=title, color=color)


def kv_panel(pairs, title=None, color=None):
    color = color or CYAN
    keyw = max((vlen(k) for k, _ in pairs if k != "__sep__"), default=0)
    lines = []
    for k, v in pairs:
        if k == "__sep__":
            lines.append("__sep__")
            continue
        lines.append(f"{CYAN}{_pad(k + ':', keyw + 1)}{RESET}  {YELLOW}{v}{RESET}")
    draw_box(lines, title=title, color=color)


def msg(kind, text):
    styles = {
        "ok": (GREEN, OK_ICON),
        "error": (RED, ERR_ICON),
        "warn": (YELLOW, WARN_ICON),
        "info": (CYAN, INFO_ICON),
    }
    col, icon = styles.get(kind, (WHITE, INFO_ICON))
    print(f"{col}{icon} {text}{RESET}")


def clear():
    os.system("clear")


def safe_input(prompt=""):
    try:
        return input(prompt).strip()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Use the menu to exit cleanly.{RESET}")
        return ""
    except EOFError:
        raise _SessionEnd()


def prompt(text):
    return safe_input(f"{YELLOW}{text}{RESET} ")


def pause():
    safe_input(f"\n{YELLOW}Press Enter to continue...{RESET}")


def is_back(choice):
    return choice in ("0", "q", "b", "back")


def banner():
    try:
        banner_path = os.path.join(BASE_DIR, "utils", "banner.py")
        spec = importlib.util.spec_from_file_location("dedsec_banner", banner_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.dedsec_banner(GREEN, CYAN, RESET, BOLD, lambda: None)
    except Exception:
        draw_box([f"{RED}{BOLD}DEDSEC ROOT OWNER PANEL{RESET}"], color=RED)


def screen(*crumbs):
    clear()
    banner()
    status_bar()
    breadcrumb(*crumbs)


def discord_alert(title, message, color=3447003, event_type="owner_menu"):
    try:
        spec = importlib.util.spec_from_file_location("discord_notify", DISCORD_NOTIFY_SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.send_discord_alert(title, message, color=color, event_type=event_type)
    except Exception:
        pass


def log(msg_text):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {msg_text}\n")


def load_rules():
    try:
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"{RED}Rules file not found:{RESET} {YELLOW}{RULES_FILE}{RESET}")
        print(f"{YELLOW}Cannot start Owner Panel without access rules.{RESET}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"{RED}Rules file is corrupt:{RESET} {YELLOW}{RULES_FILE}{RESET}")
        print(f"{YELLOW}Cannot start Owner Panel with a broken rules file.{RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{RED}Failed to load rules:{RESET} {YELLOW}{e}{RESET}")
        sys.exit(1)


def verify_hash(password, stored):
    try:
        algo, rounds, salt, expected = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(rounds))
        return hmac.compare_digest(dk.hex(), expected)
    except Exception:
        return False


def auth_owner():
    rules = load_rules()
    stored = rules.get("owner", {}).get("password_hash", "")
    display = rules.get("owner", {}).get("display_name", "owner")
    os.environ["DEDSEC_OWNER_NAME"] = display

    for attempt in range(3):
        clear()
        banner()
        draw_box([f"{WHITE}Enter the owner password to unlock the panel.{RESET}",
                  f"{DIM}Attempt {attempt + 1} of 3{RESET}"],
                 title="Owner Authentication", color=RED)
        try:
            pw = getpass.getpass(f"{YELLOW}Password:{RESET} ")
        except (KeyboardInterrupt, EOFError):
            print(f"\n{YELLOW}Authentication cancelled.{RESET}")
            log(f"AUTH_CANCEL | owner={display}")
            return False

        if verify_hash(pw, stored):
            src = os.environ.get("DEDSEC_SOURCE_IP", "unknown")
            real = os.environ.get("DEDSEC_REAL_IP", "unknown")
            log(f"AUTH_OK | owner={display} | source_ip={src}")
            discord_alert(
                "\U0001f451 DEDSEC Owner Menu Auth OK",
                f"Owner: `{display}`\nSource IP: `{src}`\nReal IP: `{real}`",
                color=3066993,
                event_type="owner_menu",
            )
            return True

        src = os.environ.get("DEDSEC_SOURCE_IP", "unknown")
        real = os.environ.get("DEDSEC_REAL_IP", "unknown")
        log(f"AUTH_FAIL | owner={display} | source_ip={src} | attempt={attempt + 1}")
        discord_alert(
            "\u26a0\ufe0f DEDSEC Owner Menu Auth Failed",
            f"Owner: `{display}`\nSource IP: `{src}`\nReal IP: `{real}`\nAttempt: `{attempt + 1}`",
            color=15105570,
            event_type="owner_menu",
        )
        msg("error", "Invalid password.")
        time.sleep(1)

    msg("error", "Too many failed attempts.")
    time.sleep(2)
    return False


def launch_ddos_panel():
    if not os.path.isfile(DDOS_PANEL):
        screen("Owner", "Traffic Intelligence")
        msg("error", "Traffic Intelligence Panel not found.")
        kv_panel([("Expected", DDOS_PANEL)])
        pause()
        return
    log("OPEN_TRAFFIC_INTELLIGENCE_PANEL")
    discord_alert(
        "\U0001f4e1 Traffic Intelligence Panel",
        f"Source IP: `{os.environ.get('DEDSEC_SOURCE_IP', 'unknown')}`",
        color=3447003,
        event_type="owner_tools",
    )
    subprocess.run(["python3", DDOS_PANEL])


def _valid_vpn_ip(value):
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip in ipaddress.ip_network("10.8.0.0/16")


def launch_lab_menu():
    wrapper = os.path.join(BASE_DIR, "access_wrapper.py")
    if not os.path.isfile(wrapper):
        screen("Owner", "Launch Lab Menu")
        msg("error", "Access wrapper not found.")
        kv_panel([("Expected", wrapper)])
        pause()
        return

    screen("Owner", "Launch Lab Menu")
    draw_box([
        f"{CYAN}Launch the lab as a specific VPN identity.{RESET}",
        f"{CYAN}This keeps account info, role, permissions, and tool tracking correct.{RESET}",
    ], title="USER SESSION LAUNCHER")

    default_ip = os.environ.get("DEDSEC_SOURCE_IP", "10.8.0.2")
    if not _valid_vpn_ip(default_ip):
        default_ip = "10.8.0.2"

    kv_panel([
        ("Default VPN Identity", default_ip),
        ("Mode", "User Wrapper Execution"),
        ("Environment", "DEDSEC Lab Secure Context"),
        ("Allowed range", "10.8.0.0/16"),
    ])

    while True:
        vpn_ip = prompt("\nEnter VPN IP or press Enter to use default:") or default_ip
        if _valid_vpn_ip(vpn_ip):
            break
        msg("error", f"Invalid VPN IP. Must be a valid address in 10.8.0.0/16.")

    env = os.environ.copy()
    env["SSH_CONNECTION"] = f"{vpn_ip} 55555 YOUR_LAB_VPN_IP 22"
    env.pop("SSH_ORIGINAL_COMMAND", None)

    log(f"OPEN_USER_ACCESS_WRAPPER | vpn_ip={vpn_ip}")
    subprocess.run(["python3", wrapper], env=env)


def system_security_scanner():
    screen("Owner", "Security Scanner")
    draw_box([f"{WHITE}Running live system checks...{RESET}"],
             title="System Security Scanner")

    checks = {
        "Listening ports": "ss -tulnp",
        "Established connections": "ss -tupn state established",
        "Top CPU processes": "ps aux --sort=-%cpu | head -15",
        "Suspicious tmp executables": "find /tmp /var/tmp /dev/shm -type f -perm /111 2>/dev/null | head -20",
        "Root crontab": "crontab -l 2>/dev/null",
        "System crontab": "cat /etc/crontab 2>/dev/null",
    }

    for title, cmd in checks.items():
        out = subprocess.run(cmd, shell=True, text=True, capture_output=True).stdout.strip()
        body = out[:3000] if out else "N/A"
        lines = [f"{YELLOW}{ln}{RESET}" for ln in body.splitlines()] or [f"{YELLOW}N/A{RESET}"]
        print()
        draw_box(lines, title=title, color=CYAN)

    log("SYSTEM_SECURITY_SCANNER")
    discord_alert(
        "\U0001f6e1\ufe0f Owner Ran System Security Scanner",
        f"Source IP: `{os.environ.get('DEDSEC_SOURCE_IP', 'unknown')}`",
        color=15844367,
        event_type="owner_tools",
    )
    pause()


def malware_payload_killer():
    screen("Owner", "Payload Killer")
    draw_box([
        f"{YELLOW}Coming soon.{RESET}",
        f"{CYAN}Planned:{RESET} process review, suspicious port killer, tmp cleanup, persistence checks.",
    ], title="Malware / Payload Killer", color=YELLOW)
    log("OPEN_PAYLOAD_KILLER")
    discord_alert(
        "\U0001f9e8 Owner Opened Payload Killer",
        "Status: `Coming soon`",
        color=15844367,
        event_type="owner_tools",
    )
    pause()


def prettify(name):
    return name.replace(".py", "").replace(".sh", "").replace("_", " ").title()


def browse_misc_tools():
    os.makedirs(MISC_DIR, exist_ok=True)

    while True:
        screen("Owner", "Misc Tools")

        files = []
        for f in sorted(os.listdir(MISC_DIR)):
            full = os.path.join(MISC_DIR, f)
            if os.path.isfile(full) and (f.endswith(".py") or f.endswith(".sh")):
                files.append(f)

        if not files:
            draw_box([
                f"{YELLOW}No tools found.{RESET}",
                f"{CYAN}Drop .py or .sh files here:{RESET}",
                f"{YELLOW}{MISC_DIR}{RESET}",
            ], title="Root Misc Tools")
            menu([("0", "Back", "q / b")], title="Actions")
        else:
            items = [(str(i), prettify(f), f) for i, f in enumerate(files, 1)]
            items.append(("__sep__", "", ""))
            items.append(("0", "Back", "q / b"))
            menu(items, title="Root Misc Tools")

        choice = prompt("\nSelect:")
        if is_back(choice):
            return
        if not choice.isdigit():
            msg("error", "Invalid option.")
            pause()
            continue

        idx = int(choice) - 1
        if idx < 0 or idx >= len(files):
            msg("error", "Invalid option.")
            pause()
            continue

        script = os.path.join(MISC_DIR, files[idx])
        screen("Owner", "Misc Tools", files[idx])
        draw_box([f"{WHITE}Running:{RESET} {YELLOW}{files[idx]}{RESET}",
                  f"{DIM}{script}{RESET}"],
                 title=f"{GREEN}{BOLD}Running Tool{RESET}", color=GREEN)
        print()
        log(f"RUN_MISC_TOOL | {script}")
        discord_alert(
            "\U0001f6e0\ufe0f Owner Ran Misc Tool",
            f"Tool: `{script}`\nSource IP: `{os.environ.get('DEDSEC_SOURCE_IP', 'unknown')}`",
            color=15844367,
            event_type="owner_tools",
        )

        start_t = time.monotonic()
        if script.endswith(".py"):
            result = subprocess.run(["python3", script])
        else:
            result = subprocess.run(["bash", script])
        duration = time.monotonic() - start_t

        print()
        res_col = GREEN if result.returncode == 0 else RED
        icon = OK_ICON if result.returncode == 0 else ERR_ICON
        draw_box([
            f"{res_col}{icon} exit {result.returncode}{RESET}   {DIM}{duration:.1f}s{RESET}"
        ], title="Result", color=res_col)
        pause()


def open_root_shell():
    screen("Owner", "Root Shell")
    draw_box([
        f"{RED}{BOLD}You are about to enter an unrestricted root shell.{RESET}",
        f"{YELLOW}Type YES (uppercase) to confirm, or anything else to cancel.{RESET}",
        f"{CYAN}Type 'exit' inside the shell to return to the Owner Panel.{RESET}",
    ], title=f"{RED}{BOLD}ROOT SHELL ACCESS{RESET}", color=RED)

    confirm = prompt("\nConfirm:")
    if confirm != "YES":
        msg("warn", "Root shell cancelled.")
        pause()
        return

    log("OPEN_ROOT_SHELL")
    discord_alert(
        "\U0001f6a8 Owner Opened ROOT SHELL",
        f"Source IP: `{os.environ.get('DEDSEC_SOURCE_IP', 'unknown')}`\n"
        f"Real IP: `{os.environ.get('DEDSEC_REAL_IP', 'unknown')}`",
        color=15158332,
        event_type="owner_tools",
    )
    print(f"\n{GREEN}Opening root shell...{RESET}\n")
    subprocess.run(["/bin/bash", "-l"])


def view_root_logs():
    screen("Owner", "Root Logs")
    files = [
        os.path.join(ROOT_DIR, "logs", "root_access.log"),
        LOG_FILE,
    ]

    for file in files:
        if os.path.isfile(file):
            out = subprocess.run(["tail", "-n", "40", file], text=True, capture_output=True).stdout
            body = (out or "N/A").strip()
        else:
            body = "N/A"
        # Keep truncation: cap displayed lines to a sensible box size.
        lines = [f"{YELLOW}{ln}{RESET}" for ln in body.splitlines()[:80]] or [f"{YELLOW}N/A{RESET}"]
        draw_box(lines, title=file, color=CYAN)
        print()

    pause()


def _fmt_size(num):
    for unit in ("B", "KB", "MB", "GB"):
        if num < 1024.0:
            return f"{num:.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} TB"


def backup_lab():
    screen("Owner", "Backup Lab")
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    os.makedirs(BACKUP_DIR, exist_ok=True)
    dest = os.path.join(BACKUP_DIR, f"dedsec-labNEW-owner-backup-{stamp}.tar.gz")

    draw_box([
        f"{YELLOW}Creating backup...{RESET}",
        f"{DIM}{dest}{RESET}",
    ], title="Backup Lab")

    start_t = time.monotonic()
    # Prefer the configured BASE_DIR so sandbox tests don't need /opt.
    result = subprocess.run(
        ["tar", "-czf", dest, BASE_DIR],
        text=True,
        capture_output=True,
    )
    elapsed = time.monotonic() - start_t

    if result.returncode == 0 and os.path.isfile(dest):
        size = _fmt_size(os.path.getsize(dest))
        draw_box([
            f"{GREEN}{OK_ICON} Backup complete.{RESET}",
            f"{CYAN}Path:{RESET}     {YELLOW}{dest}{RESET}",
            f"{CYAN}Size:{RESET}     {YELLOW}{size}{RESET}",
            f"{CYAN}Elapsed:{RESET}  {YELLOW}{elapsed:.1f}s{RESET}",
        ], title="Result", color=GREEN)
        log(f"BACKUP_OK | {dest} | size={size} | elapsed={elapsed:.1f}s")
        discord_alert(
            "\U0001f4be Owner Backup Complete",
            f"Backup: `{dest}`\nSize: `{size}`\nElapsed: `{elapsed:.1f}s`",
            color=3066993,
            event_type="owner_tools",
        )
    else:
        err = (result.stderr or "unknown error").strip()[:500]
        draw_box([
            f"{RED}{ERR_ICON} Backup failed.{RESET}",
            f"{YELLOW}{err}{RESET}",
        ], title="Result", color=RED)
        log("BACKUP_FAILED")

    pause()


def main_menu():
    while True:
        try:
            screen("Owner")
            menu([
                ("1", "Traffic Intelligence Panel", "live traffic"),
                ("2", "Launch Lab Menu as Owner/Admin", "VPN identity"),
                ("3", "System Security Scanner", "ports / procs"),
                ("4", "Malware / Payload Killer", "coming soon"),
                ("5", "Misc Tools", "root misc"),
                ("7", "View Root Logs", "last 40 lines"),
                ("8", "Backup Lab", "tar.gz snapshot"),
                ("__sep__", "", ""),
                ("__hdr__", f"{RED}{BOLD}Danger zone{RESET}", ""),
                ("6", f"{RED}Root Shell{RESET}", "unrestricted"),
                ("__sep__", "", ""),
                ("0", "Exit", "close session"),
            ], title="DEDSEC Owner Root Panel", color=RED)

            choice = prompt("\nSelect:")

            if choice == "1":
                launch_ddos_panel()
            elif choice == "2":
                launch_lab_menu()
            elif choice == "3":
                system_security_scanner()
            elif choice == "4":
                malware_payload_killer()
            elif choice == "5":
                browse_misc_tools()
            elif choice == "6":
                open_root_shell()
            elif choice == "7":
                view_root_logs()
            elif choice == "8":
                backup_lab()
            elif is_back(choice) or choice == "0":
                # Exit is option 0; also accept q/b for consistency.
                msg("info", "Goodbye.")
                break
            elif choice == "":
                # Empty Enter after Ctrl+C message: redraw, do not spin.
                continue
            else:
                msg("error", "Invalid option.")
                pause()
        except _SessionEnd:
            log("SESSION_END | stdin closed (EOF)")
            print(f"\n{YELLOW}Session closed.{RESET}")
            break
        except Exception:
            try:
                os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
                with open(LOG_FILE, "a", encoding="utf-8") as f:
                    f.write("=" * 80 + "\n")
                    f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | PANEL_ERROR\n")
                    f.write(traceback.format_exc())
            except Exception:
                pass
            try:
                msg("error", "Something went wrong. The panel has been reloaded.")
                pause()
            except _SessionEnd:
                break


if __name__ == "__main__":
    if auth_owner():
        main_menu()
