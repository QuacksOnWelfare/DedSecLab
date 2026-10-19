#!/usr/bin/env python3
"""DedSec Lab - Enter Lab access gate (sshd ForceCommand entry point).

Visual system matches menu.py / owner panel: rounded boxed panels with an
ASCII fallback, width clamped 60-90, status bar, breadcrumb, themed colours.
All access checks and behaviour are unchanged from the original wrapper.
"""
import os
import re
import sys
import json
import time
import shutil
import signal
import getpass
import hashlib
import hmac
import traceback
import importlib.util
import subprocess
from datetime import datetime, date

# Production paths (deliberately NOT overridable from the environment:
# this file is the ForceCommand gate).
BASE_DIR = "/opt/secure-scripts/dedsec-labNEW"
MENU_SCRIPT = os.path.join(BASE_DIR, "menu.py")
WHITELIST_FILE = os.path.join(BASE_DIR, "access_rules.json")
ACCESS_LOG = os.path.join(BASE_DIR, "access_audit.log")
SECURITY_LOG = os.path.join(BASE_DIR, "logs", "ssh_security.log")
ERROR_LOG = os.path.join(BASE_DIR, "logs", "access_wrapper_errors.log")
THEMES_FILE = os.path.join(BASE_DIR, "user_themes.json")
BANNER_FILE = os.path.join(BASE_DIR, "utils", "banner.py")
DISCORD_NOTIFY_SCRIPT = os.path.join(BASE_DIR, "scripts", "system", "discord_notify.py")
OPENVPN_STATUS = "/var/log/openvpn-status.log"
PYTHON_BIN = "/usr/bin/python3"

# ---------------------------------------------------------------------------
# OPTIONAL second wrapper password (DISABLED by default)
# After VPN + IP whitelist succeed, you may require an extra password before
# the Enter Lab portal. Leave empty ("") to rely on VPN lock only.
# To enable: set to a pbkdf2_sha256 hash (same format as root_owner_menu
# auth_owner: pbkdf2_sha256$<rounds>$<salt>$<hex>) OR a 64-char hex SHA-256
# of the password. Example format:
#   WRAPPER_PASSWORD_HASH = "pbkdf2_sha256$200000$YOUR_SALT$YOUR_HASH_HEX"
# ---------------------------------------------------------------------------
WRAPPER_PASSWORD_HASH = ""  # optional: set a PBKDF2/sha256 hash to require a second password after whitelist; leave empty to rely on VPN lock only


def get_real_ip_from_vpn_status(vpn_ip):
    try:
        with open(OPENVPN_STATUS, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith("CLIENT_LIST,"):
                    parts = line.strip().split(",")
                    if len(parts) >= 4 and parts[3] == vpn_ip:
                        return parts[2].split(":")[0]
    except Exception:
        pass
    return "unknown"


# --- SECURITY PATCH START ---
# Block non-interactive SSH sessions (ssh user@server "command")
if not sys.stdin.isatty():
    ssh_user = os.environ.get("USER", "unknown")
    ssh_conn = os.environ.get("SSH_CONNECTION", "").split()

    vpn_ip = ssh_conn[0] if len(ssh_conn) > 0 else "unknown"
    real_ip = get_real_ip_from_vpn_status(vpn_ip)

    cmd = os.environ.get("SSH_ORIGINAL_COMMAND", "none")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        with open(SECURITY_LOG, "a", encoding="utf-8") as f:
            f.write(f"{timestamp} | SSH_CMD_BLOCKED | user={ssh_user} | vpn_ip={vpn_ip} | real_ip={real_ip} | cmd={cmd}\n")
    except Exception:
        pass

    print("\n🚫 Blocked: Non-interactive SSH session")
    print("⚠️ This activity is being logged and monitored")
    print(f"User:      {ssh_user}")
    print(f"VPN IP:    {vpn_ip}")
    print(f"Real IP:   {real_ip}")
    print(f"Command:   {cmd}\n")

    sys.exit(1)
# --- SECURITY PATCH END ---

# Remove forced SSH command
os.environ.pop("SSH_ORIGINAL_COMMAND", None)

# Fix TERM warnings
os.environ.setdefault("TERM", "xterm")


# ---------------------------------------------------------------------------
# Colours (themed values are reassigned by apply_theme)
# ---------------------------------------------------------------------------
RESET = "\033[0m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
WHITE = "\033[97m"
RED = "\033[31m"
BOLD = "\033[1m"
DIM = "\033[2m"
# Fixed status colours for the node / service dots (never re-themed, so
# ONLINE is always green and OFFLINE always red).
ST_GREEN = "\033[32m"
ST_RED = "\033[31m"


def discord_alert(title, message, color=3447003, event_type="general"):
    try:
        spec = importlib.util.spec_from_file_location("discord_notify", DISCORD_NOTIFY_SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.send_discord_alert(title, message, color=color, event_type=event_type)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Signals: never let the user break out. SIGINT / SIGTSTP / SIGQUIT swallowed.
# ---------------------------------------------------------------------------
def _stay_in_menu(signum, frame):
    print(f"\n{YELLOW}Use the menu to exit cleanly.{RESET}")


handle_sigint = _stay_in_menu
handle_sigtstp = _stay_in_menu

signal.signal(signal.SIGINT, handle_sigint)
signal.signal(signal.SIGTSTP, handle_sigtstp)
try:
    signal.signal(signal.SIGQUIT, _stay_in_menu)
except Exception:
    pass


class _SessionEnd(Exception):
    """Raised when stdin closes (Ctrl+D / dropped connection)."""


# Clear screen without full terminal reset
def clear():
    subprocess.run(["clear"], check=False)


# ---------------------------------------------------------------------------
# UI toolkit (same as menu.py)
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
    DOT = "\u25cf"
    OK_ICON, ERR_ICON, WARN_ICON, INFO_ICON = "\u2714", "\u2716", "\u26a0", "\u2139"
else:
    BX = {"tl": "+", "tr": "+", "bl": "+", "br": "+",
          "h": "-", "v": "|", "lt": "+", "rt": "+"}
    BULLET = "*"
    DOT = "o"
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
        fill = max(0, width - 3 - vlen(t))
        out.append(f"{color}{BX['tl']}{BX['h']}{t}{color}{BX['h'] * fill}{BX['tr']}{RESET}")
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


def menu(items, title=None, color=None):
    """items: list of (key, label, desc). Renders an aligned boxed menu."""
    color = color or CYAN
    inner = term_width() - 4
    lines = []
    for key, label, desc in items:
        if key == "__sep__":
            lines.append("__sep__")
            continue
        left = f"{color}{BOLD}{str(key):>2}{RESET}  {WHITE}{label}{RESET}"
        if desc:
            right = f"{DIM}{desc}{RESET}"
            gap = max(1, inner - vlen(left) - vlen(right))
            lines.append(left + (" " * gap) + right)
        else:
            lines.append(left)
    draw_box(lines, title=title, color=color)


def msg(kind, text):
    styles = {"ok": (GREEN, OK_ICON), "error": (RED, ERR_ICON),
              "warn": (YELLOW, WARN_ICON), "info": (CYAN, INFO_ICON)}
    col, icon = styles.get(kind, (WHITE, INFO_ICON))
    print(f"{col}{icon} {text}{RESET}")


def safe_input(prompt=""):
    try:
        return input(prompt).strip()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Use the menu to exit cleanly.{RESET}")
        return ""
    except EOFError:
        raise _SessionEnd()


# ---------------------------------------------------------------------------
# Theme (same keys / file as menu.py: admin-only, keyed by source IP)
# ---------------------------------------------------------------------------
_THEME_IP = ""
_THEME_ROLE = "standard"


def load_theme():
    if _THEME_ROLE != "admin" or not _THEME_IP or _THEME_IP == "unknown":
        return "default"
    try:
        with open(THEMES_FILE, "r", encoding="utf-8") as f:
            return json.load(f).get(_THEME_IP, "default")
    except Exception:
        return "default"


def apply_theme():
    global GREEN, CYAN, WHITE, YELLOW, RED
    GREEN, CYAN, WHITE, YELLOW, RED = "\033[32m", "\033[36m", "\033[97m", "\033[33m", "\033[31m"
    theme = load_theme()
    if theme == "red":
        GREEN, CYAN, YELLOW = "\033[31m", "\033[31m", "\033[91m"
    elif theme == "minimal":
        GREEN = CYAN = YELLOW = RED = "\033[97m"
    elif theme == "blue":
        GREEN, CYAN, YELLOW = "\033[34m", "\033[94m", "\033[94m"
    elif theme == "purple":
        GREEN, CYAN, YELLOW = "\033[35m", "\033[95m", "\033[95m"
    elif theme == "cyan":
        GREEN, CYAN, YELLOW = "\033[36m", "\033[36m", "\033[96m"
    elif theme == "yellow":
        GREEN, CYAN, YELLOW = "\033[33m", "\033[93m", "\033[93m"


def banner():
    try:
        spec = importlib.util.spec_from_file_location("dedsec_banner", BANNER_FILE)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.dedsec_banner(GREEN, CYAN, RESET, BOLD, apply_theme)
    except Exception:
        # Built-in fallback header when utils/banner.py can't be loaded.
        apply_theme()
        draw_box([f"{GREEN}{BOLD}DEDSEC LAB{RESET}   {DIM}secure access terminal{RESET}"],
                 color=GREEN)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def log_event(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        os.makedirs(os.path.dirname(ACCESS_LOG), exist_ok=True)
        with open(ACCESS_LOG, "a", encoding="utf-8") as f:
            f.write(f"{timestamp} | {message}\n")
    except Exception as e:
        print(f"{RED}Log write failed:{RESET} {e}")


def log_security(event, ssh_user, ip, extra=""):
    try:
        with open(SECURITY_LOG, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now()} | {event} | user={ssh_user} | ip={ip}{extra}\n")
    except Exception:
        pass


def log_error(context):
    try:
        os.makedirs(os.path.dirname(ERROR_LOG), exist_ok=True)
        with open(ERROR_LOG, "a", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {context}\n")
            f.write(traceback.format_exc())
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Identity / rules / validation
# NOTE: the bodies of these helpers were reconstructed from the described
# behaviour (the pasted original was truncated here). Diff against the
# server copy before deploying - see menu_changes.md.
# ---------------------------------------------------------------------------
def get_ssh_user():
    try:
        return getpass.getuser()
    except Exception:
        return os.environ.get("USER", "unknown")


def get_source_ip():
    conn = os.environ.get("SSH_CONNECTION", "").split()
    if conn:
        return conn[0]
    return "unknown"


def load_rules():
    try:
        with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def get_user_rule_by_ip(rules, ip):
    return rules.get("users", {}).get(ip)


def calculate_days_left(expires):
    try:
        exp = datetime.strptime(str(expires), "%Y-%m-%d").date()
    except Exception:
        return None, False
    days = (exp - date.today()).days
    return days, days < 0



def _verify_wrapper_password(password: str, stored: str) -> bool:
    """Verify optional WRAPPER_PASSWORD_HASH (pbkdf2_sha256$... or raw sha256 hex)."""
    stored = (stored or "").strip()
    if not stored:
        return True
    try:
        if stored.startswith("pbkdf2_sha256$"):
            _algo, rounds, salt, expected = stored.split("$", 3)
            dk = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), salt.encode(), int(rounds)
            )
            return hmac.compare_digest(dk.hex(), expected)
        # Plain 64-char hex SHA-256 of the password
        if len(stored) == 64 and all(c in "0123456789abcdefABCDEF" for c in stored):
            digest = hashlib.sha256(password.encode()).hexdigest()
            return hmac.compare_digest(digest.lower(), stored.lower())
    except Exception:
        return False
    return False


def require_optional_wrapper_password(ssh_user: str, ip: str) -> None:
    """If WRAPPER_PASSWORD_HASH is set, prompt before portal; else no-op (VPN-only)."""
    stored = (WRAPPER_PASSWORD_HASH or "").strip()
    if not stored:
        return  # disabled - VPN + whitelist only
    for attempt in range(3):
        clear()
        banner()
        breadcrumb("DedSec", "Access Gate", "Password")
        draw_box(
            [
                f"{WHITE}Optional wrapper password required.{RESET}",
                f"{DIM}Attempt {attempt + 1} of 3{RESET}",
            ],
            title="Lab Authentication",
            color=YELLOW,
        )
        try:
            pw = getpass.getpass(f"{YELLOW}Password:{RESET} ")
        except (KeyboardInterrupt, EOFError):
            deny_access(ssh_user, ip, "wrapper password cancelled")
            return
        if _verify_wrapper_password(pw, stored):
            log_event(f"WRAPPER_AUTH_OK | ssh_user={ssh_user} | ip={ip}")
            return
        log_security("WRAPPER_AUTH_FAIL", ssh_user, ip, f" | attempt={attempt + 1}")
        msg("error", "Invalid password.")
        time.sleep(1)
    deny_access(ssh_user, ip, "wrapper password failed")


def validate_user(user_rule):
    if not user_rule:
        return False, "not whitelisted", None
    if not user_rule.get("enabled", True):
        return False, "user disabled", None
    role = str(user_rule.get("role", "standard")).strip().lower()
    expires = user_rule.get("subscription_expires")
    if expires:
        days_left, expired = calculate_days_left(expires)
        if expired:
            return False, "subscription expired", None
    return True, "ok", role


def deny_access(ssh_user, ip, reason):
    clear()
    banner()
    breadcrumb("DedSec", "Access Gate", "Denied")
    draw_box([
        f"{WHITE}IP     :{RESET} {YELLOW}{ip}{RESET}",
        f"{WHITE}Reason :{RESET} {YELLOW}{reason}{RESET}",
        "__sep__",
        f"{DIM}This attempt has been logged and reported.{RESET}",
    ], title=f"{RED}{BOLD}{ERR_ICON} ACCESS DENIED{RESET}", color=RED)

    log_event(f"DENY | ssh_user={ssh_user} | ip={ip} | reason={reason}")

    discord_alert(
        "🚫 DEDSEC Access Denied",
        f"**SSH User:** {ssh_user}\n**IP:** {ip}\n**Reason:** {reason}",
        color=15158332,
        event_type="deny"
    )

    time.sleep(3)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Screen panels
# ---------------------------------------------------------------------------
VPN_NODES = ["UK", "USA", "CANADA", "EU"]
SERVICES = [("DedSecLab API", True), ("CCTV API", True)]  # services shown on the portal


def _node_enabled(locations, name):
    """Case-insensitive lookup of a node in rules['vpn_locations']."""
    if not isinstance(locations, dict):
        return False
    for key, data in locations.items():
        if str(key).strip().upper() == name:
            if isinstance(data, dict):
                return bool(data.get("enabled", False))
            return bool(data)
    return False


def _status_cell(name, online, up="ONLINE", down="OFFLINE"):
    if online:
        return f"{WHITE}{BOLD}{name}{RESET} {ST_GREEN}{DOT} {up}{RESET}"
    return f"{WHITE}{BOLD}{name}{RESET} {ST_RED}{DOT} {down}{RESET}"


def _grid(cells, cols):
    inner = term_width() - 4
    cw = inner // cols
    rows = []
    for i in range(0, len(cells), cols):
        row = cells[i:i + cols]
        rows.append("".join(_pad(c, cw) for c in row).rstrip())
    return rows


def print_locations(rules):
    locations = rules.get("vpn_locations", {})
    cells = [_status_cell(n, _node_enabled(locations, n)) for n in VPN_NODES]
    # 4 across when there's room, otherwise 2x2.
    cols = 4 if term_width() - 4 >= 4 * 18 else 2
    draw_box(_grid(cells, cols), title=f"{WHITE}{BOLD}VPN NODES{RESET}")


def print_services():
    cells = [_status_cell(n, ok, "LIVE", "DOWN") for n, ok in SERVICES]
    draw_box(_grid(cells, 2), title=f"{WHITE}{BOLD}SERVICES{RESET}")


def _time_left(days_left, expired):
    if days_left is None:
        return DIM, "N/A"
    if expired:
        return RED, "Expired"
    if days_left <= 3:
        return RED, f"{days_left}d"
    if days_left <= 7:
        return YELLOW, f"{days_left}d"
    return GREEN, f"{days_left}d"


def show_screen(ip, role, rules, user_rule):
    clear()
    banner()

    expires = user_rule.get("subscription_expires", "N/A")
    days_left, expired = calculate_days_left(expires)
    display_name = user_rule.get("display_name", "unknown")
    region = user_rule.get("current_vpn_region", "UK")
    tcol, tlabel = _time_left(days_left, expired)

    badge_col = RED if role == "admin" else GREEN
    sep = f"  {DIM}{BULLET}{RESET}  "
    draw_box([sep.join([
        f"{WHITE}{display_name}{RESET}",
        f"{badge_col}{BOLD}[{str(role).upper()}]{RESET}",
        f"{CYAN}{region}{RESET}",
        f"{tcol}{tlabel} left{RESET}" if days_left is not None and not expired else f"{tcol}{tlabel}{RESET}",
        f"{DIM}{datetime.now().strftime('%H:%M')}{RESET}",
    ])])
    breadcrumb("DedSec", "Access Gate")

    pairs = [("User", f"{YELLOW}{display_name}{RESET}"),
             ("Role", f"{badge_col}{BOLD}{role}{RESET}"),
             ("VPN IP", f"{YELLOW}{ip}{RESET}"),
             ("Region", f"{YELLOW}{region}{RESET}"),
             ("Expiry", f"{YELLOW}{expires}{RESET}"),
             ("Time Left", f"{tcol}{BOLD}{tlabel}{RESET}")]
    keyw = max(len(k) for k, _ in pairs)
    draw_box([f"{CYAN}{k.ljust(keyw)}{RESET}  {DIM}:{RESET}  {v}" for k, v in pairs],
             title=f"{WHITE}{BOLD}ACCESS SESSION{RESET}")

    print_locations(rules)
    print_services()

    menu([
        ("1", "Enter Lab", "launch DedSec menu"),
        ("2", "Decline and Exit", "close session"),
    ], title=f"{WHITE}{BOLD}SELECT{RESET}")
    print(f"{DIM}Use of this system is monitored and restricted.{RESET}")


def launch_menu(ssh_user, ip, role, user_rule):
    if not os.path.isfile(MENU_SCRIPT):
        clear()
        banner()
        msg("error", "Menu script not found.")
        time.sleep(3)
        sys.exit(1)

    env = os.environ.copy()
    env["DEDSEC_USER"] = user_rule.get("display_name", ssh_user)
    env["DEDSEC_SSH_USER"] = user_rule.get("ssh_user", ssh_user)
    env["DEDSEC_SOURCE_IP"] = ip
    env["DEDSEC_ROLE"] = role

    os.execve(PYTHON_BIN, ["python3", MENU_SCRIPT], env)


def portal(ssh_user, ip, role, rules, user_rule):
    while True:
        try:
            show_screen(ip, role, rules, user_rule)
            choice = safe_input(f"\n{YELLOW}Select:{RESET} ")

            if choice == "1":
                launch_menu(ssh_user, ip, role, user_rule)
            elif choice == "2":
                msg("info", "Goodbye")
                sys.exit(0)
            else:
                log_security("INVALID_INPUT", ssh_user, ip, f" | input={choice}")
                msg("error", "Invalid")
                time.sleep(1)
        except _SessionEnd:
            print("\nSession closed.")
            sys.exit(1)
        except SystemExit:
            raise
        except Exception:
            # Never show a traceback; log it and redraw the gate.
            log_error(f"PORTAL_ERROR | user={ssh_user} | ip={ip}")
            msg("error", "Something went wrong. Reloading...")
            time.sleep(1)


def main():
    global _THEME_IP, _THEME_ROLE
    ssh_user = get_ssh_user()
    ip = get_source_ip()

    rules = load_rules()
    if not rules:
        deny_access(ssh_user, ip, "rules missing")

    user_rule = get_user_rule_by_ip(rules, ip)
    ok, reason, role = validate_user(user_rule)

    if not ok:
        deny_access(ssh_user, ip, reason)

    # Optional layer-3 password (no-op when WRAPPER_PASSWORD_HASH is empty)
    require_optional_wrapper_password(ssh_user, ip)

    _THEME_IP, _THEME_ROLE = ip, role
    portal(ssh_user, ip, role, rules, user_rule)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        # Fail closed: log, never trace, never fall through to a shell.
        log_error("FATAL")
        print("Access gate error. Session closed.")
        sys.exit(1)
