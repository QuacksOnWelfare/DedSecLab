#!/usr/bin/env python3
import os
import re
import sys
import json
import time
import shutil
import subprocess
import hashlib
import getpass
import signal
import traceback
import importlib.util
from datetime import datetime, date

# BASE_DIR may be overridden for sandbox testing ONLY via DEDSEC_BASE_DIR.
# In production the env var is unset, so the original path is used unchanged.
BASE_DIR = os.environ.get("DEDSEC_BASE_DIR", "/opt/secure-scripts/dedsec-labNEW")
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")
LOGS_DIR = os.path.join(BASE_DIR, "logs")
RULES_FILE = os.path.join(BASE_DIR, "access_rules.json")
UPDATES_FILE = os.path.join(BASE_DIR, "updates.txt")
THEMES_FILE = os.path.join(BASE_DIR, "user_themes.json")
ADMIN_NOTICE_FILE = os.path.join(BASE_DIR, "admin_notice.txt")
SESSIONS_FILE = os.path.join(BASE_DIR, "user_sessions.json")
GENERAL_CHAT_SCRIPT = os.path.join(BASE_DIR, "scripts", "system", "general_chat.py")
TICKETS_USER_SCRIPT = os.path.join(BASE_DIR, "scripts", "system", "user_ticket_help.py")
TICKETS_ADMIN_SCRIPT = os.path.join(BASE_DIR, "scripts", "admin_tools", "admin_ticket_panel.py")

ADMIN_CATEGORY = "admin_tools"
ADMIN_PASSWORD_HASH = "YOUR_SHA256_PASSWORD_HASH"
USAGE_LOG = os.path.join(LOGS_DIR, "tool_usage.log")
ADMIN_AUDIT_LOG = os.path.join(LOGS_DIR, "admin_audit.log")
ERROR_LOG = os.path.join(LOGS_DIR, "tool_errors.log")

DISCORD_NOTIFY_SCRIPT = os.path.join(BASE_DIR, "scripts", "system", "discord_notify.py")


def discord_alert(title, message, color=3447003, event_type="general"):
    try:
        spec = importlib.util.spec_from_file_location("discord_notify", DISCORD_NOTIFY_SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.send_discord_alert(title, message, color=color, event_type=event_type)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Colours / theme globals (themed values are reassigned by apply_theme)
# ---------------------------------------------------------------------------
RESET = "\033[0m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
WHITE = "\033[97m"
RED = "\033[31m"
BOLD = "\033[1m"
DIM = "\033[2m"

os.makedirs(LOGS_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# Signal handling: never let the user break out to a shell.
# SIGINT / SIGTSTP / SIGQUIT are caught and turned into a friendly message.
# ---------------------------------------------------------------------------
def _stay_in_menu(signum, frame):
    print(f"\n{YELLOW}Use the menu to exit cleanly.{RESET}")


signal.signal(signal.SIGINT, _stay_in_menu)
signal.signal(signal.SIGTSTP, _stay_in_menu)
try:
    signal.signal(signal.SIGQUIT, _stay_in_menu)
except Exception:
    pass


class _SessionEnd(Exception):
    """Raised when stdin closes (Ctrl+D) so the session can end cleanly."""


def clear():
    os.system("clear")


# ---------------------------------------------------------------------------
# UI toolkit: width-aware boxed panels with ASCII fallback
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


def _days_color(expiry):
    exp = parse_date_safe(expiry)
    if not exp:
        return DIM, "N/A"
    n = (exp - date.today()).days
    label = f"{n}d left" if n >= 0 else "expired"
    if n < 0 or n <= 3:
        return RED, label
    if n <= 7:
        return YELLOW, label
    return GREEN, label


def status_bar():
    rules = load_rules()
    ip = os.environ.get("DEDSEC_SOURCE_IP", "unknown")
    urule = rules.get("users", {}).get(ip, {})
    name = urule.get("display_name", os.environ.get("DEDSEC_USER", "unknown"))
    role = str(urule.get("role", os.environ.get("DEDSEC_ROLE", "standard"))).lower()
    region = urule.get("current_vpn_region", "UK")
    expiry = urule.get("subscription_expires", "N/A")

    badge_col = RED if role == "admin" else GREEN
    badge = f"{badge_col}{BOLD}[{role.upper()}]{RESET}"
    dcol, dlabel = _days_color(expiry)
    now = datetime.now().strftime("%H:%M")
    sep = f"  {DIM}{BULLET}{RESET}  "
    line = sep.join([
        f"{WHITE}{name}{RESET}",
        badge,
        f"{CYAN}{region}{RESET}",
        f"{dcol}{dlabel}{RESET}",
        f"{DIM}{now}{RESET}",
    ])
    draw_box([line], color=CYAN)


def menu(items, title=None, color=None):
    """items: list of (key, label, desc). Renders an aligned boxed menu."""
    color = color or CYAN
    width = term_width()
    inner = width - 4
    lines = []
    for key, label, desc in items:
        if key == "__sep__":
            lines.append("__sep__")
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
    keyw = max((vlen(k) for k, _ in pairs), default=0)
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


def safe_input(prompt=""):
    try:
        return input(prompt).strip()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Use the menu to exit cleanly.{RESET}")
        return ""
    except EOFError:
        # stdin closed (Ctrl+D): end the session cleanly, never drop to a shell.
        raise _SessionEnd()


def prompt(text):
    return safe_input(f"{YELLOW}{text}{RESET} ")


def pause():
    safe_input(f"\n{YELLOW}Press Enter to continue...{RESET}")


def is_back(choice):
    return choice in ("0", "q", "b", "back")


# ---------------------------------------------------------------------------
# Theme system (admin-only, same keys / file format as before)
# ---------------------------------------------------------------------------
def get_theme_key():
    ip = os.environ.get("DEDSEC_SOURCE_IP", "").strip()
    if ip and ip != "unknown":
        return ip
    user = os.environ.get("DEDSEC_USER", "").strip()
    if user:
        return user
    return "default"


def load_theme():
    try:
        with open(THEMES_FILE, "r", encoding="utf-8") as f:
            themes = json.load(f)
    except Exception:
        return "default"

    role = os.environ.get("DEDSEC_ROLE", "standard").strip().lower()
    if role != "admin":
        return "default"
    return themes.get(get_theme_key(), "default")


def apply_theme():
    global GREEN, CYAN, WHITE, YELLOW, RED

    GREEN = "\033[32m"
    CYAN = "\033[36m"
    WHITE = "\033[97m"
    YELLOW = "\033[33m"
    RED = "\033[31m"

    theme = load_theme()

    if theme == "red":
        GREEN = "\033[31m"
        CYAN = "\033[31m"
        YELLOW = "\033[91m"
    elif theme == "minimal":
        GREEN = "\033[97m"
        CYAN = "\033[97m"
        YELLOW = "\033[97m"
        RED = "\033[97m"
    elif theme == "blue":
        GREEN = "\033[34m"
        CYAN = "\033[94m"
        YELLOW = "\033[94m"
    elif theme == "purple":
        GREEN = "\033[35m"
        CYAN = "\033[95m"
        YELLOW = "\033[95m"
    elif theme == "cyan":
        GREEN = "\033[36m"
        CYAN = "\033[36m"
        YELLOW = "\033[96m"
    elif theme == "yellow":
        GREEN = "\033[33m"
        CYAN = "\033[93m"
        YELLOW = "\033[93m"


def banner():
    try:
        banner_path = os.path.join(BASE_DIR, "utils", "banner.py")
        spec = importlib.util.spec_from_file_location("dedsec_banner", banner_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.dedsec_banner(GREEN, CYAN, RESET, BOLD, apply_theme)
    except Exception:
        # Built-in fallback header when utils/banner.py can't be loaded.
        apply_theme()
        draw_box([f"{GREEN}{BOLD}DEDSEC LAB{RESET}   {DIM}secure access terminal{RESET}"],
                 color=GREEN)


def screen(*crumbs):
    """Standard screen chrome: clear, banner, status bar, breadcrumb."""
    clear()
    banner()
    status_bar()
    breadcrumb(*crumbs)


# ---------------------------------------------------------------------------
# Admin notice / expiry warning
# ---------------------------------------------------------------------------
def show_admin_notice():
    if not os.path.isfile(ADMIN_NOTICE_FILE):
        return
    try:
        with open(ADMIN_NOTICE_FILE, "r", encoding="utf-8") as f:
            notice = f.read().strip()
    except Exception:
        return
    if notice:
        draw_box([f"{YELLOW}{line}{RESET}" for line in notice.splitlines()] or [""],
                 title=f"{RED}{BOLD}! Admin Notice{RESET}", color=RED)


def prettify_name(name):
    overrides = {
        "ip_database.py": "IP Database",
        "hwid_locker.py": "HWID Locker",
        "vps_admin_tool.py": "HWID Locker",
    }
    if name in overrides:
        return overrides[name]
    return name.replace(".py", "").replace("_", " ").replace("/", " / ").title()


def load_rules():
    try:
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def parse_date_safe(value):
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except Exception:
        return None


def days_left(expiry):
    expiry_date = parse_date_safe(expiry)
    if not expiry_date:
        return "N/A"
    return f"{(expiry_date - date.today()).days}d"


def show_expiry_warning():
    rules = load_rules()
    ip = os.environ.get("DEDSEC_SOURCE_IP", "unknown")
    user = rules.get("users", {}).get(ip, {})

    expiry = user.get("subscription_expires")
    if not expiry:
        return

    exp_date = parse_date_safe(expiry)
    if not exp_date:
        return
    remaining = (exp_date - date.today()).days

    if 0 <= remaining <= 3:
        draw_box([f"{YELLOW}Your access expires in {remaining} day(s).{RESET}"],
                 title=f"{RED}{BOLD}! Subscription Notice{RESET}", color=RED)


# ---------------------------------------------------------------------------
# Theme picker (admin only) with colour previews
# ---------------------------------------------------------------------------
def change_theme():
    role = os.environ.get("DEDSEC_ROLE", "standard").strip().lower()
    if role != "admin":
        screen("Home", "Account", "Theme")
        msg("error", "Theme settings are restricted to admins.")
        pause()
        return

    screen("Home", "Account", "Theme")

    previews = [
        ("1", "Default Green", "\033[32m"),
        ("2", "Red", "\033[31m"),
        ("3", "Minimal White", "\033[97m"),
        ("4", "Blue", "\033[34m"),
        ("5", "Purple", "\033[35m"),
        ("6", "Cyan", "\033[36m"),
        ("7", "Yellow", "\033[33m"),
    ]
    items = []
    for key, label, col in previews:
        swatch = f"{col}{BOLD}{label}{RESET}"
        preview = f"{col}{BX['h'] * 10}{RESET}"
        items.append((key, swatch, preview))
    items.append(("__sep__", "", ""))
    items.append(("0", "Back", "q / b"))
    menu(items, title="Select Theme")

    choice = prompt("\nSelect:")

    themes = {"1": "default", "2": "red", "3": "minimal", "4": "blue",
              "5": "purple", "6": "cyan", "7": "yellow"}

    if is_back(choice):
        return
    if choice not in themes:
        msg("error", "Invalid option.")
        pause()
        return

    theme = themes[choice]
    user_key = get_theme_key()

    try:
        with open(THEMES_FILE, "r", encoding="utf-8") as f:
            saved = json.load(f)
    except Exception:
        saved = {}

    saved[user_key] = theme

    with open(THEMES_FILE, "w", encoding="utf-8") as f:
        json.dump(saved, f, indent=2)

    msg("ok", f"Theme saved: {theme}")
    pause()


def show_account():
    while True:
        screen("Home", "Account")
        role = os.environ.get("DEDSEC_ROLE", "standard").strip().lower()

        items = [("1", "View Account Info", "profile & subscription")]
        if role == "admin":
            items.append(("2", "Change Theme", "admin only"))
        items.append(("__sep__", "", ""))
        items.append(("0", "Back", "q / b"))
        menu(items, title="My Account")

        choice = prompt("\nSelect:")

        if choice == "1":
            _show_account_info()
        elif choice == "2" and os.environ.get("DEDSEC_ROLE", "standard").strip().lower() == "admin":
            change_theme()
        elif is_back(choice):
            return
        else:
            msg("error", "Invalid option.")
            pause()


def update_session_heartbeat():
    ip = os.environ.get("DEDSEC_SOURCE_IP", "unknown")
    user = os.environ.get("DEDSEC_USER", "unknown")
    role = os.environ.get("DEDSEC_ROLE", "standard")

    if ip == "unknown":
        return

    try:
        with open(SESSIONS_FILE, "r", encoding="utf-8") as f:
            sessions = json.load(f)
    except Exception:
        sessions = {}

    sessions[ip] = {
        "user": user,
        "role": role,
        "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    with open(SESSIONS_FILE, "w", encoding="utf-8") as f:
        json.dump(sessions, f, indent=2)


def _show_account_info():
    screen("Home", "Account", "Account Info")

    rules = load_rules()
    ip = os.environ.get("DEDSEC_SOURCE_IP", "unknown")
    user_rule = rules.get("users", {}).get(ip, {})

    display_name = user_rule.get("display_name", os.environ.get("DEDSEC_USER", "unknown"))
    discord_name = user_rule.get("discord_name", "N/A")
    discord_id = user_rule.get("discord_id", "N/A")
    role = user_rule.get("role", os.environ.get("DEDSEC_ROLE", "standard"))
    region = user_rule.get("current_vpn_region", "UK")
    expiry = user_rule.get("subscription_expires", "N/A")
    time_left = days_left(expiry)
    config_name = user_rule.get("config_name", "N/A")

    kv_panel([
        ("Display Name", display_name),
        ("Discord Name", discord_name),
        ("Discord ID", discord_id),
        ("VPN IP", ip),
        ("Role", role),
        ("Region", region),
        ("Expiry Date", expiry),
        ("Time Left", time_left),
        ("Config", config_name),
    ], title="My Account")
    pause()


def show_updates():
    screen("Home", "Updates")

    if not os.path.isfile(UPDATES_FILE):
        draw_box([f"{YELLOW}No updates yet.{RESET}"], title="Updates / Announcements")
        pause()
        return

    with open(UPDATES_FILE, "r", encoding="utf-8") as f:
        content = f.read().strip()
    lines = [f"{YELLOW}{ln}{RESET}" for ln in content.splitlines()] or [f"{YELLOW}No updates yet.{RESET}"]
    draw_box(lines, title="Updates / Announcements")
    pause()


def open_ticket_system():
    role = os.environ.get("DEDSEC_ROLE", "standard").strip().lower()

    if role == "admin":
        script = TICKETS_ADMIN_SCRIPT
    else:
        script = TICKETS_USER_SCRIPT

    if not os.path.isfile(script):
        screen("Home", "Help / Tickets")
        msg("error", "Ticket script not found.")
        kv_panel([("Expected", script)])
        pause()
        return

    subprocess.run(["python3", script])


def open_general_chat():
    if not os.path.isfile(GENERAL_CHAT_SCRIPT):
        screen("Home", "General Chat")
        msg("error", "General chat script not found.")
        kv_panel([("Expected", GENERAL_CHAT_SCRIPT)])
        pause()
        return

    subprocess.run(["python3", GENERAL_CHAT_SCRIPT])


def show_system_info():
    screen("Home", "System Info")

    kv_panel([
        ("SSH User", os.environ.get("DEDSEC_SSH_USER", getpass.getuser())),
        ("DEDSEC User", os.environ.get("DEDSEC_USER", "unknown")),
        ("Source IP", os.environ.get("DEDSEC_SOURCE_IP", "unknown")),
        ("Role", os.environ.get("DEDSEC_ROLE", "standard")),
        ("Directory", os.getcwd()),
    ], title="System Info")
    print()
    subprocess.run(["python3", "--version"])
    pause()


def show_rules():
    screen("Home", "Rules of Use")
    rules = [
        "Activity for lab may be logged.",
        "Do not share accounts or VPN files.",
        "Do not bypass restrictions.",
        "Admin tools are restricted.",
        "No VPN activity logging is performed.",
        "Abuse or misuse is strictly prohibited.",
    ]
    draw_box([f"{WHITE}{BULLET}{RESET} {r}" for r in rules],
             title=f"{RED}{BOLD}Rules of Use{RESET}", color=RED)
    pause()


def get_categories():
    if not os.path.isdir(SCRIPTS_DIR):
        return []

    categories = []
    role = os.environ.get("DEDSEC_ROLE", "standard").strip().lower()

    for item in sorted(os.listdir(SCRIPTS_DIR)):
        if item == "system":
            continue
        full_path = os.path.join(SCRIPTS_DIR, item)
        if os.path.isdir(full_path):
            if item == ADMIN_CATEGORY and role != "admin":
                continue
            categories.append((item, prettify_name(item)))

    return categories


IP_TOOLS_ORDER = [
    "dns_lookup.py",
    "fivem_finder.py",
    "my_live_traffic.py",
    "nikto_runner.py",
    "nmap_scan.py",
    "port_probe.py",
    "vpn_puller.py",
    "vpn_pullerv2.py",
    "reverse_dns.py",
]


def get_scripts(category):
    category_path = os.path.join(SCRIPTS_DIR, category)
    if not os.path.isdir(category_path):
        return []

    scripts = []
    names = os.listdir(category_path)
    if category == "ip_tools":
        names = [n for n in IP_TOOLS_ORDER if n in names] + sorted(
            n for n in names if n not in IP_TOOLS_ORDER
        )
    else:
        names = sorted(names)

    for item in names:
        full_path = os.path.join(category_path, item)

        if item.endswith(".py") and os.path.isfile(full_path):
            scripts.append((full_path, prettify_name(item)))

        elif os.path.isdir(full_path):
            if item in ("misc_tools", "__pycache__"):
                continue
            main_py = os.path.join(full_path, "main.py")
            folder_py = os.path.join(full_path, item + ".py")

            if os.path.isfile(main_py):
                scripts.append((main_py, prettify_name(item)))
                continue
            if os.path.isfile(folder_py):
                scripts.append((folder_py, prettify_name(item)))
                continue

            for sub_item in sorted(os.listdir(full_path)):
                sub_path = os.path.join(full_path, sub_item)
                if sub_item.endswith(".py") and os.path.isfile(sub_path):
                    scripts.append((sub_path, prettify_name(item)))
                    break

    return scripts


def log_tool_usage(category_name, filename):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user = os.environ.get("DEDSEC_USER", "unknown")
    ip = os.environ.get("DEDSEC_SOURCE_IP", "unknown")
    with open(USAGE_LOG, "a", encoding="utf-8") as f:
        f.write(f"{timestamp} | {user} | {ip} | {category_name} | {filename}\n")


def log_admin_event(message):
    try:
        os.makedirs(LOGS_DIR, exist_ok=True)
        with open(ADMIN_AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now().isoformat()} | {message}\n")
    except Exception:
        pass


def check_admin_password():
    # Admin password disabled.
    # Original password prompt removed by patch.
    log_admin_event("BYPASS | admin_tools password disabled")
    return True


def browse_categories():
    while True:
        screen("Home", "Tools")
        categories = get_categories()

        if not categories:
            draw_box([f"{RED}No categories found.{RESET}"], title="Tool Categories", color=RED)
            pause()
            return

        items = [(str(i), display, "") for i, (_, display) in enumerate(categories, start=1)]
        items.append(("__sep__", "", ""))
        items.append(("0", "Back", "q / b"))
        menu(items, title="Tool Categories")

        choice = prompt("\nSelect a category:")

        if is_back(choice):
            return
        if not choice.isdigit():
            msg("error", "Invalid choice.")
            pause()
            continue

        idx = int(choice)
        if idx < 1 or idx > len(categories):
            msg("error", "Invalid choice.")
            pause()
            continue

        category_name, category_display = categories[idx - 1]

        if category_name == ADMIN_CATEGORY:
            screen("Home", "Tools", category_display)
            if not check_admin_password():
                msg("error", "Access denied.")
                pause()
                continue

        browse_scripts(category_name, category_display)


def log_tool_error(script_path, display, error_text):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user = os.environ.get("DEDSEC_USER", "unknown")
    ip = os.environ.get("DEDSEC_SOURCE_IP", "unknown")
    role = os.environ.get("DEDSEC_ROLE", "standard")

    with open(ERROR_LOG, "a", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write(f"{timestamp} | TOOL_ERROR\n")
        f.write(f"User: {user}\n")
        f.write(f"IP: {ip}\n")
        f.write(f"Role: {role}\n")
        f.write(f"Tool: {display}\n")
        f.write(f"Path: {script_path}\n")
        f.write(error_text.strip() + "\n")

    discord_alert(
        "\u274c DEDSEC Tool Error",
        (
            f"\U0001f464 **User:** `{user}`\n"
            f"\U0001f310 **IP:** `{ip}`\n"
            f"\U0001f3ad **Role:** `{role}`\n\n"
            f"\U0001f4e6 **Tool:** `{display}`\n"
            f"\U0001f4c4 **Path:** `{script_path}`\n\n"
            f"\u26a0\ufe0f **Error logged:** `tool_errors.log`"
        ),
        color=15158332,
        event_type="admin_tools" if role == "admin" else "tools",
    )


def _tool_cmd(script_path, extra_args=None):
    extra_args = extra_args or []
    if os.geteuid() == 0:
        return ["python3", script_path, *extra_args]
    return ["sudo", "-n", "python3", script_path, *extra_args]


def run_tool_safely(script_path, display):
    try:
        if os.path.basename(script_path) in ("vpn_puller.py", "vpn_pullerv2.py"):
            user_ip = os.environ.get("DEDSEC_SOURCE_IP") or os.environ.get("SSH_CLIENT", "").split(" ")[0]
            return subprocess.run(_tool_cmd(script_path, [user_ip] if user_ip else []))
        return subprocess.run(_tool_cmd(script_path))
    except Exception as e:
        error_text = str(e)
        log_tool_error(script_path, display, error_text)
        raise


def _fmt_duration(seconds):
    if seconds < 60:
        return f"{seconds:.1f}s"
    m, s = divmod(int(seconds), 60)
    return f"{m}m {s}s"


def browse_scripts(category_name, category_display):
    page = 1
    page_size = 8
    while True:
        screen("Home", "Tools", category_display)
        scripts = get_scripts(category_name)

        if not scripts:
            draw_box([f"{RED}No scripts found in this category.{RESET}"],
                     title=category_display, color=RED)
            pause()
            return

        total_pages = max(1, (len(scripts) + page_size - 1) // page_size)
        if page > total_pages:
            page = total_pages
        start = (page - 1) * page_size
        chunk = scripts[start:start + page_size]

        title = category_display
        if total_pages > 1:
            title = f"{category_display}  (page {page}/{total_pages})"

        items = [(str(i), display, "") for i, (_, display) in enumerate(chunk, start=start + 1)]
        items.append(("__sep__", "", ""))
        if page < total_pages:
            items.append(("N", "Next page", f"{start + len(chunk) + 1}+"))
        if page > 1:
            items.append(("P", "Previous page", ""))
        items.append(("0", "Back", "q / b"))
        menu(items, title=title)

        choice = prompt("\nSelect a script:")

        if is_back(choice):
            return
        if choice.lower() == "n" and page < total_pages:
            page += 1
            continue
        if choice.lower() == "p" and page > 1:
            page -= 1
            continue

        if not choice.isdigit():
            msg("error", "Invalid choice.")
            pause()
            continue

        idx = int(choice)
        if idx < 1 or idx > len(scripts):
            msg("error", "Invalid choice.")
            pause()
            continue

        script_path, display = scripts[idx - 1]

        log_tool_usage(category_name, script_path)

        user = os.environ.get("DEDSEC_USER", "unknown")
        ip = os.environ.get("DEDSEC_SOURCE_IP", "unknown")
        role = os.environ.get("DEDSEC_ROLE", "standard")
        event_type = "admin_tools" if category_name == ADMIN_CATEGORY else "tools"

        discord_alert(
            "\U0001f6e0\ufe0f DEDSEC Tool Started",
            (
                f"\U0001f464 **User:** `{user}`\n"
                f"\U0001f310 **IP:** `{ip}`\n"
                f"\U0001f3ad **Role:** `{role}`\n\n"
                f"\U0001f4c2 **Category:** `{category_name}`\n"
                f"\U0001f4e6 **Tool:** `{display}`\n"
                f"\U0001f4c4 **Path:** `{script_path}`"
            ),
            color=15844367,
            event_type=event_type,
        )

        screen("Home", "Tools", category_display, display)
        draw_box([f"{WHITE}Running:{RESET} {YELLOW}{display}{RESET}",
                  f"{DIM}{script_path}{RESET}"],
                 title=f"{GREEN}{BOLD}Running Tool{RESET}", color=GREEN)
        print()

        start_t = time.monotonic()
        result = run_tool_safely(script_path, display)
        duration = time.monotonic() - start_t

        if result.returncode != 0:
            error_text = result.stderr or "Tool exited with non-zero status."
            log_tool_error(script_path, display, error_text)

        exit_code = result.returncode
        status_icon = "\u2705" if exit_code == 0 else "\u274c"
        status_text = "Finished" if exit_code == 0 else "Failed"
        finish_color = 3066993 if exit_code == 0 else 15158332

        discord_alert(
            f"{status_icon} DEDSEC Tool {status_text}",
            (
                f"\U0001f464 **User:** `{os.environ.get('DEDSEC_USER', 'unknown')}`\n"
                f"\U0001f310 **IP:** `{os.environ.get('DEDSEC_SOURCE_IP', 'unknown')}`\n"
                f"\U0001f3ad **Role:** `{os.environ.get('DEDSEC_ROLE', 'standard')}`\n\n"
                f"\U0001f4c2 **Category:** `{category_name}`\n"
                f"\U0001f4e6 **Tool:** `{display}`\n"
                f"\U0001f4c4 **Path:** `{script_path}`\n\n"
                f"{status_icon} **Status:** `{status_text}`\n"
                f"\U0001f522 **Exit Code:** `{exit_code}`"
            ),
            color=finish_color,
            event_type="admin_tools" if category_name == ADMIN_CATEGORY else "tools",
        )

        no_pause_tools = ["tcpdump_tool.py", "my_live_traffic.py"]

        if os.path.basename(script_path) not in no_pause_tools or result.returncode != 0:
            print()
            res_col = GREEN if exit_code == 0 else RED
            footer = [
                f"{res_col}{status_icon} {status_text}{RESET}   "
                f"{WHITE}exit {exit_code}{RESET}   "
                f"{DIM}{_fmt_duration(duration)}{RESET}",
            ]
            if exit_code != 0:
                footer.append(f"{CYAN}Error logged to:{RESET} {YELLOW}{ERROR_LOG}{RESET}")
            draw_box(footer, title="Result", color=res_col)
            pause()


def render_home():
    update_session_heartbeat()
    screen("Home")
    show_admin_notice()
    show_expiry_warning()
    menu([
        ("1", "My Account", "profile, theme"),
        ("2", "Updates / Announcements", "read-only"),
        ("3", "Help / Tickets", "support"),
        ("4", "General Chat", "community"),
        ("5", "Browse Tool Categories", "lab tools"),
        ("__sep__", "", ""),
        ("6", "Exit", "close session"),
    ], title="DEDSEC Lab")


def main():
    while True:
        try:
            render_home()
            choice = prompt("\nSelect an option:")

            if choice == "1":
                show_account()
            elif choice == "2":
                # Read-only: available to everyone (bug fix).
                show_updates()
            elif choice == "3":
                open_ticket_system()
            elif choice == "4":
                open_general_chat()
            elif choice == "5":
                browse_categories()
            elif choice == "6":
                msg("info", "Goodbye.")
                break
            else:
                msg("error", "Invalid option.")
                pause()
        except _SessionEnd:
            # Ctrl+D / closed stdin: end the session cleanly, no shell, no spin.
            log_admin_event("SESSION_END | stdin closed (EOF)")
            print(f"\n{YELLOW}Session closed.{RESET}")
            break
        except Exception:
            # Never die with a traceback to the terminal; log and redraw.
            try:
                os.makedirs(LOGS_DIR, exist_ok=True)
                with open(ERROR_LOG, "a", encoding="utf-8") as f:
                    f.write("=" * 80 + "\n")
                    f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | MENU_ERROR\n")
                    f.write(traceback.format_exc())
            except Exception:
                pass
            try:
                msg("error", "Something went wrong. The menu has been reloaded.")
                pause()
            except _SessionEnd:
                break


# Runs unconditionally, like the original module-level loop.
main()
