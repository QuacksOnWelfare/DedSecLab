#!/usr/bin/env python3
import os
import re
import sys
import json
import shutil
import subprocess
import signal
import hashlib
import base64
from datetime import datetime, date, timedelta


def auto_root():
    if os.geteuid() != 0:
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)


auto_root()

BASE_DIR = "/opt/secure-scripts/dedsec-labNEW"
LOGS_DIR = os.path.join(BASE_DIR, "logs")
RULES_FILE = os.path.join(BASE_DIR, "access_rules.json")
BACKUP_DIR = os.path.join(BASE_DIR, "backups")
OUTPUT_DIR = "/opt/secure-scripts/dedsec-labNEW/etc/www/"
WEBSITE_USER_DOWNLOADS_DIR = ""  # optional: folder for user downloads

DJANGO_SITE_DIR = ""  # optional: set only if you also host a companion site

EASYRSA_DIR = "/etc/openvpn/server/easy-rsa"
CCD_DIR = "/etc/openvpn/server/ccd"
TLS_CRYPT_KEY = "/etc/openvpn/server/tc.key"
CA_FILE = os.path.join(EASYRSA_DIR, "pki/ca.crt")
CRL_DST = "/etc/openvpn/server/crl.pem"

REMOTE_HOST = "YOUR_VPN_SERVER"
REMOTE_PORT = "9981"
PROTO = "udp"
DEV = "tun"

VPN_NET_PREFIX = "10.8.0."
FIRST_CUSTOMER_IP = 4
LAST_CUSTOMER_IP = 254

RESET = "\033[0m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
WHITE = "\033[97m"
RED = "\033[31m"
BOLD = "\033[1m"

PROTECTED_USERNAMES = [
    "YOUR_PROTECTED_USERNAME",  # usernames that cannot be deleted
]


def handle_sigint(signum, frame):
    print(f"\n{YELLOW}Use the menu to exit cleanly.{RESET}")


def handle_sigtstp(signum, frame):
    print(f"\n{YELLOW}Use the menu to exit cleanly.{RESET}")


signal.signal(signal.SIGINT, handle_sigint)
signal.signal(signal.SIGTSTP, handle_sigtstp)

os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(BACKUP_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(CCD_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOGS_DIR, "ssh_whitelist_manager.log")


def clear():
    os.system("clear")


def pause():
    input(f"\n{YELLOW}Press Enter to continue...{RESET}")


def banner():
    import importlib.util

    banner_path = os.path.join(BASE_DIR, "utils", "banner.py")
    spec = importlib.util.spec_from_file_location("dedsec_banner", banner_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    def noop_theme():
        return None

    mod.dedsec_banner(GREEN, CYAN, RESET, BOLD, noop_theme)


def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{timestamp} | {message}\n")


def run_cmd(cmd, cwd=None):
    try:
        result = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return 1, "", str(e)


def load_rules():
    if not os.path.isfile(RULES_FILE):
        return {"vpn_locations": {"UK": {"enabled": True}}, "users": {}}

    with open(RULES_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def backup_rules():
    if os.path.isfile(RULES_FILE):
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(BACKUP_DIR, f"access_rules_{stamp}.json")
        shutil.copyfile(RULES_FILE, backup_path)


def save_rules(rules):
    backup_rules()

    with open(RULES_FILE, "w", encoding="utf-8") as f:
        json.dump(rules, f, indent=2)

    log("SAVED access_rules.json")


def valid_name(name):
    return re.fullmatch(r"[A-Za-z0-9_-]{2,40}", name) is not None


def clean_name(name):
    name = re.sub(r"[^A-Za-z0-9_-]", "_", name.strip())
    return name[:25] if name else "user"


def make_app_username(display_name):
    return clean_name(display_name).lower()


def make_app_password_hash(password):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200000)

    return (
        "pbkdf2_sha256$200000$"
        + base64.b64encode(salt).decode()
        + "$"
        + base64.b64encode(dk).decode()
    )


def find_django_settings_module():
    """Not configured: return None."""
    return None


def create_or_update_website_user(username, password, display_name="", role="standard", enabled=True):
    """Hook for an optional companion website. Not configured by default."""
    return True, "website sync not configured"


def delete_website_user(username):
    """Hook for an optional companion website. Not configured by default."""
    return True, "website sync not configured"


def parse_date(value):
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except Exception:
        return None


def days_left(expiry):
    expiry_date = parse_date(expiry)

    if not expiry_date:
        return None

    return (expiry_date - date.today()).days


def cert_path(config_name):
    return os.path.join(EASYRSA_DIR, "pki", "issued", config_name + ".crt")


def key_path(config_name):
    return os.path.join(EASYRSA_DIR, "pki", "private", config_name + ".key")


def ovpn_path(config_name):
    return os.path.join(OUTPUT_DIR, config_name + ".ovpn")


def user_download_dir(app_username):
    safe_user = clean_name(app_username).lower()
    return os.path.join(WEBSITE_USER_DOWNLOADS_DIR, safe_user)


def user_ovpn_path(app_username, config_name):
    return os.path.join(user_download_dir(app_username), config_name + ".ovpn")


def ensure_user_download_root():
    os.makedirs(WEBSITE_USER_DOWNLOADS_DIR, exist_ok=True)
    os.chmod(WEBSITE_USER_DOWNLOADS_DIR, 0o750)


def copy_config_to_user_download_folder(app_username, config_name):
    ensure_user_download_root()

    folder = user_download_dir(app_username)
    os.makedirs(folder, exist_ok=True)

    src = ovpn_path(config_name)
    dst = user_ovpn_path(app_username, config_name)

    if not os.path.isfile(src):
        return False, f"Source config not found: {src}"

    shutil.copyfile(src, dst)
    os.chmod(folder, 0o750)
    os.chmod(dst, 0o640)

    return True, dst


def ccd_path(config_name):
    return os.path.join(CCD_DIR, config_name)


def read_file(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def check_vpn_paths():
    missing = []

    for path in [EASYRSA_DIR, CA_FILE, TLS_CRYPT_KEY, CCD_DIR]:
        if not os.path.exists(path):
            missing.append(path)

    if missing:
        print(f"{RED}Missing VPN files/folders:{RESET}")

        for item in missing:
            print(f"{YELLOW}- {item}{RESET}")

        return False

    return True


def used_ips_from_rules(rules):
    return set(rules.get("users", {}).keys())


def used_ips_from_ccd():
    used = set()

    if not os.path.isdir(CCD_DIR):
        return used

    for item in os.listdir(CCD_DIR):
        path = os.path.join(CCD_DIR, item)

        if not os.path.isfile(path):
            continue

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()

                    if line.startswith("ifconfig-push"):
                        parts = line.split()

                        if len(parts) >= 2:
                            used.add(parts[1])
        except Exception:
            pass

    return used


def get_next_free_ip(rules):
    used = used_ips_from_rules(rules) | used_ips_from_ccd()

    for last_octet in range(FIRST_CUSTOMER_IP, LAST_CUSTOMER_IP + 1):
        ip = f"{VPN_NET_PREFIX}{last_octet}"

        if ip not in used:
            return ip

    return None


def make_config_name(display_name, expiry_date):
    base = clean_name(display_name)
    stamp = datetime.now().strftime("%H%M%S")
    return f"{base}_{expiry_date.strftime('%Y%m%d')}_{stamp}"


def create_ccd(config_name, vpn_ip):
    with open(ccd_path(config_name), "w", encoding="utf-8") as f:
        f.write(f"ifconfig-push {vpn_ip} 255.255.255.0\n")

    os.chmod(ccd_path(config_name), 0o644)


def delete_ccd(config_name):
    if config_name and os.path.exists(ccd_path(config_name)):
        os.remove(ccd_path(config_name))


def create_vpn_config(config_name, days, vpn_ip):
    code, out, err = run_cmd(
        ["./easyrsa", "--batch", f"--days={days}", "build-client-full", config_name, "nopass"],
        cwd=EASYRSA_DIR
    )

    if code != 0:
        return False, err or out

    create_ccd(config_name, vpn_ip)

    ovpn = f"""client
dev {DEV}
proto {PROTO}
remote {REMOTE_HOST} {REMOTE_PORT}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
verb 3

<ca>
{read_file(CA_FILE)}
</ca>

<cert>
{read_file(cert_path(config_name))}
</cert>

<key>
{read_file(key_path(config_name))}
</key>

<tls-crypt>
{read_file(TLS_CRYPT_KEY)}
</tls-crypt>
"""

    with open(ovpn_path(config_name), "w", encoding="utf-8") as f:
        f.write(ovpn)

    os.chmod(ovpn_path(config_name), 0o600)

    return True, ovpn_path(config_name)


def revoke_vpn_config(config_name):
    if not config_name:
        return True, "No config linked"

    run_cmd(["./easyrsa", "--batch", "revoke", config_name], cwd=EASYRSA_DIR)
    run_cmd(["./easyrsa", "gen-crl"], cwd=EASYRSA_DIR)

    crl_src = os.path.join(EASYRSA_DIR, "pki", "crl.pem")

    if os.path.exists(crl_src):
        shutil.copyfile(crl_src, CRL_DST)
        os.chmod(CRL_DST, 0o644)

    if os.path.exists(ovpn_path(config_name)):
        os.remove(ovpn_path(config_name))

    delete_ccd(config_name)
    run_cmd(["systemctl", "restart", "openvpn-server@server"])

    return True, "Revoked, deleted .ovpn, deleted CCD, restarted OpenVPN"


def add_user():
    clear()
    banner()

    rules = load_rules()
    users = rules.setdefault("users", {})
    ensure_user_download_root()
    vpn_ip = get_next_free_ip(rules)

    if not vpn_ip:
        print(f"{RED}No free VPN IPs available.{RESET}")
        pause()
        return

    print(f"{WHITE}Auto assigned VPN IP:{RESET} {YELLOW}{vpn_ip}{RESET}\n")

    display_name = input(f"{YELLOW}Display name:{RESET} ").strip()

    if not display_name:
        print(f"{RED}Display name required.{RESET}")
        pause()
        return

    ssh_user = input(f"{YELLOW}SSH user [{os.environ.get('SUDO_USER', 'dedsecuser')}]:{RESET} ").strip()

    if not ssh_user:
        ssh_user = os.environ.get("SUDO_USER", "dedsecuser")

    discord_name = input(f"{YELLOW}Discord name optional:{RESET} ").strip()
    discord_id = input(f"{YELLOW}Discord ID optional:{RESET} ").strip()

    app_username_default = make_app_username(display_name)
    app_username = input(f"{YELLOW}App/Website username [{app_username_default}]:{RESET} ").strip()

    if not app_username:
        app_username = app_username_default

    if not valid_name(app_username):
        print(f"{RED}Invalid app username. Use letters, numbers, _ or - only.{RESET}")
        pause()
        return

    if app_username.lower() in PROTECTED_USERNAMES:
        print(f"{RED}That username is protected/reserved.{RESET}")
        pause()
        return

    app_password = input(f"{YELLOW}Temporary app/website password:{RESET} ").strip()

    if len(app_password) < 8:
        print(f"{RED}App password must be at least 8 characters.{RESET}")
        pause()
        return

    app_password_hash = make_app_password_hash(app_password)

    role = "standard"
    print(f"{WHITE}Role:{RESET} {YELLOW}standard{RESET}")

    region = input(f"{YELLOW}VPN region [UK]:{RESET} ").strip().upper()

    if not region:
        region = "UK"

    days = input(f"{YELLOW}Subscription days:{RESET} ").strip()

    if not days.isdigit() or int(days) < 1:
        print(f"{RED}Invalid days.{RESET}")
        pause()
        return

    expiry_date = date.today() + timedelta(days=int(days))

    if not check_vpn_paths():
        pause()
        return

    config_name = make_config_name(display_name, expiry_date)

    print()
    print(f"{WHITE}Creating user:{RESET} {YELLOW}{display_name}{RESET}")
    print(f"{WHITE}VPN IP:{RESET} {YELLOW}{vpn_ip}{RESET}")
    print(f"{WHITE}Config:{RESET} {YELLOW}{config_name}.ovpn{RESET}")
    print(f"{WHITE}Expiry:{RESET} {YELLOW}{expiry_date}{RESET}")
    print(f"{WHITE}App/Website username:{RESET} {YELLOW}{app_username}{RESET}")
    print(f"{WHITE}SSH wrapper user:{RESET} {YELLOW}{ssh_user}{RESET}")
    print(f"{GREEN}{'-' * 46}{RESET}")

    ok, msg = create_vpn_config(config_name, int(days), vpn_ip)

    if not ok:
        print(f"{RED}Failed to create VPN config:{RESET}")
        print(msg)
        pause()
        return

    user_config_ok, user_config_msg = copy_config_to_user_download_folder(
        app_username,
        config_name
    )

    if not user_config_ok:
        print(f"{RED}Failed to copy config to website user folder:{RESET}")
        print(user_config_msg)
        pause()
        return

    website_ok, website_msg = create_or_update_website_user(
        username=app_username,
        password=app_password,
        display_name=display_name,
        role=role,
        enabled=True
    )

    if not website_ok:
        print(f"{RED}Failed to create website user:{RESET}")
        print(website_msg)
        pause()
        return

    users[vpn_ip] = {
        "display_name": display_name,
        "config_name": config_name,
        "ssh_user": ssh_user,
        "discord_name": discord_name,
        "discord_id": discord_id,
        "enabled": True,
        "role": role,
        "current_vpn_region": region,
        "subscription_expires": expiry_date.strftime("%Y-%m-%d"),
        "welcome_message": "Welcome to DEDSEC LAB",
        "app_username": app_username,
        "app_password_hash": app_password_hash,
        "user_download_folder": user_download_dir(app_username),
        "user_ovpn_file": user_config_msg
    }

    save_rules(rules)
    run_cmd(["systemctl", "restart", "openvpn-server@server"])

    print(f"{GREEN}User added successfully.{RESET}")
    print(f"{WHITE}VPN IP:{RESET} {YELLOW}{vpn_ip}{RESET}")
    print(f"{WHITE}Private config saved:{RESET} {YELLOW}{msg}{RESET}")
    print(f"{WHITE}Website user config:{RESET} {YELLOW}{user_config_msg}{RESET}")
    print(f"{WHITE}CCD created:{RESET} {YELLOW}{ccd_path(config_name)}{RESET}")
    print(f"{WHITE}App username:{RESET} {YELLOW}{app_username}{RESET}")
    print(f"{WHITE}Website login:{RESET} {YELLOW}{website_msg}{RESET}")
    print(f"{WHITE}SSH wrapper user:{RESET} {YELLOW}{ssh_user}{RESET}")
    print(f"{WHITE}Temporary app/website password:{RESET} {YELLOW}{app_password}{RESET}")
    print(f"{RED}Give this password to the user once. It is not saved in plain text.{RESET}")

    pause()


def list_users():
    clear()
    banner()

    rules = load_rules()
    users = rules.get("users", {})

    print(f"{WHITE}{BOLD}Whitelisted Users:{RESET}\n")

    if not users:
        print(f"{RED}No users found.{RESET}")
        pause()
        return

    for ip, user in sorted(users.items()):
        name = user.get("display_name", "unknown")
        role = user.get("role", "standard")
        enabled = user.get("enabled", True)
        expiry = user.get("subscription_expires", "N/A")
        left = days_left(expiry)
        config = user.get("config_name", "")
        app_username = user.get("app_username", "N/A")
        ssh_user = user.get("ssh_user", "N/A")

        if not enabled:
            status = f"{RED}DISABLED{RESET}"
        elif left is None:
            status = f"{YELLOW}UNKNOWN{RESET}"
        elif left < 0:
            status = f"{RED}EXPIRED {abs(left)}d ago{RESET}"
        elif left <= 3:
            status = f"{RED}{left}d left{RESET}"
        elif left <= 7:
            status = f"{YELLOW}{left}d left{RESET}"
        else:
            status = f"{GREEN}{left}d left{RESET}"

        print(f"{CYAN}{BOLD}{ip}{RESET}  {WHITE}{name}{RESET}")
        print(f"   {WHITE}Role:{RESET} {YELLOW}{role}{RESET}  {WHITE}Expiry:{RESET} {YELLOW}{expiry}{RESET}  {WHITE}Status:{RESET} {status}")
        print(f"   {WHITE}App/Website Username:{RESET} {YELLOW}{app_username}{RESET}")
        print(f"   {WHITE}SSH Wrapper User:{RESET} {YELLOW}{ssh_user}{RESET}")
        print(f"   {WHITE}Config:{RESET} {YELLOW}{config if config else 'none'}{RESET}")

        if config:
            print(f"   {WHITE}CCD:{RESET} {YELLOW}{'yes' if os.path.exists(ccd_path(config)) else 'no'}{RESET}")

    pause()


def extend_user():
    clear()
    banner()

    rules = load_rules()
    users = rules.get("users", {})
    vpn_ip = input(f"{YELLOW}VPN IP to extend:{RESET} ").strip()

    if vpn_ip not in users:
        print(f"{RED}User not found.{RESET}")
        pause()
        return

    user = users[vpn_ip]
    old_expiry = parse_date(user.get("subscription_expires", ""))
    start_date = old_expiry if old_expiry and old_expiry >= date.today() else date.today()

    add_days = input(f"{YELLOW}Add how many days?:{RESET} ").strip()

    if not add_days.isdigit() or int(add_days) < 1:
        print(f"{RED}Invalid days.{RESET}")
        pause()
        return

    new_expiry = start_date + timedelta(days=int(add_days))
    cert_days = max((new_expiry - date.today()).days, 1)

    old_config = user.get("config_name", "")
    display_name = user.get("display_name", vpn_ip)

    print(f"{WHITE}Current expiry:{RESET} {YELLOW}{user.get('subscription_expires', 'N/A')}{RESET}")
    print(f"{WHITE}New expiry:{RESET} {YELLOW}{new_expiry}{RESET}")
    print(f"{WHITE}VPN IP kept:{RESET} {YELLOW}{vpn_ip}{RESET}")
    print(f"{WHITE}Old config:{RESET} {YELLOW}{old_config if old_config else 'none'}{RESET}")

    confirm = input(f"{RED}Renew user and generate new VPN config? Type YES:{RESET} ").strip()

    if confirm.upper() != "YES":
        print(f"{YELLOW}Cancelled.{RESET}")
        pause()
        return

    if not check_vpn_paths():
        pause()
        return

    if old_config:
        revoke_vpn_config(old_config)

    new_config = make_config_name(display_name, new_expiry)
    ok, msg = create_vpn_config(new_config, cert_days, vpn_ip)

    if not ok:
        print(f"{RED}Failed to create renewed config:{RESET}")
        print(msg)
        pause()
        return

    user["subscription_expires"] = new_expiry.strftime("%Y-%m-%d")
    user["config_name"] = new_config
    user["enabled"] = True

    save_rules(rules)
    run_cmd(["systemctl", "restart", "openvpn-server@server"])

    print(f"{GREEN}User renewed successfully.{RESET}")
    print(f"{WHITE}VPN IP:{RESET} {YELLOW}{vpn_ip}{RESET}")
    print(f"{WHITE}New config:{RESET} {YELLOW}{new_config}.ovpn{RESET}")
    print(f"{WHITE}Saved to:{RESET} {YELLOW}{msg}{RESET}")

    pause()


def set_user_enabled(enabled):
    clear()
    banner()

    rules = load_rules()
    users = rules.get("users", {})
    vpn_ip = input(f"{YELLOW}VPN IP:{RESET} ").strip()

    if vpn_ip not in users:
        print(f"{RED}User not found.{RESET}")
        pause()
        return

    users[vpn_ip]["enabled"] = enabled
    save_rules(rules)

    print(f"{GREEN}User updated.{RESET}")
    print(f"{WHITE}{vpn_ip}:{RESET} {YELLOW}{'enabled' if enabled else 'disabled'}{RESET}")

    pause()


def delete_user():
    clear()
    banner()

    rules = load_rules()
    users = rules.get("users", {})
    vpn_ip = input(f"{YELLOW}VPN IP to delete:{RESET} ").strip()

    if vpn_ip not in users:
        print(f"{RED}User not found.{RESET}")
        pause()
        return

    config_name = users[vpn_ip].get("config_name", "")
    app_username = users[vpn_ip].get("app_username", "")

    confirm = input(f"{RED}Delete user, website login, and revoke linked VPN config? Type YES:{RESET} ").strip()

    if confirm.upper() != "YES":
        print(f"{YELLOW}Cancelled.{RESET}")
        pause()
        return

    if config_name:
        revoke_vpn_config(config_name)

    web_ok, web_msg = delete_website_user(app_username)

    if web_ok:
        print(f"{GREEN}{web_msg}{RESET}")
    else:
        print(f"{YELLOW}Website delete warning:{RESET} {web_msg}")

    del users[vpn_ip]
    save_rules(rules)

    print(f"{GREEN}User deleted and VPN config revoked.{RESET}")

    pause()


def link_config():
    clear()
    banner()

    rules = load_rules()
    users = rules.get("users", {})
    vpn_ip = input(f"{YELLOW}VPN IP:{RESET} ").strip()

    if vpn_ip not in users:
        print(f"{RED}User not found.{RESET}")
        pause()
        return

    config = input(f"{YELLOW}Config name without .ovpn:{RESET} ").strip()

    if config.endswith(".ovpn"):
        config = config[:-5]

    if not valid_name(config):
        print(f"{RED}Invalid config name.{RESET}")
        pause()
        return

    create_static = input(f"{YELLOW}Create/update CCD static IP for this config? yes/no [yes]:{RESET} ").strip().lower()

    if create_static in ["", "y", "yes"]:
        create_ccd(config, vpn_ip)
        run_cmd(["systemctl", "restart", "openvpn-server@server"])

    users[vpn_ip]["config_name"] = config
    save_rules(rules)

    print(f"{GREEN}Linked config:{RESET} {YELLOW}{config}{RESET}")
    print(f"{GREEN}VPN IP forced to:{RESET} {YELLOW}{vpn_ip}{RESET}")

    pause()



def copy_existing_config_to_user_folder():
    clear()
    banner()

    rules = load_rules()
    users = rules.get("users", {})

    vpn_ip = input(f"{YELLOW}VPN IP to copy config for:{RESET} ").strip()

    if vpn_ip not in users:
        print(f"{RED}User not found.{RESET}")
        pause()
        return

    user = users[vpn_ip]
    app_username = user.get("app_username", "")
    config_name = user.get("config_name", "")

    if not app_username:
        print(f"{RED}User has no app_username in JSON.{RESET}")
        pause()
        return

    if not config_name:
        print(f"{RED}User has no config_name in JSON.{RESET}")
        pause()
        return

    ok, msg = copy_config_to_user_download_folder(app_username, config_name)

    if not ok:
        print(f"{RED}Failed to copy config:{RESET}")
        print(msg)
        pause()
        return

    user["user_download_folder"] = user_download_dir(app_username)
    user["user_ovpn_file"] = msg
    save_rules(rules)

    print(f"{GREEN}Config copied to website user folder.{RESET}")
    print(f"{WHITE}User:{RESET} {YELLOW}{app_username}{RESET}")
    print(f"{WHITE}File:{RESET} {YELLOW}{msg}{RESET}")

    pause()

def main():
    while True:
        clear()
        banner()

        print(f"{WHITE}{BOLD}SSH/VPN Whitelist Manager:{RESET}\n")
        print(f"{CYAN}{BOLD}1.{RESET}  {WHITE}Add User + Auto VPN IP + Config + App Login + Website Login{RESET}")
        print(f"{CYAN}{BOLD}2.{RESET}  {WHITE}List Users + Days Left{RESET}")
        print(f"{CYAN}{BOLD}3.{RESET}  {WHITE}Extend User + Renew VPN Config{RESET}")
        print(f"{CYAN}{BOLD}4.{RESET}  {WHITE}Disable User{RESET}")
        print(f"{CYAN}{BOLD}5.{RESET}  {WHITE}Enable User{RESET}")
        print(f"{CYAN}{BOLD}6.{RESET}  {WHITE}Delete User + Revoke VPN Config{RESET}")
        print(f"{CYAN}{BOLD}7.{RESET}  {WHITE}Link Existing Config + Create CCD{RESET}")
        print(f"{CYAN}{BOLD}8.{RESET}  {WHITE}Copy Existing User Config To Website Folder{RESET}")
        print(f"{CYAN}{BOLD}0.{RESET}  {WHITE}Back / Exit{RESET}")
        print()
        print(f"{GREEN}{'-' * 46}{RESET}")

        try:
            choice = input(f"{YELLOW}Select an option:{RESET} ").strip()
        except KeyboardInterrupt:
            print(f"\n{YELLOW}Use the menu to exit cleanly.{RESET}")
            pause()
            continue

        if choice == "1":
            add_user()
        elif choice == "2":
            list_users()
        elif choice == "3":
            extend_user()
        elif choice == "4":
            set_user_enabled(False)
        elif choice == "5":
            set_user_enabled(True)
        elif choice == "6":
            delete_user()
        elif choice == "7":
            link_config()
        elif choice == "8":
            copy_existing_config_to_user_folder()
        elif choice == "0":
            break
        else:
            print(f"{RED}Invalid option.{RESET}")
            pause()


if __name__ == "__main__":
    main()
