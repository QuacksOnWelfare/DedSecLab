#!/usr/bin/env python3
import os
import sys
import subprocess
import signal
from datetime import datetime

BASE_DIR = "/opt/secure-scripts/dedsec-labNEW"
LOGS_DIR = os.path.join(BASE_DIR, "logs")
SERVICE_NAME = "dedsec-api"
SERVICE_FILE = f"/etc/systemd/system/{SERVICE_NAME}.service"
API_HOST = "YOUR_LAB_VPN_IP"
API_PORT = "8443"
APP_API = os.path.join(BASE_DIR, "app_api.py")
VENV_UVICORN = os.path.join(BASE_DIR, "venv", "bin", "uvicorn")
LOG_FILE = os.path.join(LOGS_DIR, "api_manager.log")

RESET = "\033[0m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
WHITE = "\033[97m"
RED = "\033[31m"
BOLD = "\033[1m"


def auto_root():
    if os.geteuid() != 0:
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)


auto_root()
os.makedirs(LOGS_DIR, exist_ok=True)


def handle_sigint(signum, frame):
    print(f"\n{YELLOW}Use the menu to exit cleanly.{RESET}")


signal.signal(signal.SIGINT, handle_sigint)
signal.signal(signal.SIGTSTP, handle_sigint)


def clear():
    os.system("clear")


def pause():
    input(f"\n{YELLOW}Press Enter to continue...{RESET}")


def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{timestamp} | {message}\n")


def banner():
    import importlib.util

    banner_path = os.path.join(BASE_DIR, "utils", "banner.py")
    spec = importlib.util.spec_from_file_location("dedsec_banner", banner_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    def noop_theme():
        return None

    mod.dedsec_banner(GREEN, CYAN, RESET, BOLD, noop_theme)


def run_cmd(cmd):
    return subprocess.run(cmd, text=True, capture_output=True)


def service_exists():
    return os.path.isfile(SERVICE_FILE)


def install_service():
    if not os.path.isfile(APP_API):
        print(f"{RED}Missing app_api.py:{RESET} {YELLOW}{APP_API}{RESET}")
        pause()
        return

    if not os.path.isfile(VENV_UVICORN):
        print(f"{RED}Missing uvicorn in venv:{RESET} {YELLOW}{VENV_UVICORN}{RESET}")
        print(f"{YELLOW}Run: cd {BASE_DIR} && source venv/bin/activate && pip install fastapi uvicorn{RESET}")
        pause()
        return

    service_content = f"""[Unit]
Description=DEDSEC Lab API
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={BASE_DIR}
ExecStart={VENV_UVICORN} app_api:app --host {API_HOST} --port {API_PORT} --ssl-certfile {BASE_DIR}/certs/cert.pem --ssl-keyfile {BASE_DIR}/certs/key.pem
Restart=always
RestartSec=3
User=root
Group=root

[Install]
WantedBy=multi-user.target
"""

    with open(SERVICE_FILE, "w", encoding="utf-8") as f:
        f.write(service_content)

    run_cmd(["systemctl", "daemon-reload"])
    run_cmd(["systemctl", "enable", SERVICE_NAME])

    log("Installed and enabled API systemd service")

    print(f"{GREEN}Service installed and enabled:{RESET} {YELLOW}{SERVICE_NAME}{RESET}")
    print(f"{WHITE}API:{RESET} {CYAN}https://{API_HOST}:{API_PORT}{RESET}")
    pause()


def start_service():
    result = run_cmd(["systemctl", "start", SERVICE_NAME])
    log("Started API service")

    if result.returncode == 0:
        print(f"{GREEN}API service started.{RESET}")
    else:
        print(f"{RED}Failed to start API service.{RESET}")
        print(result.stderr)

    pause()


def stop_service():
    result = run_cmd(["systemctl", "stop", SERVICE_NAME])
    log("Stopped API service")

    if result.returncode == 0:
        print(f"{GREEN}API service stopped.{RESET}")
    else:
        print(f"{RED}Failed to stop API service.{RESET}")
        print(result.stderr)

    pause()


def restart_service():
    result = run_cmd(["systemctl", "restart", SERVICE_NAME])
    log("Restarted API service")

    if result.returncode == 0:
        print(f"{GREEN}API service restarted.{RESET}")
    else:
        print(f"{RED}Failed to restart API service.{RESET}")
        print(result.stderr)

    pause()


def show_status():
    clear()
    banner()

    print(f"{WHITE}{BOLD}DEDSEC API Status:{RESET}\n")

    result = run_cmd(["systemctl", "is-active", SERVICE_NAME])
    active = result.stdout.strip()

    enabled_result = run_cmd(["systemctl", "is-enabled", SERVICE_NAME])
    enabled = enabled_result.stdout.strip()

    port_result = run_cmd(["ss", "-tulpn"])
    port_lines = [
        line for line in port_result.stdout.splitlines()
        if f":{API_PORT}" in line
    ]

    print(f"{CYAN}Service:{RESET} {YELLOW}{SERVICE_NAME}{RESET}")
    print(f"{CYAN}State:{RESET}   {GREEN if active == 'active' else RED}{active or 'unknown'}{RESET}")
    print(f"{CYAN}Boot:{RESET}    {GREEN if enabled == 'enabled' else YELLOW}{enabled or 'unknown'}{RESET}")
    print(f"{CYAN}API URL:{RESET} {YELLOW}https://{API_HOST}:{API_PORT}{RESET}")
    print()

    print(f"{WHITE}{BOLD}Port Check:{RESET}")
    if port_lines:
        for line in port_lines:
            print(f"{GREEN}{line}{RESET}")
    else:
        print(f"{RED}Nothing is listening on port {API_PORT}.{RESET}")

    print()
    print(f"{WHITE}{BOLD}Recent Logs:{RESET}")
    logs = run_cmd(["journalctl", "-u", SERVICE_NAME, "-n", "15", "--no-pager"])

    if logs.stdout.strip():
        print(logs.stdout)
    else:
        print(f"{YELLOW}No journal logs found yet.{RESET}")

    pause()


def show_live_logs():
    clear()
    banner()
    print(f"{WHITE}{BOLD}Live API Logs:{RESET}")
    print(f"{YELLOW}Press CTRL+C to return to menu.{RESET}\n")

    try:
        subprocess.run(["journalctl", "-u", SERVICE_NAME, "-f"])
    except KeyboardInterrupt:
        pass


def test_api():
    clear()
    banner()

    print(f"{WHITE}{BOLD}Testing API endpoint:{RESET}\n")
    print(f"{CYAN}URL:{RESET} {YELLOW}https://{API_HOST}:{API_PORT}/api/me{RESET}\n")

    result = run_cmd(["curl", "-sk", f"https://{API_HOST}:{API_PORT}/api/me"])

    if result.returncode != 0:
        print(f"{RED}curl failed.{RESET}")
        print(result.stderr)
    elif result.stdout.strip():
        print(result.stdout)
    else:
        print(f"{RED}No response from API.{RESET}")

    pause()


def main():
    while True:
        clear()
        banner()

        print(f"{WHITE}{BOLD}DEDSEC API Manager:{RESET}\n")
        print(f"{CYAN}{BOLD}1.{RESET}  {WHITE}Install / Update API Service{RESET}")
        print(f"{CYAN}{BOLD}2.{RESET}  {WHITE}Start API{RESET}")
        print(f"{CYAN}{BOLD}3.{RESET}  {WHITE}Stop API{RESET}")
        print(f"{CYAN}{BOLD}4.{RESET}  {WHITE}Restart API{RESET}")
        print(f"{CYAN}{BOLD}5.{RESET}  {WHITE}Status + Recent Logs{RESET}")
        print(f"{CYAN}{BOLD}6.{RESET}  {WHITE}Live Logs{RESET}")
        print(f"{CYAN}{BOLD}7.{RESET}  {WHITE}Test /api/me{RESET}")
        print(f"{CYAN}{BOLD}0.{RESET}  {WHITE}Back / Exit{RESET}")
        print()
        print(f"{GREEN}{'-' * 46}{RESET}")

        choice = input(f"{YELLOW}Select an option:{RESET} ").strip()

        if choice == "1":
            install_service()
        elif choice == "2":
            start_service()
        elif choice == "3":
            stop_service()
        elif choice == "4":
            restart_service()
        elif choice == "5":
            show_status()
        elif choice == "6":
            show_live_logs()
        elif choice == "7":
            test_api()
        elif choice == "0":
            break
        else:
            print(f"{RED}Invalid option.{RESET}")
            pause()


if __name__ == "__main__":
    main()
