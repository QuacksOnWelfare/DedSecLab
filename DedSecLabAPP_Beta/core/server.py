import os
import platform
from pathlib import Path
from urllib.parse import quote

import requests
import psutil
from core.config import APP_VERSION
from core.tls import LabTLSError, http_get, http_post, http_request


def _tls_error_text(e) -> str:
    if isinstance(e, LabTLSError):
        return str(e)
    if isinstance(e, requests.exceptions.SSLError):
        return ("Secure connection failed: the server certificate did not match the "
                "pinned lab CA. Connection refused.")
    return ""


def lab_probe(server_url: str, timeout: float = 2.0):
    """Check the real lab backend is reachable over pinned TLS.

    Returns (reachable: bool, error_text: str). Reachable only when TLS to the
    pinned lab CA succeeds AND /api/me answers with a JSON object carrying a
    boolean "ok" field (ok may be False when not logged in). A bare
    {"reason": ...} or any other shape is NOT accepted.
    """
    url = f"{str(server_url).rstrip('/')}/api/me"
    try:
        r = http_get(url, timeout=timeout)
        if r.status_code >= 500:
            return False, f"Server error {r.status_code}"
        data = r.json()
    except (LabTLSError, requests.exceptions.SSLError) as e:
        return False, _tls_error_text(e)
    except Exception:
        return False, ""
    if isinstance(data, dict) and isinstance(data.get("ok"), bool):
        return True, ""
    return False, "Unexpected response from lab server."

# Generate fingerprint locally - no server calls, no threads
try:
    from hardware_locker.fingerprint import generate_fingerprint, get_display_id

    _fingerprint = generate_fingerprint()
    _display_id = get_display_id()
except Exception:
    _fingerprint = ""
    _display_id = "0000-0000"


class MockServerClient:
    def __init__(self):
        self.connected = False
        self.user = None
        self.server_url = ""
        self.username = ""
        self.device_id = _display_id

    def login(self, username, password, server_url):
        if not server_url:
            return False, "Server URL missing."

        self.server_url = server_url.rstrip("/")
        self.username = username.strip()

        try:
            response = http_post(
                f"{self.server_url}/api/login",
                json={
                    "username": username,
                    "password": password,
                    "fingerprint": _fingerprint,
                    "label": platform.node(),
                    "version": APP_VERSION,
                },
                timeout=6,
            )
            data = response.json()
        except (LabTLSError, requests.exceptions.SSLError) as e:
            return False, _tls_error_text(e)
        except requests.exceptions.ConnectionError:
            return False, "Cannot reach backend. Make sure VPN is connected."
        except requests.exceptions.Timeout:
            return False, "Backend timed out."
        except Exception as e:
            return False, f"Backend error: {e}"

        if not isinstance(data, dict):
            return False, "Unexpected response from server."
        if not data.get("ok"):
            reason = data.get("reason", "Access denied.")
            if reason == "device_pending":
                return False, "device_pending"
            if reason == "device_revoked":
                return False, "device_revoked"
            return False, reason

        self.connected = True
        self.user = data
        return True, f"Welcome {data.get('display_name', 'user')}."

    def change_password(self, current_password, new_password):
        if not self.connected or not self.user:
            return False, "Not logged in."

        try:
            response = http_post(
                f"{self.server_url}/api/change-password",
                json={
                    "username": self.username,
                    "current_password": current_password,
                    "new_password": new_password,
                },
                timeout=6,
            )
            data = response.json()
        except (LabTLSError, requests.exceptions.SSLError) as e:
            return False, _tls_error_text(e)
        except requests.exceptions.ConnectionError:
            return False, "Cannot reach backend. Make sure VPN is connected."
        except requests.exceptions.Timeout:
            return False, "Backend timed out."
        except Exception as e:
            return False, f"Backend error: {e}"

        if not data.get("ok"):
            return False, data.get("reason", "Password change failed.")

        return True, data.get("message", "Password changed successfully.")

    def disconnect(self):
        self.connected = False
        self.user = None
        self.username = ""

    def get_status(self):
        if not self.connected or not self.user:
            return {
                "online": False,
                "cpu": 0,
                "ram": 0,
                "disk": 0,
                "uptime": "Offline",
                "vpn": "Offline",
                "ssh": "Locked",
            }

        try:
            cpu = int(psutil.cpu_percent(interval=None))
            ram = int(psutil.virtual_memory().percent)
            disk = int(psutil.disk_usage(Path.home().anchor or os.sep).percent)
        except Exception:
            cpu = ram = disk = 0

        return {
            "online": True,
            "cpu": cpu,
            "ram": ram,
            "disk": disk,
            "uptime": "Connected",
            "vpn": "Active",
            "ssh": "App Controlled",
            "user": self.user.get("display_name"),
            "role": self.user.get("role"),
            "days_left": self.user.get("days_left"),
        }

    def get_logs(self):
        if not self.connected or not self.user:
            return "[SERVER] Not connected"
        return (
            f"[SERVER] Logged in as {self.user.get('display_name')} | "
            f"Role: {self.user.get('role')} | "
            f"VPN IP: {self.user.get('vpn_ip')} | "
            f"Days left: {self.user.get('days_left')}"
        )

    # =========================================================
    # IP DATABASE
    # =========================================================
    def get_ip_database(self):
        if not self.connected:
            return []
        try:
            response = http_get(
                f"{self.server_url}/api/ips",
                timeout=6,
            )
            data = response.json()
            return data if isinstance(data, list) else []
        except (LabTLSError, requests.exceptions.SSLError) as e:
            raise RuntimeError(_tls_error_text(e)) from e
        except Exception:
            return []

    def add_ip(self, data):
        if not self.connected:
            return {"ok": False, "reason": "Not connected"}
        try:
            response = http_post(
                f"{self.server_url}/api/ips/add",
                json=data,
                timeout=6,
            )
            return response.json()
        except Exception as e:
            return {"ok": False, "reason": str(e)}

    def delete_ip(self, ip):
        if not self.connected:
            return {"ok": False, "reason": "Not connected"}
        try:
            response = http_request("DELETE", 
                f"{self.server_url}/api/ips/{quote(str(ip), safe='')}",
                timeout=6,
            )
            return response.json()
        except Exception as e:
            return {"ok": False, "reason": str(e)}
