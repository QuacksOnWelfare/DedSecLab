import json
import os
import threading
from pathlib import Path

# When False (default), skip the VPN gate and open the lab directly.
# Set True to restore the VPN-locked flow (requires your own OpenVPN + lab).
REQUIRE_VPN_GATE = False

APP_NAME = "DedSec-Lab Client"
APP_VERSION = "1.0.6"
APP_DIR = Path(os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming")) / "DedSecLab"
CONFIG_FILE = APP_DIR / "config.json"
OPENVPN_DOWNLOAD_URL = "https://openvpn.net/community/"

# v2 = Default/Dark/Light where "default" is the original look.
THEME_SCHEMA = 2
_VALID_THEMES = ("default", "dark", "light", "matrix", "crimson", "midnight", "amber", "oled")
# Keys that must never be persisted in plaintext config.
_FORBIDDEN_KEYS = ("ssh_password", "password")

_lock = threading.RLock()


def _migrate_theme(config: dict) -> bool:
    """Map pre-v2 theme values. Returns True if config changed."""
    if config.get("theme_schema") == THEME_SCHEMA:
        if config.get("theme") not in _VALID_THEMES:
            config["theme"] = "default"
            return True
        return False
    old = str(config.get("theme") or "default").strip().lower()
    # v1: "dark" was the original look, "default"/"system" followed the OS.
    config["theme"] = "light" if old == "light" else "default"
    config["theme_schema"] = THEME_SCHEMA
    return True


class ConfigManager:
    DEFAULTS = {
        "server_url": "https://YOUR_LAB_HOST:8443",
        "username": "",
        "auto_connect": False,
        "save_username": True,
        "ovpn_config": "",
        "ssh_host": "",
        "ssh_port": "22",
        "ssh_username": "",
        "theme": "default",
        "theme_schema": THEME_SCHEMA,
        "lab_ca_path": "",
        "ipapi_key": "",
    }

    @staticmethod
    def _read() -> dict:
        try:
            data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    @staticmethod
    def peek() -> dict:
        """Read-only view (defaults applied, nothing written). Thread-safe."""
        with _lock:
            cfg = dict(ConfigManager.DEFAULTS)
            cfg.update(ConfigManager._read())
            return cfg

    @staticmethod
    def load():
        with _lock:
            APP_DIR.mkdir(parents=True, exist_ok=True)
            if not CONFIG_FILE.exists():
                config = dict(ConfigManager.DEFAULTS)
                ConfigManager.save(config)
                return config

            config = ConfigManager._read() or dict(ConfigManager.DEFAULTS)
            changed = False
            # Migrate theme BEFORE filling defaults - otherwise DEFAULTS would
            # inject theme_schema=2 and hide a legacy "dark"/"system" value.
            changed = _migrate_theme(config) or changed
            for key, value in ConfigManager.DEFAULTS.items():
                if key not in config:
                    config[key] = value
                    changed = True
            for key in _FORBIDDEN_KEYS:
                if key in config:
                    config.pop(key, None)   # never persist plaintext secrets
                    changed = True
            config.pop("ssh_save_password", None)

            url = str(config.get("server_url") or "").strip()
            if url.startswith(("http://YOUR_LAB_HOST", "https://YOUR_LAB_HOST", "http://10.8.0.", "https://10.8.0.")) and "YOUR_LAB_HOST" not in url:
                config["server_url"] = "https://YOUR_LAB_HOST:8443"
                changed = True

            if changed:
                ConfigManager.save(config)
            return config

    @staticmethod
    def save(config):
        with _lock:
            APP_DIR.mkdir(parents=True, exist_ok=True)
            clean = {k: v for k, v in dict(config).items() if k not in _FORBIDDEN_KEYS}
            tmp = CONFIG_FILE.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(clean, indent=4), encoding="utf-8")
            if os.name != "nt":
                try:
                    os.chmod(tmp, 0o600)
                except OSError:
                    pass
            os.replace(tmp, CONFIG_FILE)   # atomic: no half-written config
