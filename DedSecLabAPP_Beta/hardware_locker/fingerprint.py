"""
Stable device fingerprint.

Client-side hardening only: the cache under %APPDATA% is HMAC-protected with a
DPAPI-/keyring-bound secret so casual editing of the JSON is rejected and a
fresh fingerprint is regenerated. This does NOT make the server trust the
fingerprint - the server MUST treat it as a non-authoritative hint and bind
devices to a server-issued enrollment token.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
from pathlib import Path

from core import secure_store


def _machine_guid() -> str:
    if platform.system() != "Windows":
        return ""
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
        )
        value, _ = winreg.QueryValueEx(key, "MachineGuid")
        winreg.CloseKey(key)
        return str(value or "").strip()
    except Exception:
        return ""


def _cache_path() -> Path:
    base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    folder = base / "DedSecLab"
    folder.mkdir(parents=True, exist_ok=True)
    return folder / "device_fp.json"


def _hmac_key() -> bytes:
    """Stable key for the cache HMAC, stored via the secure store."""
    raw = secure_store.get_secret("device_fp_hmac")
    if raw and len(raw) >= 32:
        return bytes.fromhex(raw) if all(c in "0123456789abcdef" for c in raw.lower()) else raw.encode()
    key = os.urandom(32)
    try:
        secure_store.set_secret("device_fp_hmac", key.hex())
    except Exception:
        pass
    return key


def _valid_fp(fp: str) -> bool:
    return len(fp) == 64 and all(c in "0123456789abcdef" for c in fp)


def _compute() -> str:
    guid = _machine_guid()
    raw = guid or platform.node() or "unknown-device"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def generate_fingerprint() -> str:
    cache = _cache_path()
    if cache.exists():
        try:
            data = json.loads(cache.read_text(encoding="utf-8"))
            fp = str(data.get("fingerprint") or "").strip().lower()
            mac = str(data.get("mac") or "").strip().lower()
            expected = hmac.new(_hmac_key(), fp.encode(), hashlib.sha256).hexdigest()
            if _valid_fp(fp) and hmac.compare_digest(mac, expected):
                return fp
            # Tampered / unsigned cache: discard and regenerate.
        except Exception:
            pass

    fp = _compute()
    try:
        mac = hmac.new(_hmac_key(), fp.encode(), hashlib.sha256).hexdigest()
        cache.write_text(
            json.dumps({"fingerprint": fp, "mac": mac, "v": 2}, indent=2),
            encoding="utf-8",
        )
        if os.name != "nt":
            try:
                os.chmod(cache, 0o600)
            except OSError:
                pass
    except Exception:
        pass
    return fp


def get_display_id() -> str:
    short = generate_fingerprint()[:8].upper()
    return f"{short[:4]}-{short[4:]}"


if __name__ == "__main__":
    print("MachineGuid:", _machine_guid() or "(none)")
    print("Fingerprint:", generate_fingerprint())
    print("Display ID :", get_display_id())
    print("Cache      :", _cache_path())
    print("Store      :", secure_store.backend().name, "secure=" + str(secure_store.is_secure()))
