"""
Secure local secret storage for DedSec Lab.

Backend preference:
    1. keyring  (Windows Credential Manager / macOS Keychain / Secret Service)
    2. Windows DPAPI (CryptProtectData, current-user scope) via ctypes
    3. INSECURE fallback: Fernet file with key in a separate per-user file.
       Only used when neither of the above works; a loud warning is returned.

Legacy migration: the old design kept login.key (Fernet key) next to login.dat
in the app folder. On first load, if those exist and a secure backend works,
the blob is decrypted once, re-stored securely, and BOTH legacy files are
deleted. Secret values are never logged.
"""
from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path

SERVICE = "DedSecLab"


def _appdata_dir() -> Path:
    base = Path(os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming"))
    d = base / "DedSecLab"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _restrict(path: Path) -> None:
    try:
        if os.name != "nt":
            os.chmod(path, 0o600)
    except OSError:
        pass


# ------------------------------------------------------------------ keyring
class _KeyringBackend:
    name = "keyring"
    secure = True

    def __init__(self):
        import keyring  # noqa: F401
        from keyring.backends import fail
        self._kr = keyring
        if isinstance(keyring.get_keyring(), fail.Keyring):
            raise RuntimeError("no usable keyring backend")

    def get(self, key):
        return self._kr.get_password(SERVICE, key)

    def set(self, key, value):
        self._kr.set_password(SERVICE, key, value)

    def delete(self, key):
        try:
            self._kr.delete_password(SERVICE, key)
        except Exception:
            pass


# ------------------------------------------------------------------ DPAPI
class _DpapiBackend:
    name = "windows-dpapi"
    secure = True

    def __init__(self):
        if sys.platform != "win32":
            raise RuntimeError("DPAPI is Windows-only")
        import ctypes
        from ctypes import wintypes

        class BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

        self._ct, self._BLOB = ctypes, BLOB
        self._crypt32 = ctypes.windll.crypt32
        self._kernel32 = ctypes.windll.kernel32
        # round-trip self-test so we never "store" into a broken backend
        if self._unprotect(self._protect(b"selftest")) != b"selftest":
            raise RuntimeError("DPAPI self-test failed")

    def _blob(self, data: bytes):
        buf = self._ct.create_string_buffer(data, len(data))
        return self._BLOB(len(data), self._ct.cast(buf, self._ct.POINTER(self._ct.c_char))), buf

    def _protect(self, data: bytes) -> bytes:
        inp, _keep = self._blob(data)
        out = self._BLOB()
        if not self._crypt32.CryptProtectData(self._ct.byref(inp), "DedSecLab", None, None, None, 0x01, self._ct.byref(out)):
            raise OSError("CryptProtectData failed")
        try:
            return self._ct.string_at(out.pbData, out.cbData)
        finally:
            self._kernel32.LocalFree(out.pbData)

    def _unprotect(self, data: bytes) -> bytes:
        inp, _keep = self._blob(data)
        out = self._BLOB()
        if not self._crypt32.CryptUnprotectData(self._ct.byref(inp), None, None, None, None, 0x01, self._ct.byref(out)):
            raise OSError("CryptUnprotectData failed")
        try:
            return self._ct.string_at(out.pbData, out.cbData)
        finally:
            self._kernel32.LocalFree(out.pbData)

    def _file(self, key):
        safe = "".join(c for c in key if c.isalnum() or c in "-_")
        return _appdata_dir() / f"{safe}.dpapi"

    def get(self, key):
        p = self._file(key)
        if not p.is_file():
            return None
        return self._unprotect(p.read_bytes()).decode("utf-8")

    def set(self, key, value):
        p = self._file(key)
        p.write_bytes(self._protect(value.encode("utf-8")))
        _restrict(p)

    def delete(self, key):
        self._file(key).unlink(missing_ok=True)


# ------------------------------------------------------------------ fallback
class _InsecureFileBackend:
    """Last resort. Key and data are in separate files under the user profile;
    this only protects against casual copying of the app folder."""
    name = "INSECURE-file-fallback"
    secure = False

    def __init__(self):
        from cryptography.fernet import Fernet
        kf = _appdata_dir() / "store.key"
        if not kf.is_file():
            kf.write_bytes(Fernet.generate_key())
            _restrict(kf)
        self._f = Fernet(kf.read_bytes())

    def _file(self, key):
        safe = "".join(c for c in key if c.isalnum() or c in "-_")
        return _appdata_dir() / f"{safe}.enc"

    def get(self, key):
        p = self._file(key)
        return self._f.decrypt(p.read_bytes()).decode("utf-8") if p.is_file() else None

    def set(self, key, value):
        p = self._file(key)
        p.write_bytes(self._f.encrypt(value.encode("utf-8")))
        _restrict(p)

    def delete(self, key):
        self._file(key).unlink(missing_ok=True)


_backend = {"obj": None, "warning": ""}


def backend():
    if _backend["obj"] is None:
        errors = []
        for cls in (_KeyringBackend, _DpapiBackend):
            try:
                _backend["obj"] = cls()
                break
            except Exception as e:
                errors.append(f"{cls.name}: {e}")
        if _backend["obj"] is None:
            _backend["obj"] = _InsecureFileBackend()
            _backend["warning"] = (
                "WARNING: no secure credential store available "
                f"({'; '.join(errors)}). Saved passwords use an INSECURE file fallback. "
                "Install 'keyring' or run on Windows (DPAPI) to fix."
            )
    return _backend["obj"]


def backend_warning() -> str:
    backend()
    return _backend["warning"]


def is_secure() -> bool:
    return bool(getattr(backend(), "secure", False))


def get_secret(key: str):
    return backend().get(key)


def set_secret(key: str, value: str) -> None:
    backend().set(key, value)


def delete_secret(key: str) -> None:
    backend().delete(key)


# ------------------------------------------------------------------ login creds
_LOGIN_KEY = "login"


def save_login(username: str, password: str) -> None:
    set_secret(_LOGIN_KEY, json.dumps({"username": username, "password": password}))


def clear_login() -> None:
    delete_secret(_LOGIN_KEY)


def load_login(legacy_dir: Path | None = None, log=None):
    """Return {"username","password"} or None. Migrates legacy files once."""
    raw = None
    try:
        raw = get_secret(_LOGIN_KEY)
    except Exception as e:
        if log:
            log(f"[LOGIN] Secure store read failed ({type(e).__name__}).")
    if raw:
        try:
            return json.loads(raw)
        except ValueError:
            return None
    if legacy_dir is not None:
        return _migrate_legacy(Path(legacy_dir), log)
    return None


def _migrate_legacy(folder: Path, log=None):
    key_file, dat_file = folder / "login.key", folder / "login.dat"
    if not (key_file.is_file() and dat_file.is_file()):
        return None
    try:
        from cryptography.fernet import Fernet
        data = json.loads(Fernet(key_file.read_bytes()).decrypt(dat_file.read_bytes()).decode())
    except Exception as e:
        if log:
            log(f"[LOGIN] Legacy credential file unreadable ({type(e).__name__}); ignored.")
        return None
    if not is_secure():
        if log:
            log("[LOGIN] Legacy credentials found but no secure store available; not migrated.")
        return data
    try:
        save_login(str(data.get("username", "")), str(data.get("password", "")))
        dat_file.unlink(missing_ok=True)
        key_file.unlink(missing_ok=True)
        if log:
            log(f"[LOGIN] Migrated saved login to {backend().name}; removed legacy login.dat/login.key.")
    except Exception as e:
        if log:
            log(f"[LOGIN] Migration failed ({type(e).__name__}); legacy files kept.")
    return data
