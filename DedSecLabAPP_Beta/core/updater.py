"""
DedSec Lab client version checker + in-place updater.

Copy this file to core/updater.py in the app project.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import io
import os
import sys
import time
import shutil
import zipfile
import subprocess
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urljoin, urlsplit

import requests

from core.tls import LabTLSError, http_get

APP_VERSION = "1.0.6"

DEFAULT_SERVER_URL = "https://YOUR_LAB_VPN_IP:8443"
DEFAULT_WEBSITE_URL = "https://YOUR_WEBSITE_URL.example"
ALLOWED_WEBSITE_HOSTS = {"YOUR_WEBSITE_URL.example", "www.YOUR_WEBSITE_URL.example"}

APPLY_FLAG = "--apply-update"
MAX_UPDATE_BYTES = 1024 * 1024 * 1024  # 1 GiB hard cap

# ---------------------------------------------------------------------------
# Update signing. Paste the base64 of the RAW 32-byte Ed25519 public key here
# (the private key stays on the build machine). When set, every update MUST
# carry a valid "signature" (base64 Ed25519 over the exact zip bytes).
# While empty, updates are still REQUIRED to match the manifest "sha256".
# ---------------------------------------------------------------------------
UPDATE_SIGNING_PUBKEY_B64 = ""

KEEP_NAMES = {
    "login.key",
    "login.dat",
    "embedded_config.json",
    "config.json",
    "settings.json",
    "lab_ca.pem",
}

KEEP_DIR_NAMES = {
    "logs",
    "updates",
}


def parse_version(v: str) -> Tuple[int, ...]:
    parts = []
    for p in str(v).strip().lstrip("vV").split("."):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    return tuple(parts) if parts else (0,)


def is_newer(remote: str, local: str) -> bool:
    return parse_version(remote) > parse_version(local)


def _origin(url: str):
    u = urlsplit(url)
    port = u.port or (443 if u.scheme == "https" else 80)
    return (u.scheme.lower(), (u.hostname or "").lower(), port)


def resolve_download_url(base: str, download_url: str) -> Tuple[str, str]:
    """Resolve (possibly relative) download_url against the API base and
    require it to be https on the SAME origin. Returns (url, error)."""
    if not download_url:
        return "", ""
    full = urljoin(base.rstrip("/") + "/", download_url)
    if _origin(full)[0] != "https":
        return "", "Update URL rejected: must use https."
    if _origin(full) != _origin(base):
        return "", "Update URL rejected: it is not on the lab API server."
    return full, ""


def safe_website_url(url: str) -> str:
    try:
        u = urlsplit(str(url or ""))
        if u.scheme == "https" and (u.hostname or "").lower() in ALLOWED_WEBSITE_HOSTS:
            return url
    except ValueError:
        pass
    return DEFAULT_WEBSITE_URL


def _norm_sha256(value) -> str:
    v = str(value or "").strip().lower()
    return v if len(v) == 64 and all(c in "0123456789abcdef" for c in v) else ""


def check_for_update(server_url: Optional[str] = None, timeout: int = 8) -> Tuple[str, dict | str]:
    base = (server_url or DEFAULT_SERVER_URL).rstrip("/")
    url = f"{base}/api/update/version"

    try:
        r = http_get(url, timeout=timeout)
        r.raise_for_status()
        data = r.json()
    except LabTLSError as e:
        return "error", str(e)
    except requests.exceptions.SSLError:
        return "error", "Secure connection failed: server certificate does not match the pinned lab CA."
    except Exception as e:
        return "error", f"Could not check updates:\n{e}"

    if not isinstance(data, dict) or not data.get("ok"):
        reason = ""
        if isinstance(data, dict):
            reason = data.get("reason") or data.get("error") or str(data)
        else:
            reason = str(data)
        return "error", reason or "Update check failed"

    dl, dl_err = resolve_download_url(base, str(data.get("download_url") or "").strip())
    info = {
        "version": str(data.get("version", "")).strip(),
        "min_version": str(data.get("min_version", "")).strip(),
        "notes": str(data.get("notes") or ""),
        "website_url": safe_website_url(str(data.get("website_url") or DEFAULT_WEBSITE_URL).strip()),
        "download_url": dl,
        "download_error": dl_err,
        "sha256": _norm_sha256(data.get("sha256")),
        "signature": str(data.get("signature") or "").strip(),
        "server_url": base,
    }

    if not info["version"]:
        return "error", "Server returned no version"

    if is_newer(info["version"], APP_VERSION):
        return "update_available", info
    return "up_to_date", info


def verify_update_bytes(data: bytes, expected_sha256: str, signature_b64: str = "") -> Tuple[bool, str]:
    """Integrity + authenticity gate. Must pass before anything is extracted."""
    expected = _norm_sha256(expected_sha256)
    if not expected:
        return False, "Update refused: the server did not provide a valid sha256 checksum."
    actual = hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(actual, expected):
        return False, "Update refused: checksum mismatch (file corrupted or tampered with)."
    if UPDATE_SIGNING_PUBKEY_B64:
        if not signature_b64:
            return False, "Update refused: signature missing."
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(UPDATE_SIGNING_PUBKEY_B64))
            pub.verify(base64.b64decode(signature_b64, validate=True), data)
        except (binascii.Error, ValueError):
            return False, "Update refused: signature is malformed."
        except Exception:
            return False, "Update refused: signature verification failed."
    return True, actual


def verify_update_file(path, expected_sha256: str, signature_b64: str = "") -> Tuple[bool, str]:
    p = Path(path)
    if not p.is_file():
        return False, "Update zip not found."
    if p.stat().st_size > MAX_UPDATE_BYTES:
        return False, "Update refused: file too large."
    return verify_update_bytes(p.read_bytes(), expected_sha256, signature_b64)


def download_update(url: str, dest_dir=None, timeout: int = 180, version: str = "", progress_cb=None,
                    sha256: str = "", signature: str = "", server_url: Optional[str] = None):
    if not url:
        return "error", "Update file is not on the server yet."
    base = (server_url or DEFAULT_SERVER_URL).rstrip("/")
    url, err = resolve_download_url(base, url)
    if err or not url:
        return "error", err or "Update URL rejected."
    if not _norm_sha256(sha256):
        return "error", "Update refused: the server did not provide a sha256 checksum."

    dest_dir = Path(dest_dir or (Path.home() / "Downloads"))
    dest_dir.mkdir(parents=True, exist_ok=True)
    ver = "".join(ch for ch in str(version or "").strip() if ch.isdigit() or ch == ".")
    name = f"DedSecLab-{ver}.zip" if ver else f"DedSecLab-{APP_VERSION}.zip"
    dest = dest_dir / name
    part = dest.with_suffix(".zip.part")

    try:
        r = http_get(url, timeout=timeout, stream=True)
        if r.status_code == 404:
            return "error", "Update file is not on the server yet."
        r.raise_for_status()
        total = int(r.headers.get("Content-Length") or 0)
        if total > MAX_UPDATE_BYTES:
            return "error", "Update refused: file too large."
        done = 0
        with open(part, "wb") as f:
            for chunk in r.iter_content(chunk_size=1024 * 64):
                if not chunk:
                    continue
                done += len(chunk)
                if done > MAX_UPDATE_BYTES:
                    raise ValueError("update exceeds size limit")
                f.write(chunk)
                if progress_cb:
                    if total > 0:
                        progress_cb(min(100, int(done * 100 / total)))
                    else:
                        progress_cb(min(99, done // (256 * 1024)))
        ok, msg = verify_update_file(part, sha256, signature)
        if not ok:
            part.unlink(missing_ok=True)
            return "error", msg
        if not zipfile.is_zipfile(part):
            part.unlink(missing_ok=True)
            return "error", "Download is not a zip file."
        os.replace(part, dest)
        if progress_cb:
            progress_cb(100)
        return "ok", dest
    except LabTLSError as e:
        part.unlink(missing_ok=True)
        return "error", str(e)
    except requests.exceptions.SSLError:
        part.unlink(missing_ok=True)
        return "error", "Secure connection failed: server certificate does not match the pinned lab CA."
    except Exception as e:
        part.unlink(missing_ok=True)
        return "error", f"Download failed:\n{e}"


def _is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False) or getattr(sys, "__compiled__", False))


def app_dir() -> Path:
    if _is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]


def launch_command() -> list[str]:
    if getattr(sys, "frozen", False):
        exe = Path(sys.executable).resolve()
        if exe.name.lower().startswith("dedseclabupdater"):
            sibling = exe.with_name("DedSecLab.exe")
            if sibling.is_file():
                return [str(sibling)]
        return [str(exe)]
    script = Path(sys.argv[0]).resolve() if sys.argv and sys.argv[0] else app_dir() / "app.py"
    return [sys.executable, str(script)]


def restart_command() -> list[str]:
    """Command to relaunch this app with its current user arguments."""
    extra = [a for a in sys.argv[1:] if a != APPLY_FLAG]
    return launch_command() + extra


def _materialize_updater(base: Path) -> Path | None:
    """Turn the embedded assets/dsl_upd.bin into a hidden DedSecLabUpdater.exe when needed."""
    blob = Path(base) / "assets" / "dsl_upd.bin"
    if not blob.is_file():
        return None
    out = Path(base) / "DedSecLabUpdater.exe"
    try:
        if (not out.is_file()) or out.stat().st_size != blob.stat().st_size:
            if out.is_file() and os.name == "nt":
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(str(out), 0x80)  # NORMAL so we can overwrite
            shutil.copy2(blob, out)
        _win_hide(out)
        return out
    except OSError:
        return None


def updater_command() -> list[str]:
    here = Path(sys.executable).resolve().parent
    roots = [here, here / "DedSecLab", Path.cwd(), Path.cwd() / "DedSecLab"]
    if not _is_frozen():
        roots.append(Path(__file__).resolve().parents[1])
        roots.append(Path(__file__).resolve().parents[1] / "DedSecLab")
    for base in roots:
        for name in ("DedSecLabUpdater.exe", "updater.exe"):
            cand = base / name
            if cand.is_file():
                _win_hide(cand)
                return [str(cand)]
        made = _materialize_updater(base)
        if made is not None:
            return [str(made)]
    if _is_frozen():
        return [str(Path(sys.executable).resolve())]
    standalone = Path(__file__).resolve().parents[1] / "updater.py"
    if standalone.is_file():
        return [sys.executable, str(standalone)]
    return [sys.executable, str(Path(__file__).resolve())]


def _safe_zip_members(zf: zipfile.ZipFile, dest: Path) -> list:
    ok = []
    dest = dest.resolve()
    for info in zf.infolist():
        name = info.filename.replace("\\", "/")
        if name.startswith("/") or name.startswith("\\") or ".." in Path(name).parts:
            continue
        target = (dest / name).resolve()
        if dest not in target.parents and target != dest:
            continue
        ok.append(info)
    return ok


def _zip_strip_root(names: list[str]) -> str:
    tops = set()
    for n in names:
        n = n.replace("\\", "/").strip("/")
        if not n:
            continue
        tops.add(n.split("/")[0])
    if len(tops) == 1:
        root = next(iter(tops))
        if any(n.replace("\\", "/").rstrip("/").startswith(root + "/") for n in names):
            return root
    return ""


def _win_hide(path: Path) -> None:
    if os.name != "nt" or not Path(path).is_file():
        return
    import ctypes
    # Hidden | System - stays out of normal Explorer views
    ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x02 | 0x04)


def hide_updater(dest: Path) -> None:
    dest = Path(dest)
    for name in ("DedSecLabUpdater.exe", "updater.exe"):
        _win_hide(dest / name)
    _win_hide(dest / "assets" / "dsl_upd.bin")


def unblock_tree(root: Path) -> None:
    if os.name != "nt":
        return
    for p in Path(root).rglob("*"):
        if not p.is_file():
            continue
        try:
            os.remove(f"{p}:Zone.Identifier")
        except OSError:
            pass


def apply_zip(zip_source, dest: Path) -> None:
    """zip_source: verified zip bytes (preferred) or a path."""
    dest.mkdir(parents=True, exist_ok=True)
    src = io.BytesIO(zip_source) if isinstance(zip_source, (bytes, bytearray)) else zip_source
    with zipfile.ZipFile(src, "r") as zf:
        members = _safe_zip_members(zf, dest)
        strip = _zip_strip_root([m.filename for m in members])
        for info in members:
            name = info.filename.replace("\\", "/").lstrip("/")
            if strip and (name == strip or name.startswith(strip + "/")):
                name = name[len(strip):].lstrip("/")
            if not name:
                continue
            base = Path(name).name
            if base in KEEP_NAMES:
                continue
            if Path(name).parts and Path(name).parts[0] in KEEP_DIR_NAMES:
                continue
            if base.lower() in {"dedseclabupdater.exe", "updater.exe"}:
                continue
            target = dest / name
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                out.write(src.read())
    unblock_tree(dest)
    hide_updater(dest)


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes
            SYNCHRONIZE = 0x00100000
            handle = ctypes.windll.kernel32.OpenProcess(SYNCHRONIZE, False, pid)
            if handle:
                ctypes.windll.kernel32.CloseHandle(handle)
                return True
            return False
        except Exception:
            return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def wait_for_pid(pid: int, timeout: float = 60.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline and _pid_alive(pid):
        time.sleep(0.25)
    time.sleep(0.8)


def run_apply_update_mode(argv: list | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if args and args[0] == APPLY_FLAG:
        args = args[1:]
    if len(args) < 4:
        return 2
    zip_path = Path(args[0])
    dest = Path(args[1])
    try:
        wait_pid = int(args[2])
    except ValueError:
        wait_pid = 0
    expected_sha = args[3]
    signature = args[4] if len(args) > 4 else ""

    log = dest / "updates" / "apply.log"
    log.parent.mkdir(parents=True, exist_ok=True)

    def write(msg: str) -> None:
        try:
            with open(log, "a", encoding="utf-8") as f:
                f.write(msg + "\n")
        except Exception:
            pass

    write(f"apply start zip={zip_path} dest={dest} wait={wait_pid}")
    wait_for_pid(wait_pid)
    if not zip_path.is_file():
        write("zip missing")
        return 3
    try:
        data = zip_path.read_bytes()
    except OSError as e:
        write(f"read failed: {e}")
        return 3
    ok, msg = verify_update_bytes(data, expected_sha, signature)
    if not ok:
        write(f"verify failed: {msg}")
        return 6
    try:
        apply_zip(data, dest)
        write("extract ok")
    except Exception as e:
        write(f"extract failed: {e}")
        return 4

    cmd = launch_command()
    write(f"relaunch {cmd}")
    try:
        flags = 0
        if os.name == "nt":
            flags = getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
            flags |= getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        subprocess.Popen(cmd, cwd=str(dest), close_fds=True, creationflags=flags)
    except Exception as e:
        write(f"relaunch failed: {e}")
        return 5
    write("relaunch ok")
    return 0


def start_apply_and_exit(zip_path: Path, install_dir: Optional[Path] = None,
                         sha256: str = "", signature: str = "") -> Tuple[str, str]:
    zip_path = Path(zip_path)
    dest = Path(install_dir or app_dir())
    if not zip_path.is_file():
        return "error", "Update zip not found."
    if not zipfile.is_zipfile(zip_path):
        return "error", "Update file is not a zip."
    ok, msg = verify_update_file(zip_path, sha256, signature)
    if not ok:
        return "error", msg

    cmd = updater_command() + [APPLY_FLAG, str(zip_path), str(dest), str(os.getpid()),
                               _norm_sha256(sha256)]
    if signature:
        cmd.append(signature)
    try:
        flags = 0
        if os.name == "nt":
            flags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0x00000010)
            flags |= getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        subprocess.Popen(cmd, cwd=str(dest), close_fds=True, creationflags=flags)
    except Exception as e:
        return "error", f"Could not start updater:\n{e}"
    return "ok", "Updater started. The app will close and reopen."


def maybe_handle_argv() -> bool:
    if len(sys.argv) > 1 and sys.argv[1] == APPLY_FLAG:
        code = run_apply_update_mode(sys.argv[1:])
        raise SystemExit(code)
    return False


if __name__ == "__main__":
    raise SystemExit(run_apply_update_mode(sys.argv[1:]))
