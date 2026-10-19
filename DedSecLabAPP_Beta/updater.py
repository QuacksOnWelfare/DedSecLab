"""
DedSecLabUpdater - standalone apply helper.

Built as DedSecLabUpdater.exe and shipped next to DedSecLab.exe.

DedSecLab.exe:
  1. Downloads DedSecLab-x.y.z.zip
  2. Starts: DedSecLabUpdater.exe --apply-update <zip> <install_dir> <pid> <sha256> [signature]
  3. Exits

This process:
  1. Waits for that pid / DedSecLab.exe to die
  2. Unpacks the zip over the install folder (keeps login/config)
  3. Starts DedSecLab.exe
  4. Exits
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import os
import sys
import time
import zipfile
import subprocess
from pathlib import Path

# MUST match core/updater.py UPDATE_SIGNING_PUBKEY_B64 (raw Ed25519 key, base64).
UPDATE_SIGNING_PUBKEY_B64 = ""

APPLY_FLAG = "--apply-update"

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

SKIP_REPLACE = {
    "dedseclabupdater.exe",
    "updater.exe",
}

APP_EXE_NAMES = ("DedSecLab.exe", "DedSecLabAPP.exe")


def write_log(dest: Path, msg: str) -> None:
    try:
        p = dest / "updates" / "apply.log"
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S") + "  " + msg + "\n")
    except Exception:
        pass
    print(msg, flush=True)


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes
            handle = ctypes.windll.kernel32.OpenProcess(0x00100000, False, pid)
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


def wait_for_pid(pid: int, timeout: float = 90.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline and pid_alive(pid):
        time.sleep(0.25)
    time.sleep(0.6)


def kill_main_app() -> None:
    if os.name != "nt":
        return
    for name in APP_EXE_NAMES:
        subprocess.run(
            ["taskkill", "/IM", name, "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )


def safe_members(zf: zipfile.ZipFile, dest: Path) -> list:
    ok = []
    dest = dest.resolve()
    for info in zf.infolist():
        name = info.filename.replace("\\", "/")
        if name.startswith("/") or (len(name) > 1 and name[1] == ":") or ".." in Path(name).parts:
            continue
        target = (dest / name).resolve()
        if dest not in target.parents and target != dest:
            continue
        ok.append(info)
    return ok


def zip_strip_root(names: list[str]) -> str:
    tops = set()
    for n in names:
        n = n.replace("\\", "/").strip("/")
        if n:
            tops.add(n.split("/")[0])
    if len(tops) != 1:
        return ""
    root = next(iter(tops))
    if any(n.replace("\\", "/").rstrip("/").startswith(root + "/") for n in names):
        return root
    return ""


def verify_bytes(data: bytes, expected_sha256: str, signature_b64: str = "") -> tuple:
    expected = str(expected_sha256 or "").strip().lower()
    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        return False, "no valid sha256 supplied"
    if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), expected):
        return False, "sha256 mismatch"
    if UPDATE_SIGNING_PUBKEY_B64:
        if not signature_b64:
            return False, "signature missing"
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            Ed25519PublicKey.from_public_bytes(base64.b64decode(UPDATE_SIGNING_PUBKEY_B64)).verify(
                base64.b64decode(signature_b64, validate=True), data)
        except Exception:
            return False, "signature invalid"
    return True, "ok"


def apply_zip(zip_source, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    src = io.BytesIO(zip_source) if isinstance(zip_source, (bytes, bytearray)) else zip_source
    with zipfile.ZipFile(src, "r") as zf:
        members = safe_members(zf, dest)
        strip = zip_strip_root([m.filename for m in members])
        for info in members:
            name = info.filename.replace("\\", "/").lstrip("/")
            if strip and (name == strip or name.startswith(strip + "/")):
                name = name[len(strip):].lstrip("/")
            if not name:
                continue
            parts = Path(name).parts
            base = Path(name).name
            if base in KEEP_NAMES:
                continue
            if parts and parts[0] in KEEP_DIR_NAMES:
                continue
            if base.lower() in SKIP_REPLACE:
                continue
            target = dest / name
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            data = zf.read(info)
            last_err = None
            for _ in range(8):
                try:
                    with open(target, "wb") as out:
                        out.write(data)
                    last_err = None
                    break
                except PermissionError as e:
                    last_err = e
                    time.sleep(0.4)
            if last_err:
                raise last_err


def find_app_exe(dest: Path) -> Path | None:
    for name in APP_EXE_NAMES:
        p = dest / name
        if p.is_file():
            return p
    for p in dest.glob("*.exe"):
        n = p.name.lower()
        if n.startswith("dedseclab") and "updater" not in n:
            return p
    return None


def launch_app(dest: Path) -> None:
    exe = find_app_exe(dest)
    if exe is None:
        raise FileNotFoundError("DedSecLab.exe not found after extract")
    flags = 0
    if os.name == "nt":
        flags = 0x00000008 | 0x00000200
    subprocess.Popen(
        [str(exe)],
        cwd=str(dest),
        close_fds=True,
        creationflags=flags,
    )


def run_apply(argv: list[str]) -> int:
    args = list(argv)
    if args and args[0] == APPLY_FLAG:
        args = args[1:]
    if len(args) < 4:
        print("Usage: DedSecLabUpdater.exe --apply-update <zip> <install_dir> <wait_pid> <sha256> [signature]")
        return 2
    expected_sha = args[3]
    signature = args[4] if len(args) > 4 else ""

    zip_path = Path(args[0])
    dest = Path(args[1])
    try:
        wait_pid = int(args[2])
    except ValueError:
        wait_pid = 0

    write_log(dest, f"updater start zip={zip_path} dest={dest} wait={wait_pid}")
    write_log(dest, "waiting for DedSecLab to close")
    wait_for_pid(wait_pid)
    kill_main_app()
    time.sleep(0.8)

    if not zip_path.is_file():
        write_log(dest, "zip missing")
        return 3
    try:
        data = zip_path.read_bytes()
    except OSError as e:
        write_log(dest, f"read failed: {e}")
        return 3
    ok, why = verify_bytes(data, expected_sha, signature)
    if not ok:
        write_log(dest, f"verification failed: {why}; update NOT applied")
        return 6
    if not zipfile.is_zipfile(io.BytesIO(data)):
        write_log(dest, "not a zip")
        return 3

    try:
        write_log(dest, "extracting (verified)")
        apply_zip(data, dest)
        write_log(dest, "extract ok")
    except Exception as e:
        write_log(dest, f"extract failed: {e}")
        return 4

    try:
        write_log(dest, "launching DedSecLab")
        launch_app(dest)
        write_log(dest, "relaunch ok")
    except Exception as e:
        write_log(dest, f"relaunch failed: {e}")
        return 5
    return 0


def main() -> int:
    if len(sys.argv) > 1:
        return run_apply(sys.argv[1:])
    print("DedSecLab updater")
    print("DedSecLab.exe starts this after it downloads an update zip.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
