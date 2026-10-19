"""
fingerprint.py
--------------
Generates a stable hardware fingerprint for the current device.
Works on Windows, macOS, and Linux.
"""

import hashlib
import platform
import subprocess
import uuid
import json
from pathlib import Path


def _run(cmd: list[str]) -> str:
    """Run a shell command and return stdout, or empty string on failure."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return result.stdout.strip()
    except Exception:
        return ""


def _get_windows_ids() -> dict:
    ids = {}
    # Motherboard UUID
    ids["board_uuid"] = _run(["wmic", "csproduct", "get", "UUID"]).split("\n")[-1].strip()
    # CPU ID
    ids["cpu_id"] = _run(["wmic", "cpu", "get", "ProcessorId"]).split("\n")[-1].strip()
    # Disk serial
    ids["disk_serial"] = _run(["wmic", "diskdrive", "get", "SerialNumber"]).split("\n")[-1].strip()
    # BIOS serial
    ids["bios_serial"] = _run(["wmic", "bios", "get", "SerialNumber"]).split("\n")[-1].strip()
    return ids


def _get_macos_ids() -> dict:
    ids = {}
    # Hardware UUID
    out = _run(["system_profiler", "SPHardwareDataType"])
    for line in out.splitlines():
        if "Hardware UUID" in line:
            ids["hardware_uuid"] = line.split(":")[-1].strip()
        if "Serial Number" in line:
            ids["serial_number"] = line.split(":")[-1].strip()
    # IOPlatformUUID
    ids["io_uuid"] = _run([
        "ioreg", "-rd1", "-c", "IOPlatformExpertDevice"
    ])
    return ids


def _get_linux_ids() -> dict:
    ids = {}
    # Machine ID (stable across reboots)
    mid = Path("/etc/machine-id")
    if mid.exists():
        ids["machine_id"] = mid.read_text().strip()
    # DMI product UUID
    dmi_uuid = Path("/sys/class/dmi/id/product_uuid")
    if dmi_uuid.exists():
        try:
            ids["dmi_uuid"] = dmi_uuid.read_text().strip()
        except PermissionError:
            pass
    # DMI serial
    dmi_serial = Path("/sys/class/dmi/id/product_serial")
    if dmi_serial.exists():
        try:
            ids["dmi_serial"] = dmi_serial.read_text().strip()
        except PermissionError:
            pass
    return ids


def _get_mac_address() -> str:
    """Get the primary network interface MAC address."""
    try:
        mac = uuid.getnode()
        # uuid.getnode() can return a random value if no MAC found
        if (mac >> 40) % 2:  # multicast bit set = random
            return ""
        return ":".join(f"{(mac >> (8 * i)) & 0xFF:02x}" for i in reversed(range(6)))
    except Exception:
        return ""


def collect_hardware_ids() -> dict:
    """Collect all available hardware identifiers for the current platform."""
    system = platform.system()
    ids = {
        "platform": system,
        "hostname": platform.node(),
        "machine": platform.machine(),
        "mac_address": _get_mac_address(),
    }

    if system == "Windows":
        ids.update(_get_windows_ids())
    elif system == "Darwin":
        ids.update(_get_macos_ids())
    elif system == "Linux":
        ids.update(_get_linux_ids())

    return ids


def generate_fingerprint() -> str:
    """
    Returns a stable SHA-256 fingerprint string for this device.
    Only the hash is ever sent to the server - raw IDs stay local.
    """
    ids = collect_hardware_ids()

    # Sort keys so the hash is consistent regardless of dict ordering
    canonical = json.dumps(ids, sort_keys=True)
    fingerprint = hashlib.sha256(canonical.encode()).hexdigest()
    return fingerprint


def get_display_id() -> str:
    """
    A short, human-readable device ID to show users on the locked screen
    so they can tell their admin which device needs approving.
    Format: XXXX-XXXX (first 8 hex chars of the fingerprint).
    """
    fp = generate_fingerprint()
    short = fp[:8].upper()
    return f"{short[:4]}-{short[4:]}"


if __name__ == "__main__":
    print("Hardware IDs:")
    for k, v in collect_hardware_ids().items():
        print(f"  {k}: {v}")
    print(f"\nFingerprint : {generate_fingerprint()}")
    print(f"Display ID  : {get_display_id()}")
