"""Small Windows helpers: safe PowerShell quoting and Authenticode checks."""
from __future__ import annotations

import subprocess
import sys

# PowerShell treats these as single-quote characters inside '...' strings.
_PS_QUOTES = ("'", "\u2018", "\u2019", "\u201a", "\u201b")


def ps_quote(value) -> str:
    """Return value as a safe single-quoted PowerShell literal."""
    s = str(value)
    if any(ch in s for ch in ("\x00", "\r", "\n")):
        raise ValueError("control characters not allowed in PowerShell argument")
    for q in _PS_QUOTES:
        s = s.replace(q, q + q)
    return "'" + s + "'"


def _no_window():
    return subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0


def authenticode_signer(path) -> tuple:
    """(status, signer_subject) using Get-AuthenticodeSignature. Windows only."""
    ps = (
        f"$s = Get-AuthenticodeSignature -LiteralPath {ps_quote(path)}; "
        "Write-Output $s.Status; Write-Output $s.SignerCertificate.Subject"
    )
    r = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
        capture_output=True, text=True, timeout=60, creationflags=_no_window(),
    )
    lines = [ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip()]
    status = lines[0] if lines else "Unknown"
    subject = lines[1] if len(lines) > 1 else ""
    return status, subject


def verify_authenticode(path, required_subject_substr: str) -> tuple:
    """(ok, message). ok only if signature is Valid and signer matches."""
    if sys.platform != "win32":
        return False, "Authenticode verification is only available on Windows."
    try:
        status, subject = authenticode_signer(path)
    except Exception as e:
        return False, f"Signature check failed: {e}"
    if status != "Valid":
        return False, f"Installer signature status is '{status}'."
    if required_subject_substr.lower() not in subject.lower():
        return False, f"Installer signed by unexpected publisher: {subject}"
    return True, subject
