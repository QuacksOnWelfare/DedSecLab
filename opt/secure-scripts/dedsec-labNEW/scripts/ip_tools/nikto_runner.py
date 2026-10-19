#!/usr/bin/env python3
"""
Nikto lab runner - authorized targets only.
Usage:
  nikto_runner.py <target_url_or_host> [maxtime_seconds]
Example:
  nikto_runner.py https://example.com 120
"""
from __future__ import annotations

import os
import re
import sys
import time
import subprocess
from pathlib import Path
from urllib.parse import urlparse

NIKTO_BIN = "/usr/bin/nikto"
BASE = Path("/opt/nikto-lab")
LOG_DIR = BASE / "logs"
JOB_DIR = BASE / "jobs"
DEFAULT_MAXTIME = 120
HARD_MAXTIME = 300  # absolute cap

# Optional: only allow these hosts/suffixes (empty set = allow any syntactically valid target)
# Fill this in for production, e.g. {"example.com", "yourlab.local"}
ALLOW_HOST_SUFFIXES: set[str] = set()

LOG_DIR.mkdir(parents=True, exist_ok=True)
JOB_DIR.mkdir(parents=True, exist_ok=True)


def die(msg: str, code: int = 1) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def normalize_target(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw or len(raw) > 500:
        die("invalid target")
    if "://" not in raw:
        raw = "http://" + raw
    u = urlparse(raw)
    if u.scheme not in ("http", "https"):
        die("only http/https allowed")
    if not u.hostname:
        die("missing hostname")
    # block obvious local escapes if you want (comment out if you scan lab LAN)
    host = u.hostname.lower().rstrip(".")
    if host in ("localhost", "127.0.0.1", "::1"):
        die("localhost not allowed")
    if ALLOW_HOST_SUFFIXES:
        ok = any(host == s or host.endswith("." + s) for s in ALLOW_HOST_SUFFIXES)
        if not ok:
            die("target not in allowlist")
    # rebuild clean URL (host + optional port + path)
    netloc = u.hostname
    if u.port:
        netloc = f"{u.hostname}:{u.port}"
    path = u.path or "/"
    return f"{u.scheme}://{netloc}{path}"


def run_nikto(target: str, maxtime: int) -> dict:
    if not os.path.isfile(NIKTO_BIN):
        die(f"nikto not found at {NIKTO_BIN}")

    session = f"nikto_{int(time.time())}"
    out_file = LOG_DIR / f"{session}.txt"
    maxtime = max(30, min(int(maxtime), HARD_MAXTIME))

    cmd = [
        NIKTO_BIN,
        "-h", target,
        "-maxtime", f"{maxtime}s",
        "-Format", "txt",
        "-output", str(out_file),
    ]

    started = time.time()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=maxtime + 60,
            cwd=str(JOB_DIR),
        )
    except subprocess.TimeoutExpired:
        die("nikto hard timeout")

    # merge file + stdout
    body = ""
    if out_file.is_file():
        body = out_file.read_text(encoding="utf-8", errors="ignore")
    else:
        body = (proc.stdout or "") + (proc.stderr or "")

    # nikto often exits non-zero; still return report
    return {
        "ok": True,
        "session": session,
        "target": target,
        "maxtime": maxtime,
        "exit_code": proc.returncode,
        "elapsed": round(time.time() - started, 1),
        "log_file": str(out_file),
        "report": body[-12000:],
    }


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__.strip())
        sys.exit(2)

    target = normalize_target(sys.argv[1])
    maxtime = DEFAULT_MAXTIME
    if len(sys.argv) >= 3:
        try:
            maxtime = int(sys.argv[2])
        except ValueError:
            die("maxtime must be an integer (seconds)")

    result = run_nikto(target, maxtime)
    print(f"session={result['session']} exit={result['exit_code']} elapsed={result['elapsed']}s")
    print(f"log={result['log_file']}")
    print("--- report ---")
    print(result["report"] or "(empty report)")


if __name__ == "__main__":
    main()
