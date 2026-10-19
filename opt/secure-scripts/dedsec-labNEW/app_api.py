"""
DedSecLab lab API. Set the YOUR_* values in config before deploying.
"""
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from datetime import datetime, date, timedelta
import psutil
import json
import os
import sys
import hashlib
import base64
import hmac
import asyncio
import subprocess
import pty
import select
import signal
import sqlite3
import time
import uuid
import secrets
import socket
import urllib.request

BASE_DIR = "/opt/secure-scripts/dedsec-labNEW"
RULES_FILE = os.path.join(BASE_DIR, "access_rules.json")
SESSIONS_FILE = os.path.join(BASE_DIR, "user_sessions.json")
LOCKER_DB = "/opt/secure-scripts/dedsec-labNEW/hardware_locker/locker.db"
IP_DB_FILE = os.path.join(BASE_DIR, "ip_database.json")

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

# =========================================================
# TERMINAL TOKEN STORE
# =========================================================
_terminal_tokens = {}
_terminal_tokens_lock = asyncio.Lock()
TERMINAL_TOKEN_TTL_SECONDS = 90


async def _cleanup_expired_tokens():
    now = time.time()
    expired = [
        t for t, meta in _terminal_tokens.items()
        if meta.get("used") or meta.get("expires", 0) < now
    ]
    for t in expired:
        _terminal_tokens.pop(t, None)


def _make_terminal_token() -> str:
    return secrets.token_urlsafe(32)


async def issue_terminal_token(ip: str, display_name: str, role: str) -> str:
    async with _terminal_tokens_lock:
        await _cleanup_expired_tokens()
        token = _make_terminal_token()
        _terminal_tokens[token] = {
            "ip": ip,
            "user": display_name,
            "role": role,
            "expires": time.time() + TERMINAL_TOKEN_TTL_SECONDS,
            "used": False,
        }
        return token


async def validate_and_consume_terminal_token(token: str, expected_ip: str) -> bool:
    if not token or not isinstance(token, str) or len(token) < 16:
        return False
    async with _terminal_tokens_lock:
        await _cleanup_expired_tokens()
        meta = _terminal_tokens.get(token)
        if not meta:
            return False
        if meta.get("used"):
            return False
        if meta.get("expires", 0) < time.time():
            _terminal_tokens.pop(token, None)
            return False
        if meta.get("ip") != expected_ip:
            return False
        meta["used"] = True
        return True


# =========================================================
# JOHN API HELPERS (VPN + one-time token)
# =========================================================
JOHN_BIN = "/opt/john-bleeding-jumbo/run/john"
JOHN_BASE = "/opt/john-menu"
JOHN_HASH_DIR = os.path.join(JOHN_BASE, "hashes")
JOHN_WORDLIST_DIR = os.path.join(JOHN_BASE, "wordlists")
JOHN_LOG_DIR = os.path.join(JOHN_BASE, "logs")
JOHN_POT = os.path.join(JOHN_BASE, "john.pot")
JOHN_TOKEN_TTL_SECONDS = 90
JOHN_MAX_RUNTIME = 3600
JOHN_MAX_UPLOAD_BYTES = 8 * 1024 * 1024  # 8 MB custom wordlist

_john_tokens = {}
_john_tokens_lock = asyncio.Lock()
_john_jobs = {}
_john_jobs_lock = asyncio.Lock()


async def issue_john_token(ip: str, display_name: str, role: str) -> str:
    async with _john_tokens_lock:
        now = time.time()
        expired = [
            t for t, m in _john_tokens.items()
            if m.get("used") or m.get("expires", 0) < now
        ]
        for t in expired:
            _john_tokens.pop(t, None)
        token = secrets.token_urlsafe(32)
        _john_tokens[token] = {
            "ip": ip,
            "user": display_name,
            "role": role,
            "expires": now + JOHN_TOKEN_TTL_SECONDS,
            "used": False,
        }
        return token


async def validate_and_consume_john_token(token: str, expected_ip: str) -> bool:
    if not token or not isinstance(token, str) or len(token) < 16:
        return False
    async with _john_tokens_lock:
        now = time.time()
        meta = _john_tokens.get(token)
        if not meta or meta.get("used") or meta.get("expires", 0) < now:
            _john_tokens.pop(token, None)
            return False
        if meta.get("ip") != expected_ip:
            return False
        meta["used"] = True
        return True


def _john_safe_wordlist_name(name: str):
    name = (name or "").strip()
    if not name or ".." in name or name.startswith("/") or "\\" in name:
        return None
    if not name.endswith((".txt", ".lst", ".dic", ".wordlist", ".pass", ".passwords")):
        return None
    return name


# =========================================================
# NETWORK EMULATION (tc / netem on tun0, per VPN IP)
# =========================================================
NETEM_IFACE = "tun0"
NETEM_MAX_DURATION = 86400
NETEM_CAP_DELAY_MS = 0
NETEM_CAP_LOSS_PCT = 95.0
NETEM_CAP_CORRUPT_PCT = 90.0
NETEM_CAP_REORDER_PCT = 90.0
NETEM_CAP_MIN_RATE_KB = 50.0
NETEM_WHITELIST_PORTS = (8443, 80, 443)
_netem_sessions = {}
_netem_lock = asyncio.Lock()
_netem_class_counter = 10


def _clamp(val, lo, hi):
    try:
        v = float(val)
    except Exception:
        v = lo
    return max(lo, min(hi, v))


def _tc(*args):
    try:
        r = subprocess.run(
            ["tc", *args],
            capture_output=True,
            text=True,
            timeout=8,
        )
        out = (r.stdout or "") + (r.stderr or "")
        return r.returncode == 0, out.strip()
    except Exception as e:
        return False, str(e)


def _netem_build_args(cfg: dict) -> list:
    args = []
    delay = int(cfg.get("delay_ms") or 0)
    jitter = int(cfg.get("jitter_ms") or 0)
    loss = float(cfg.get("loss_pct") or 0)
    corrupt = float(cfg.get("corrupt_pct") or 0)
    reorder = float(cfg.get("reorder_pct") or 0)
    if delay > 0 or jitter > 0:
        args += ["delay", f"{delay}ms"]
        if jitter > 0:
            args += [f"{jitter}ms"]
    if loss > 0:
        args += ["loss", f"{loss}%"]
    if corrupt > 0:
        args += ["corrupt", f"{corrupt}%"]
    if reorder > 0 and delay > 0:
        args += ["reorder", f"{reorder}%"]
    if not args:
        args = ["delay", "0ms"]
    return args


async def _netem_rebuild_all():
    global _netem_class_counter
    _tc("qdisc", "del", "dev", NETEM_IFACE, "root")
    now = time.time()
    expired = [ip for ip, s in _netem_sessions.items() if s.get("expires", 0) <= now]
    for ip in expired:
        _netem_sessions.pop(ip, None)
    if not _netem_sessions:
        return True, "idle"
    ok, out = _tc(
        "qdisc", "add", "dev", NETEM_IFACE,
        "root", "handle", "1:", "htb", "default", "999"
    )
    if not ok:
        return False, f"root qdisc failed: {out}"
    _tc(
        "class", "add", "dev", NETEM_IFACE,
        "parent", "1:", "classid", "1:999",
        "htb", "rate", "1000mbit"
    )
    _netem_class_counter = 10
    for ip, cfg in _netem_sessions.items():
        classid = _netem_class_counter
        _netem_class_counter += 1
        flow = f"1:{classid}"
        rate_kb = float(cfg.get("rate_kb") or 0)
        rate_str = f"{int(rate_kb)}kbit" if rate_kb >= NETEM_CAP_MIN_RATE_KB else "100mbit"
        _tc(
            "class", "add", "dev", NETEM_IFACE,
            "parent", "1:", "classid", flow,
            "htb", "rate", rate_str, "ceil", rate_str
        )
        netem_args = _netem_build_args(cfg)
        _tc(
            "qdisc", "add", "dev", NETEM_IFACE,
            "parent", flow, "handle", f"{classid}:",
            "netem", *netem_args
        )
        direction = (cfg.get("direction") or "both").lower()
        for port in NETEM_WHITELIST_PORTS:
            port = int(port)
            if direction in ("both", "out", "outbound"):
                _tc(
                    "filter", "add", "dev", NETEM_IFACE,
                    "protocol", "ip", "parent", "1:", "prio", "1",
                    "u32",
                    "match", "ip", "src", f"{ip}/32",
                    "match", "ip", "dport", str(port), "0xffff",
                    "flowid", "1:999"
                )
            if direction in ("both", "in", "inbound"):
                _tc(
                    "filter", "add", "dev", NETEM_IFACE,
                    "protocol", "ip", "parent", "1:", "prio", "1",
                    "u32",
                    "match", "ip", "dst", f"{ip}/32",
                    "match", "ip", "sport", str(port), "0xffff",
                    "flowid", "1:999"
                )
        if direction in ("both", "in", "inbound"):
            _tc(
                "filter", "add", "dev", NETEM_IFACE,
                "protocol", "ip", "parent", "1:", "prio", "2",
                "u32", "match", "ip", "dst", f"{ip}/32",
                "flowid", flow
            )
        if direction in ("both", "out", "outbound"):
            _tc(
                "filter", "add", "dev", NETEM_IFACE,
                "protocol", "ip", "parent", "1:", "prio", "2",
                "u32", "match", "ip", "src", f"{ip}/32",
                "flowid", flow
            )
        cfg["classid"] = flow
    return True, "applied"


def _netem_normalize(body: dict) -> dict:
    delay = int(_clamp(body.get("delay_ms", 0), 0, NETEM_CAP_DELAY_MS))
    jitter = int(_clamp(body.get("jitter_ms", 0), 0, NETEM_CAP_DELAY_MS))
    loss = _clamp(body.get("loss_pct", 0), 0, NETEM_CAP_LOSS_PCT)
    corrupt = _clamp(body.get("corrupt_pct", 0), 0, NETEM_CAP_CORRUPT_PCT)
    reorder = _clamp(body.get("reorder_pct", 0), 0, NETEM_CAP_REORDER_PCT)
    rate = float(body.get("rate_kb") or 0)
    if rate > 0:
        rate = max(rate, NETEM_CAP_MIN_RATE_KB)
    direction = str(body.get("direction") or "both").lower()
    if direction not in ("both", "in", "out", "inbound", "outbound"):
        direction = "both"
    enabled = body.get("enabled") or {}
    return {
        "delay_ms": delay if enabled.get("latency", True) else 0,
        "jitter_ms": jitter if enabled.get("jitter", True) else 0,
        "loss_pct": loss if enabled.get("loss", True) else 0,
        "corrupt_pct": corrupt if enabled.get("corrupt", True) else 0,
        "reorder_pct": reorder if enabled.get("reorder", True) else 0,
        "rate_kb": rate if enabled.get("speed", True) else 0,
        "direction": direction,
        "preset": str(body.get("preset") or ""),
    }


class LoginRequest(BaseModel):
    username: str
    password: str
    fingerprint: str = ""
    label: str = ""
    version: str = ""


class ChangePasswordRequest(BaseModel):
    username: str
    current_password: str
    new_password: str


class NetEmulateRequest(BaseModel):
    delay_ms: float = 0
    jitter_ms: float = 0
    loss_pct: float = 0
    corrupt_pct: float = 0
    reorder_pct: float = 0
    rate_kb: float = 0
    direction: str = "both"
    preset: str = ""
    enabled: dict = {}


class JohnStartRequest(BaseModel):
    token: str
    hash_text: str
    wordlist: str = "rockyou.txt"
    format: str = "Auto"


class JohnWordlistRequest(BaseModel):
    token: str
    filename: str = "custom.txt"
    content: str = ""


class CuppRequest(BaseModel):
    token: str
    first_name: str = ""
    surname: str = ""
    nickname: str = ""
    birthdate: str = ""  # DDMMYYYY
    partner_name: str = ""
    partner_nickname: str = ""
    partner_birthdate: str = ""
    child_name: str = ""
    child_nickname: str = ""
    child_birthdate: str = ""
    pet_name: str = ""
    company: str = ""
    keywords: str = ""  # comma-separated optional
    special_chars: bool = True
    random_numbers: bool = True
    leet: bool = False


def load_rules():
    with open(RULES_FILE, "r", encoding="utf-8") as f:
        return json.load(f)



def _update_website_password(username: str, password: str):
    username = (username or "").strip().lower()
    if not username:
        return False, "no website username"
    website_dir = "/var/www/YOUR_WEBSITE_DIR"
    manage_py = os.path.join(website_dir, "manage.py")
    if not os.path.isfile(manage_py):
        return False, "manage.py missing"
    code = (
        "from django.contrib.auth.models import User\n"
        f"u = User.objects.filter(username__iexact={username!r}).first()\n"
        "if not u:\n"
        "    print('missing')\n"
        "else:\n"
        f"    u.set_password({password!r})\n"
        "    u.save()\n"
        "    print('updated')\n"
    )
    for pybin in (
        os.path.join(website_dir, "venv/bin/python3"),
        os.path.join(website_dir, "venv/bin/python"),
        sys.executable,
    ):
        if not os.path.exists(pybin):
            continue
        r = subprocess.run(
            [pybin, manage_py, "shell", "-c", code],
            cwd=website_dir,
            text=True,
            capture_output=True,
        )
        out = (r.stdout or "").strip().splitlines()
        last = out[-1].strip() if out else ""
        if r.returncode == 0 and last == "updated":
            return True, "updated"
        if r.returncode == 0 and last == "missing":
            return False, "website user not found"
        err = (r.stderr or r.stdout or "").strip()
        if err:
            return False, err[:200]
    return False, "django python not found"

def save_rules(rules):
    with open(RULES_FILE, "w", encoding="utf-8") as f:
        json.dump(rules, f, indent=2)


def load_ip_database():
    try:
        with open(IP_DB_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
    except Exception:
        pass
    return []


def save_ip_database(data):
    with open(IP_DB_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def parse_date(value):
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except Exception:
        return None


def calc_days_left(expiry):
    expiry_date = parse_date(expiry)
    if not expiry_date:
        return None
    return (expiry_date - date.today()).days


def get_client_ip(request: Request):
    return request.client.host


def make_password_hash(password):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200000)
    return (
        "pbkdf2_sha256$200000$"
        + base64.b64encode(salt).decode()
        + "$"
        + base64.b64encode(dk).decode()
    )


def verify_password(password, stored_hash):
    try:
        algo, iterations, salt_b64, hash_b64 = stored_hash.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected_hash = base64.b64decode(hash_b64)
        actual_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt, int(iterations)
        )
        return hmac.compare_digest(actual_hash, expected_hash)
    except Exception:
        return False


def save_session(ip, user, role):
    try:
        with open(SESSIONS_FILE, "r", encoding="utf-8") as f:
            sessions = json.load(f)
    except Exception:
        sessions = {}
    sessions[ip] = {
        "user": user,
        "role": role,
        "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source": "pyqt_app",
    }
    with open(SESSIONS_FILE, "w", encoding="utf-8") as f:
        json.dump(sessions, f, indent=2)


def validate_vpn_user(ip):
    rules = load_rules()
    user_rule = rules.get("users", {}).get(ip)
    if not user_rule:
        return None, {
            "ok": False,
            "reason": "VPN IP is not whitelisted",
            "vpn_ip": ip,
        }
    if not user_rule.get("enabled", True):
        return None, {
            "ok": False,
            "reason": "User disabled",
            "vpn_ip": ip,
        }
    expiry = user_rule.get("subscription_expires")
    days_left = calc_days_left(expiry)
    if days_left is not None and days_left < 0:
        return None, {
            "ok": False,
            "reason": "Subscription expired",
            "vpn_ip": ip,
            "subscription_expires": expiry,
            "days_left": days_left,
        }
    return user_rule, None


def build_user_response(ip, user_rule):
    expiry = user_rule.get("subscription_expires")
    days_left = calc_days_left(expiry)
    display_name = user_rule.get("display_name", "unknown")
    role = user_rule.get("role", "standard").lower()
    save_session(ip, display_name, role)
    return {
        "ok": True,
        "display_name": display_name,
        "app_username": user_rule.get("app_username", ""),
        "role": role,
        "vpn_ip": ip,
        "ssh_user": user_rule.get("ssh_user"),
        "discord_name": user_rule.get("discord_name"),
        "current_vpn_region": user_rule.get("current_vpn_region", "UK"),
        "subscription_expires": expiry,
        "days_left": days_left,
        "welcome_message": user_rule.get("welcome_message", ""),
    }


def _now():
    return datetime.now().isoformat()



def _parse_app_version(v: str):
    try:
        return tuple(int(x) for x in str(v).strip().lstrip("vV").split(".") if x != "")
    except Exception:
        return (0, 0, 0)

def _locker_min_version() -> str:
    try:
        conn = sqlite3.connect(LOCKER_DB, timeout=5)
        row = conn.execute("SELECT value FROM config WHERE key = 'min_version'").fetchone()
        conn.close()
        if row and row[0]:
            return str(row[0]).strip()
    except Exception:
        pass
    return "1.0.1"

def check_app_version(client_version: str) -> bool:
    """True if client is allowed."""
    ver = (client_version or "").strip() or "0.0.0"
    return _parse_app_version(ver) >= _parse_app_version(_locker_min_version())

def check_device_fingerprint(fingerprint: str, label: str = "", user: str = "", vpn_ip: str = "") -> str:
    """Return device status: 'approved' | 'pending' | 'revoked' | 'error'.

    H3 hardening vs the original:
      * Empty / malformed / placeholder fingerprints are rejected ('error').
      * The first device is NO LONGER auto-approved unless the operator
        explicitly sets locker.db config 'auto_approve_first_device' = '1'.
        New devices enroll as 'pending' and require admin approval.
      * Devices are bound to the account that enrolled them. An approved
        fingerprint presented under a DIFFERENT account is treated as an
        impersonation attempt and denied ('revoked').
      * FAILS CLOSED: on any DB error the device is NOT trusted ('error'),
        instead of the previous 'approved' default.

    The client fingerprint remains only a HINT. For full assurance, issue a
    per-device enrollment secret at approval time and verify it on every
    request (the reserved 'enroll_secret' column is where it would live).
    """
    fp = (fingerprint or "").strip().lower()
    if not _fp_is_valid(fp):
        return "error"
    _ensure_device_columns()
    try:
        conn = sqlite3.connect(LOCKER_DB, timeout=5)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        row = cur.execute(
            "SELECT id, status, bound_user FROM devices WHERE lower(fingerprint) = ?",
            (fp,),
        ).fetchone()
        if row:
            status = row["status"]
            bound_user = (row["bound_user"] or "").strip().lower()
            req_user = (user or "").strip().lower()
            if status == "approved":
                if bound_user:
                    # An approved device must stay on its enrolled account.
                    if req_user and req_user != bound_user:
                        cur.execute(
                            """
                            INSERT INTO audit_log (device_id, action, actor, timestamp, details)
                            VALUES (?, ?, ?, ?, ?)
                            """,
                            (row["id"], "account-mismatch", "server", _now(),
                             f"fingerprint bound to '{bound_user}' used by '{req_user}'"),
                        )
                        conn.commit()
                        conn.close()
                        return "revoked"
                elif req_user:
                    # Legacy row without a binding yet: bind it now (one-time).
                    cur.execute(
                        "UPDATE devices SET bound_user = ?, bound_vpn_ip = ?, updated_at = ? WHERE id = ?",
                        (user, vpn_ip, _now(), row["id"]),
                    )
                    conn.commit()
            conn.close()
            return status
        # --- New device enrollment ---
        auto_first = _locker_cfg("auto_approve_first_device", "0").lower() in (
            "1", "true", "yes", "on",
        )
        approved_count = cur.execute(
            "SELECT COUNT(*) FROM devices WHERE status = 'approved'"
        ).fetchone()[0]
        device_id = str(uuid.uuid4())
        device_label = label or f"Device {device_id[:8].upper()}"
        if auto_first and approved_count == 0:
            cur.execute(
                """
                INSERT INTO devices
                (id, fingerprint, label, status, registered_at, updated_at, approved_by, bound_user, bound_vpn_ip)
                VALUES (?, ?, ?, 'approved', ?, ?, 'auto-first', ?, ?)
                """,
                (device_id, fingerprint, device_label, _now(), _now(), user, vpn_ip),
            )
            cur.execute(
                """
                INSERT INTO audit_log (device_id, action, actor, timestamp, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (device_id, "registered+auto-approved", "server", _now(),
                 "First device auto-approved (auto_approve_first_device enabled)"),
            )
            status = "approved"
        else:
            notes = f"user={user or device_label} vpn={vpn_ip or 'unknown'}"
            cur.execute(
                """
                INSERT INTO devices
                (id, fingerprint, label, status, registered_at, updated_at, notes, bound_user, bound_vpn_ip)
                VALUES (?, ?, ?, 'pending', ?, ?, ?, ?, ?)
                """,
                (device_id, fingerprint, device_label, _now(), _now(), notes, user, vpn_ip),
            )
            cur.execute(
                """
                INSERT INTO audit_log (device_id, action, actor, timestamp, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (device_id, "registered", None, _now(), "Pending admin approval"),
            )
            status = "pending"
            try:
                import json as _json
                import urllib.request as _ur
                wh_path = "/opt/secure-scripts/dedsec-labNEW/hardware_locker/hwid_webhook.json"
                wh = ""
                try:
                    d = _json.loads(open(wh_path, encoding="utf-8").read())
                    wh = str(d.get("webhook") or d.get("url") or "").strip()
                except Exception:
                    wh = ""
                if wh.startswith("https://discord.com/api/webhooks/"):
                    short = (fingerprint or "")[:16].upper()
                    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    msg = (
                        f"**Time:** `{now}`\n"
                        f"**User:** `{user or device_label or 'unknown'}`\n"
                        f"**VPN IP:** `{vpn_ip or 'unknown'}`\n"
                        f"**Fingerprint:** `{short}`"
                    )
                    body = _json.dumps({
                        "username": "DedSecEye",
                        "embeds": [{
                            "title": "HWID request - pending",
                            "description": msg,
                            "color": 0xFFAA00,
                            "footer": {"text": "DEDSCAN • HWID locker"},
                        }],
                    }).encode()
                    req = _ur.Request(
                        wh,
                        data=body,
                        headers={
                            "Content-Type": "application/json",
                            "User-Agent": "DedSecEye/1.0 (HWID; +https://discord.com)",
                        },
                        method="POST",
                    )
                    _ur.urlopen(req, timeout=10)
            except Exception:
                pass
        conn.commit()
        conn.close()
        return status
    except Exception:
        # FAIL CLOSED: never trust a device we could not verify.
        return "error"

def service_state(name):
    try:
        result = subprocess.run(
            ["systemctl", "is-active", name],
            capture_output=True,
            text=True,
            timeout=2,
        )
        state = result.stdout.strip()
        return state if state else "unknown"
    except Exception:
        return "unknown"


def load_sessions():
    try:
        with open(SESSIONS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


# =========================================================
# API ROUTES
# =========================================================


# =========================================================
# HARDENING HELPERS (defensive - added to match the hardened client)
# =========================================================
import threading as _threading
from pathlib import Path as _Path

UPDATE_DIR = "/opt/secure-scripts/dedsec-labNEW/app_updates"


def _locker_cfg(key, default=""):
    """Best-effort single value read from the locker.db `config` table."""
    try:
        conn = sqlite3.connect(LOCKER_DB, timeout=5)
        row = conn.execute("SELECT value FROM config WHERE key = ?", (key,)).fetchone()
        conn.close()
        if row and row[0] is not None and str(row[0]).strip():
            return str(row[0]).strip()
    except Exception:
        pass
    return default


def _bearer_token_from_ws(websocket) -> str:
    """Extract the bearer token from the WebSocket handshake Authorization
    header. The hardened client (H4) sends `Authorization: Bearer <token>` and
    no longer puts the token in the URL query string."""
    try:
        auth = (
            websocket.headers.get("authorization")
            or websocket.headers.get("Authorization")
            or ""
        )
    except Exception:
        auth = ""
    auth = auth.strip()
    if auth[:7].lower() == "bearer ":
        return auth[7:].strip()
    return ""


# ---- Update manifest integrity (C2) -------------------------------------
def _update_file_path():
    """Resolve the exact update file served by /api/update/download."""
    folder = _Path(UPDATE_DIR)
    name = _locker_cfg("download_filename")
    if name:
        path = folder / _Path(name).name
        return path if path.is_file() else None
    try:
        files = (
            sorted(folder.glob("*.exe"))
            + sorted(folder.glob("*.msi"))
            + sorted(folder.glob("*.zip"))
        )
    except Exception:
        files = []
    return files[-1] if files else None


_update_integrity_cache = {}
_update_integrity_lock = _threading.Lock()


def _load_update_signing_key():
    """Load an Ed25519 private key for signing updates, if configured.

    Key material is NEVER hardcoded. Provide it via either:
      * env  DEDSEC_UPDATE_SIGNING_KEY  = path to a PEM Ed25519 private key, or
      * locker.db config key 'update_signing_key_path'
    Returns an Ed25519PrivateKey or None. See UPDATE_SIGNING.md for how to
    generate the key and publish the matching public key to the client
    (UPDATE_SIGNING_PUBKEY_B64 in core/updater.py)."""
    key_path = (
        os.environ.get("DEDSEC_UPDATE_SIGNING_KEY", "").strip()
        or _locker_cfg("update_signing_key_path")
    )
    if not key_path or not os.path.isfile(key_path):
        return None
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        with open(key_path, "rb") as fh:
            key = load_pem_private_key(fh.read(), password=None)
        if isinstance(key, Ed25519PrivateKey):
            return key
    except Exception:
        pass
    return None


def _update_integrity(path):
    """Return (sha256_hex, signature_b64) for the update file, cached by
    (path, size, mtime). signature_b64 is '' when no signing key is set."""
    try:
        st = path.stat()
    except Exception:
        return "", ""
    cache_key = (str(path), st.st_size, int(st.st_mtime))
    with _update_integrity_lock:
        cached = _update_integrity_cache.get(cache_key)
    if cached:
        return cached
    try:
        data = path.read_bytes()
    except Exception:
        return "", ""
    sha = hashlib.sha256(data).hexdigest()
    sig = ""
    key = _load_update_signing_key()
    if key is not None:
        try:
            sig = base64.b64encode(key.sign(data)).decode("ascii")
        except Exception:
            sig = ""
    with _update_integrity_lock:
        _update_integrity_cache[cache_key] = (sha, sig)
    return sha, sig


# ---- Device fingerprint hardening (H3) ----------------------------------
def _ensure_device_columns():
    """Additively ensure the devices table carries the columns needed for
    server-side account binding + future enrollment. Safe to call repeatedly."""
    try:
        conn = sqlite3.connect(LOCKER_DB, timeout=5)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(devices)").fetchall()}
        if "bound_user" not in cols:
            conn.execute("ALTER TABLE devices ADD COLUMN bound_user TEXT")
        if "bound_vpn_ip" not in cols:
            conn.execute("ALTER TABLE devices ADD COLUMN bound_vpn_ip TEXT")
        if "enroll_secret" not in cols:
            conn.execute("ALTER TABLE devices ADD COLUMN enroll_secret TEXT")
        conn.commit()
        conn.close()
    except Exception:
        pass


def _fp_is_valid(fp: str) -> bool:
    """Reject empty, malformed, or obviously placeholder fingerprints."""
    fp = (fp or "").strip().lower()
    if len(fp) != 64 or any(c not in "0123456789abcdef" for c in fp):
        return False
    if len(set(fp)) <= 2:  # all / near-all one character, e.g. 64*'a' or 64*'0'
        return False
    _blocklist = {
        hashlib.sha256(b"").hexdigest(),
        hashlib.sha256(b"unknown-device").hexdigest(),
    }
    if fp in _blocklist:
        return False
    return True


@app.get("/api/update/download")
async def api_update_download(request: Request):
    from fastapi.responses import FileResponse
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    # Resolve the exact file via the shared helper so /api/update/version and
    # /api/update/download always describe and serve the SAME bytes (C2).
    path = _update_file_path()
    if path is None or not path.is_file():
        return {"ok": False, "reason": "Update file is not on the server yet."}
    return FileResponse(
        path=str(path),
        filename=path.name,
        media_type="application/octet-stream",
    )

@app.get("/api/update/version")
async def api_update_version():
    """Public-enough on VPN: current published app version + where to get it.

    Hardened client (C2) requires `sha256` (hex) of the exact zip bytes served
    by /api/update/download. Optional Ed25519 `signature` is included when a
    signing key is configured (see UPDATE_SIGNING.md / SERVER_TLS.md).
    """
    latest = _locker_cfg("latest_version") or _locker_cfg("min_version") or "1.0.1"
    min_v = _locker_cfg("min_version") or "1.0.1"
    sha256 = ""
    signature = ""
    _upath = _update_file_path()
    if _upath is not None:
        sha256, signature = _update_integrity(_upath)
    resp = {
        "ok": True,
        "version": latest,
        "min_version": min_v,
        "notes": _locker_cfg("update_notes", ""),
        "website_url": _locker_cfg("website_url", "https://YOUR_WEBSITE_URL.example"),
        # Client requires https SAME-ORIGIN as the API (e.g. "/api/update/download").
        "download_url": _locker_cfg("download_url", ""),
        "sha256": sha256,
    }
    if signature:
        resp["signature"] = signature
    return resp

@app.get("/api/status")
def api_status(request: Request):
    ip = get_client_ip(request)
    local_check_ips = ["127.0.0.1", "YOUR_LAB_VPN_IP"]
    if ip not in local_check_ips:
        user_rule, error = validate_vpn_user(ip)
        if error:
            return error
    try:
        psutil.cpu_percent(None)
        cpu = int(psutil.cpu_percent(interval=1))
        ram = int(psutil.virtual_memory().percent)
        disk = int(psutil.disk_usage("/").percent)
    except Exception:
        cpu = ram = disk = 0
    sessions = load_sessions()
    openvpn_state = service_state("openvpn-server@server.service")
    api_state = service_state("dedsec-api.service")
    ssh_state = service_state("ssh.service")
    vpn_text = "Connected" if openvpn_state == "active" else openvpn_state.title()
    return {
        "ok": True,
        "online": True,
        "cpu": cpu,
        "ram": ram,
        "disk": disk,
        "vpn": vpn_text,
        "api": api_state,
        "openvpn": openvpn_state,
        "ssh": ssh_state,
        "active_sessions": len(sessions),
        "vpn_ip": ip,
        "server_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


@app.get("/api/me")
def api_me(request: Request):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    return build_user_response(ip, user_rule)


@app.get("/api/ips")
def get_ips(request: Request):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return []
    return load_ip_database()


@app.post("/api/ips/add")
def add_ip(data: dict, request: Request):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return {"ok": False, "reason": "Access denied"}
    database = load_ip_database()
    new_entry = {
        "ip": str(data.get("ip", "")).strip(),
        "label": str(data.get("label", "")).strip(),
        "network": str(data.get("network", "")).strip(),
        "country": str(data.get("country", "")).strip(),
        "notes": str(data.get("notes", "")).strip(),
        "status": "active",
        "added": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    if not new_entry["ip"]:
        return {"ok": False, "reason": "Missing IP"}
    for entry in database:
        if str(entry.get("ip", "")).strip() == new_entry["ip"]:
            return {"ok": False, "reason": "IP already exists"}
    database.insert(0, new_entry)
    save_ip_database(database)
    return {"ok": True}


@app.delete("/api/ips/{target_ip}")
def delete_ip(target_ip: str, request: Request):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return {"ok": False, "reason": "Access denied"}
    database = load_ip_database()
    updated = [
        entry for entry in database
        if str(entry.get("ip", "")).strip() != target_ip.strip()
    ]
    save_ip_database(updated)
    return {"ok": True}


@app.post("/api/login")
def api_login(payload: LoginRequest, request: Request):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    expected_username = str(user_rule.get("app_username", "")).strip().lower()
    given_username = payload.username.strip().lower()
    if not expected_username or given_username != expected_username:
        return {"ok": False, "reason": "Invalid username or password", "vpn_ip": ip}
    if not verify_password(payload.password, user_rule.get("app_password_hash", "")):
        return {"ok": False, "reason": "Invalid username or password", "vpn_ip": ip}
    if not check_app_version(getattr(payload, "version", "") or ""):
        min_ver = _locker_min_version()
        latest = min_ver
        try:
            import json as _vj
            for vp in (
                "/opt/secure-scripts/dedsec-labNEW/version.json",
                "/var/www/YOUR_WEBSITE_DIR/version.json",
                "/var/www/html/downloads/version.json",
            ):
                from pathlib import Path as _P
                if _P(vp).is_file():
                    latest = str(_vj.loads(_P(vp).read_text(encoding="utf-8")).get("version") or min_ver)
                    break
        except Exception:
            latest = min_ver
        return {
            "ok": False,
            "reason": (
                f"You are using an old version of the app. "
                f"New version {latest} is available. Please update."
            ),
            "min_version": min_ver,
            "latest_version": latest,
            "vpn_ip": ip,
        }
    if payload.fingerprint:
        device_status = check_device_fingerprint(payload.fingerprint, payload.label, payload.username, ip)
        if device_status == "pending":
            try:
                import json as _json, time as _time, urllib.request as _ur
                seen_path = "/opt/secure-scripts/dedsec-labNEW/hardware_locker/hwid_alert_seen.json"
                fp = (payload.fingerprint or "")[:16].upper()
                now_ts = int(_time.time())
                seen = {}
                try:
                    seen = _json.loads(open(seen_path, encoding="utf-8").read())
                    if not isinstance(seen, dict):
                        seen = {}
                except Exception:
                    seen = {}
                last = int((seen.get("cooldowns") or {}).get(fp) or 0)
                if now_ts - last >= 600:
                    seen.setdefault("cooldowns", {})[fp] = now_ts
                    open(seen_path, "w", encoding="utf-8").write(_json.dumps(seen, indent=2))
                    wh = ""
                    try:
                        d = _json.loads(open("/opt/secure-scripts/dedsec-labNEW/hardware_locker/hwid_webhook.json", encoding="utf-8").read())
                        wh = str(d.get("webhook") or d.get("url") or "").strip()
                    except Exception:
                        pass
                    if wh.startswith("https://discord.com/api/webhooks/"):
                        msg = (
                            f"**Time:** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`\n"
                            f"**User:** `{payload.username}`\n"
                            f"**VPN IP:** `{ip}`\n"
                            f"**Fingerprint:** `{fp}`\n"
                            f"**Status:** `pending`"
                        )
                        body = _json.dumps({
                            "username": "DedSecEye",
                            "embeds": [{
                                "title": "HWID request - pending",
                                "description": msg,
                                "color": 0xFFAA00,
                                "footer": {"text": "DEDSCAN • HWID locker"},
                            }],
                        }).encode()
                        req = _ur.Request(
                            wh, data=body,
                            headers={
                                "Content-Type": "application/json",
                                "User-Agent": "DedSecEye/1.0 (HWID; +https://discord.com)",
                            },
                            method="POST",
                        )
                        _ur.urlopen(req, timeout=10)
            except Exception:
                pass
            return {"ok": False, "reason": "device_pending", "vpn_ip": ip}
        if device_status == "revoked":
            return {"ok": False, "reason": "device_revoked", "vpn_ip": ip}
        if device_status == "error":
            # Fail closed: unverifiable, spoofed, or malformed fingerprint.
            return {"ok": False, "reason": "device_error", "vpn_ip": ip}
        if device_status != "approved":
            return {"ok": False, "reason": "device_pending", "vpn_ip": ip}
    return build_user_response(ip, user_rule)


@app.post("/api/change-password")
def api_change_password(payload: ChangePasswordRequest, request: Request):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    expected_username = str(user_rule.get("app_username", "")).strip().lower()
    given_username = (payload.username or "").strip().lower()
    if not expected_username or given_username != expected_username:
        return {"ok": False, "reason": "Invalid username or password"}
    if not verify_password(payload.current_password, user_rule.get("app_password_hash", "")):
        return {"ok": False, "reason": "Current password is wrong"}
    new_pw = (payload.new_password or "").strip()
    if len(new_pw) < 8:
        return {"ok": False, "reason": "New password must be at least 8 characters"}
    rules = load_rules()
    users = rules.get("users") or {}
    if ip not in users:
        return {"ok": False, "reason": "User record missing"}
    users[ip]["app_password_hash"] = make_password_hash(new_pw)
    save_rules(rules)
    web_user = str(users[ip].get("app_username") or payload.username or "").strip()
    web_ok, web_msg = _update_website_password(web_user, new_pw)
    if not web_ok:
        return {
            "ok": True,
            "message": "App password changed. Website login was not updated: " + web_msg,
        }
    return {"ok": True, "message": "App and website password changed."}


@app.post("/api/terminal-token")
async def api_terminal_token(request: Request):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    display_name = user_rule.get("display_name", "unknown")
    role = user_rule.get("role", "standard").lower()
    token = await issue_terminal_token(ip, display_name, role)
    return {
        "ok": True,
        "token": token,
        "expires_in": TERMINAL_TOKEN_TTL_SECONDS,
        "vpn_ip": ip,
    }


# =========================================================
# JOHN ROUTES
# =========================================================
@app.post("/api/john/token")
async def api_john_token(request: Request):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    token = await issue_john_token(
        ip,
        user_rule.get("display_name", "unknown"),
        user_rule.get("role", "standard").lower(),
    )
    return {
        "ok": True,
        "token": token,
        "expires_in": JOHN_TOKEN_TTL_SECONDS,
        "vpn_ip": ip,
    }


@app.get("/api/john/status")
async def api_john_status(request: Request):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    john_ok = os.path.isfile(JOHN_BIN) and os.access(JOHN_BIN, os.X_OK)
    wordlists = []
    try:
        for fn in sorted(os.listdir(JOHN_WORDLIST_DIR))[:30]:
            path = os.path.join(JOHN_WORDLIST_DIR, fn)
            if os.path.isfile(path):
                wordlists.append(fn)
    except Exception:
        pass
    async with _john_jobs_lock:
        job = _john_jobs.get(ip)
    return {
        "ok": True,
        "vpn_ip": ip,
        "john": "OK" if john_ok else "MISSING",
        "wordlists": wordlists,
        "job": job,
    }


@app.post("/api/john/start")
async def api_john_start(payload: JohnStartRequest, request: Request):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    if not await validate_and_consume_john_token(payload.token, expected_ip=ip):
        return {
            "ok": False,
            "reason": "invalid, expired, or missing john token",
            "vpn_ip": ip,
        }

    hash_text = (payload.hash_text or "").strip()
    if not hash_text or len(hash_text) > 200_000:
        return {"ok": False, "reason": "invalid hash payload"}

    wl_name = _john_safe_wordlist_name(payload.wordlist)
    if not wl_name:
        return {"ok": False, "reason": "invalid wordlist name"}

    wl_path = os.path.join(JOHN_WORDLIST_DIR, wl_name)
    if not os.path.isfile(wl_path):
        return {"ok": False, "reason": f"wordlist not found: {wl_name}"}

    if not os.path.isfile(JOHN_BIN):
        return {"ok": False, "reason": "john binary missing"}

    os.makedirs(JOHN_HASH_DIR, exist_ok=True)
    os.makedirs(JOHN_LOG_DIR, exist_ok=True)

    session = f"gui_{ip.replace('.', '_')}_{int(time.time())}"
    hash_file = os.path.join(JOHN_HASH_DIR, f"{session}.txt")
    log_file = os.path.join(JOHN_LOG_DIR, f"{session}.log")

    with open(hash_file, "w", encoding="utf-8") as f:
        f.write(hash_text.rstrip() + "\n")

    fmt = (payload.format or "Auto").strip()
    # Ensure pot file exists and is usable
    try:
        os.makedirs(JOHN_BASE, exist_ok=True)
        if not os.path.isfile(JOHN_POT):
            open(JOHN_POT, "a", encoding="utf-8").close()
    except Exception:
        pass

    cmd = [
        JOHN_BIN,
        f"--wordlist={wl_path}",
        f"--session={session}",
        f"--pot={JOHN_POT}",
    ]
    if fmt and fmt != "Auto":
        allowed = {
            "Raw-MD5", "Raw-SHA1", "Raw-SHA256", "Raw-SHA512",
            "NT", "bcrypt", "sha512crypt", "md5crypt", "sha256crypt",
        }
        if fmt not in allowed:
            return {"ok": False, "reason": "format not allowed"}
        cmd.append(f"--format={fmt}")
    cmd.append(hash_file)

    run_user = user_rule.get("ssh_user") or "dedsecuser"
    full_cmd = ["sudo", "-u", run_user, "--"] + cmd

    # Make hash/log dirs and pot writable for the run user when possible
    try:
        import pwd
        uid = pwd.getpwnam(run_user).pw_uid
        gid = pwd.getpwnam(run_user).pw_gid
        for path in (hash_file, JOHN_POT, JOHN_HASH_DIR, JOHN_LOG_DIR, JOHN_WORDLIST_DIR):
            try:
                os.chown(path, uid, gid)
            except Exception:
                pass
    except Exception:
        pass

    try:
        with open(log_file, "w", encoding="utf-8") as log:
            proc = subprocess.run(
                full_cmd,
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=JOHN_MAX_RUNTIME,
                cwd=JOHN_LOG_DIR,
            )
        try:
            import pwd
            os.chown(log_file, pwd.getpwnam(run_user).pw_uid, pwd.getpwnam(run_user).pw_gid)
        except Exception:
            pass
        with open(log_file, "r", encoding="utf-8", errors="ignore") as log:
            log_tail = log.read()[-4000:]
    except subprocess.TimeoutExpired:
        return {"ok": False, "reason": "john timed out", "log": log_file}
    except Exception as e:
        return {"ok": False, "reason": str(e)}

    show_cmd = [
        "sudo", "-u", run_user, "--", JOHN_BIN,
        "--show",
        f"--pot={JOHN_POT}",
    ]
    if fmt and fmt != "Auto":
        show_cmd.append(f"--format={fmt}")
    show_cmd.append(hash_file)
    try:
        show = subprocess.run(
            show_cmd,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=JOHN_LOG_DIR,
        )
        show_out = (show.stdout or "") + (show.stderr or "")
    except Exception as e:
        show_out = str(e)

    job = {
        "session": session,
        "hash_file": hash_file,
        "log_file": log_file,
        "format": fmt,
        "wordlist": wl_name,
        "exit_code": proc.returncode,
        "finished": time.time(),
        "user": user_rule.get("display_name", "unknown"),
    }
    async with _john_jobs_lock:
        _john_jobs[ip] = job

    return {
        "ok": True,
        "vpn_ip": ip,
        "session": session,
        "exit_code": proc.returncode,
        "log_tail": log_tail,
        "show": show_out[-2000:],
    }


@app.get("/api/john/show")
async def api_john_show(request: Request):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    async with _john_jobs_lock:
        job = _john_jobs.get(ip)
    if not job:
        return {"ok": False, "reason": "no job for this VPN IP"}

    fmt = job.get("format") or "Auto"
    hash_file = job.get("hash_file")
    run_user = user_rule.get("ssh_user") or "dedsecuser"
    show_cmd = [
        "sudo", "-u", run_user, "--", JOHN_BIN,
        "--show",
        f"--pot={JOHN_POT}",
    ]
    if fmt and fmt != "Auto":
        show_cmd.append(f"--format={fmt}")
    show_cmd.append(hash_file)

    try:
        show = subprocess.run(
            show_cmd, capture_output=True, text=True, timeout=30, cwd=JOHN_LOG_DIR
        )
        out = (show.stdout or "") + (show.stderr or "")
    except Exception as e:
        return {"ok": False, "reason": str(e)}

    return {
        "ok": True,
        "show": out,
        "session": job.get("session"),
        "vpn_ip": ip,
    }


@app.post("/api/john/wordlist")
async def api_john_wordlist(payload: JohnWordlistRequest, request: Request):
    """
    Upload a custom wordlist from the client (max 8 MB).
    Requires a one-time John token (same as /api/john/start).
    File is stored under /opt/john-menu/wordlists/ with a safe name.
    """
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error

    if not await validate_and_consume_john_token(payload.token, expected_ip=ip):
        return {
            "ok": False,
            "reason": "invalid, expired, or missing john token",
            "vpn_ip": ip,
        }

    raw_name = (payload.filename or "custom.txt").strip()
    raw_name = os.path.basename(raw_name)
    if not raw_name:
        raw_name = "custom.txt"
    # Keep only safe characters
    safe = "".join(c if (c.isalnum() or c in "._-") else "_" for c in raw_name)[:80]
    if not safe.lower().endswith((".txt", ".lst", ".dic", ".wordlist", ".pass", ".passwords")):
        safe = safe + ".txt"

    content = payload.content or ""
    if not str(content).strip():
        return {"ok": False, "reason": "Empty wordlist"}

    encoded = content.encode("utf-8", errors="ignore")
    if len(encoded) > JOHN_MAX_UPLOAD_BYTES:
        return {
            "ok": False,
            "reason": f"Wordlist too large (max {JOHN_MAX_UPLOAD_BYTES // (1024*1024)} MB)",
        }

    os.makedirs(JOHN_WORDLIST_DIR, exist_ok=True)
    path = os.path.join(JOHN_WORDLIST_DIR, safe)

    try:
        with open(path, "w", encoding="utf-8", errors="ignore") as f:
            f.write(content)
        run_user = user_rule.get("ssh_user") or "dedsecuser"
        try:
            import pwd
            os.chown(path, pwd.getpwnam(run_user).pw_uid, pwd.getpwnam(run_user).pw_gid)
        except Exception:
            pass
    except Exception as e:
        return {"ok": False, "reason": f"Failed to save wordlist: {e}"}

    return {
        "ok": True,
        "filename": safe,
        "path": path,
        "vpn_ip": ip,
        "bytes": len(encoded),
    }


@app.post("/api/john/cupp")
async def api_john_cupp(payload: CuppRequest, request: Request):
    """
    Run CUPP (-i) with profile fields from the app.
    Saves generated wordlist into /opt/john-menu/wordlists/ as cupp_<name>.txt
    Requires a one-time John token.
    """
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    if not await validate_and_consume_john_token(payload.token, expected_ip=ip):
        return {
            "ok": False,
            "reason": "invalid, expired, or missing john token",
            "vpn_ip": ip,
        }

    first = (payload.first_name or "profile").strip() or "profile"
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in first.lower())[:40] or "profile"
    out_name = f"cupp_{safe}.txt"

    yn = lambda b: "y" if b else "n"
    kw_raw = (payload.keywords or "").strip()
    kw = "y" if kw_raw else "n"
    lines = [
        payload.first_name or "",
        payload.surname or "",
        payload.nickname or "",
        payload.birthdate or "",
        payload.partner_name or "",
        payload.partner_nickname or "",
        payload.partner_birthdate or "",
        payload.child_name or "",
        payload.child_nickname or "",
        payload.child_birthdate or "",
        payload.pet_name or "",
        payload.company or "",
        kw,
    ]
    if kw == "y":
        lines.append(kw_raw.replace(",", " "))
    lines += [
        yn(payload.special_chars),
        yn(payload.random_numbers),
        yn(payload.leet),
        "n",  # Hyperspeed Print = no
    ]
    stdin_data = "\n".join(lines) + "\n"

    cupp_dir = "/opt/secure-scripts/cupp"
    cupp_py = os.path.join(cupp_dir, "cupp.py")
    if not os.path.isfile(cupp_py):
        return {"ok": False, "reason": "cupp.py not found at /opt/secure-scripts/cupp"}

    try:
        proc = subprocess.run(
            ["python3", cupp_py, "-i", "-q"],
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=120,
            cwd=cupp_dir,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "reason": "cupp timed out"}
    except Exception as e:
        return {"ok": False, "reason": str(e)}

    # CUPP names file after first name, e.g. bob.txt
    generated = os.path.join(cupp_dir, f"{first}.txt")
    if not os.path.isfile(generated):
        candidates = [
            os.path.join(cupp_dir, f)
            for f in os.listdir(cupp_dir)
            if f.endswith(".txt") and os.path.isfile(os.path.join(cupp_dir, f))
        ]
        if not candidates:
            return {
                "ok": False,
                "reason": "cupp finished but no .txt found",
                "stdout": (proc.stdout or "")[-500],
                "stderr": (proc.stderr or "")[-500],
            }
        generated = max(candidates, key=os.path.getmtime)

    dest = os.path.join(JOHN_WORDLIST_DIR, out_name)
    try:
        import shutil

        os.makedirs(JOHN_WORDLIST_DIR, exist_ok=True)
        shutil.copy2(generated, dest)
        run_user = user_rule.get("ssh_user") or "dedsecuser"
        try:
            import pwd

            os.chown(dest, pwd.getpwnam(run_user).pw_uid, pwd.getpwnam(run_user).pw_gid)
        except Exception:
            pass
    except Exception as e:
        return {"ok": False, "reason": f"copy failed: {e}"}

    word_count = 0
    try:
        with open(dest, "r", encoding="utf-8", errors="ignore") as f:
            word_count = sum(1 for _ in f)
    except Exception:
        pass

    return {
        "ok": True,
        "filename": out_name,
        "vpn_ip": ip,
        "word_count": word_count,
        "hint": (proc.stdout or "")[-300],
    }


# =========================================================
# after Nikto / John routes is fine
# =========================================================
SHODAN_RUNNER = "/opt/secure-scripts/dedsec-labNEW/scripts/ip_tools/shodan_runner.py"
SHODAN_BASE = "/opt/shodan-lab"
SHODAN_TOKEN_TTL_SECONDS = 90
SHODAN_MAX_QUERY_LEN = 500

_shodan_tokens = {}
_shodan_tokens_lock = asyncio.Lock()
_shodan_jobs = {}
_shodan_jobs_lock = asyncio.Lock()


async def issue_shodan_token(ip: str, display_name: str, role: str) -> str:
    async with _shodan_tokens_lock:
        now = time.time()
        expired = [
            t for t, m in _shodan_tokens.items()
            if m.get("used") or m.get("expires", 0) < now
        ]
        for t in expired:
            _shodan_tokens.pop(t, None)
        token = secrets.token_urlsafe(32)
        _shodan_tokens[token] = {
            "ip": ip,
            "user": display_name,
            "role": role,
            "expires": now + SHODAN_TOKEN_TTL_SECONDS,
            "used": False,
        }
        return token


async def validate_and_consume_shodan_token(token: str, expected_ip: str) -> bool:
    if not token or not isinstance(token, str) or len(token) < 16:
        return False
    async with _shodan_tokens_lock:
        now = time.time()
        meta = _shodan_tokens.get(token)
        if not meta or meta.get("used") or meta.get("expires", 0) < now:
            _shodan_tokens.pop(token, None)
            return False
        if meta.get("ip") != expected_ip:
            return False
        meta["used"] = True
        return True


def _shodan_run(args: list, timeout: int = 90) -> dict:
    if not os.path.isfile(SHODAN_RUNNER):
        return {"ok": False, "reason": "shodan_runner.py missing"}
    try:
        proc = subprocess.run(
            ["/opt/secure-scripts/dedsec-labNEW/venv/bin/python", SHODAN_RUNNER, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=SHODAN_BASE if os.path.isdir(SHODAN_BASE) else "/tmp",
            env={**os.environ},
        )
        out = (proc.stdout or "").strip()
        if not out:
            return {
                "ok": False,
                "reason": (proc.stderr or "empty output")[:500],
                "exit_code": proc.returncode,
            }
        try:
            data = json.loads(out.splitlines()[-1] if out else "{}")
            if isinstance(data, dict):
                return data
            return {"ok": False, "reason": "invalid json from runner"}
        except Exception:
            return {"ok": False, "reason": out[:500]}
    except subprocess.TimeoutExpired:
        return {"ok": False, "reason": "shodan timed out"}
    except Exception as e:
        return {"ok": False, "reason": str(e)}


class ShodanQueryRequest(BaseModel):
    token: str
    query: str = ""
    page: int = 1
    limit: int = 25


class ShodanHostRequest(BaseModel):
    token: str
    ip: str


class ShodanDnsRequest(BaseModel):
    token: str
    domain: str = ""
    hosts: str = ""
    ips: str = ""


@app.post("/api/shodan/token")
async def api_shodan_token(request: Request):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    token = await issue_shodan_token(
        ip,
        user_rule.get("display_name", "unknown"),
        user_rule.get("role", "standard").lower(),
    )
    return {
        "ok": True,
        "token": token,
        "expires_in": SHODAN_TOKEN_TTL_SECONDS,
        "vpn_ip": ip,
    }


@app.get("/api/shodan/status")
async def api_shodan_status(request: Request):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    runner_ok = os.path.isfile(SHODAN_RUNNER)
    info = _shodan_run(["info"], timeout=30) if runner_ok else {"ok": False, "reason": "runner missing"}
    async with _shodan_jobs_lock:
        job = _shodan_jobs.get(ip)
    out = {
        "ok": True if info.get("ok") else False,
        "vpn_ip": ip,
        "runner": "OK" if runner_ok else "MISSING",
        "job": job,
    }
    if info.get("ok"):
        out.update({
            "ok": True,
            "plan": info.get("plan"),
            "query_credits": info.get("query_credits"),
            "scan_credits": info.get("scan_credits"),
        })
    else:
        out["reason"] = info.get("reason", "shodan not configured")
        # still 200-style payload for UI
        out["ok"] = False
    return out


@app.post("/api/shodan/count")
async def api_shodan_count(payload: ShodanQueryRequest, request: Request):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    if not await validate_and_consume_shodan_token(payload.token, expected_ip=ip):
        return {"ok": False, "reason": "invalid or expired shodan token", "vpn_ip": ip}
    q = (payload.query or "").strip()
    if not q or len(q) > SHODAN_MAX_QUERY_LEN:
        return {"ok": False, "reason": "invalid query"}
    result = _shodan_run(["count", q], timeout=60)
    async with _shodan_jobs_lock:
        _shodan_jobs[ip] = {
            "action": "count",
            "query": q,
            "finished": time.time(),
            "user": user_rule.get("display_name", "unknown"),
        }
    return result


@app.post("/api/shodan/search")
async def api_shodan_search(payload: ShodanQueryRequest, request: Request):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    if not await validate_and_consume_shodan_token(payload.token, expected_ip=ip):
        return {"ok": False, "reason": "invalid or expired shodan token", "vpn_ip": ip}
    q = (payload.query or "").strip()
    if not q or len(q) > SHODAN_MAX_QUERY_LEN:
        return {"ok": False, "reason": "invalid query"}
    page = max(1, min(int(payload.page or 1), 20))
    limit = max(1, min(int(payload.limit or 25), 50))
    result = _shodan_run(["search", q, str(page), str(limit)], timeout=120)
    async with _shodan_jobs_lock:
        _shodan_jobs[ip] = {
            "action": "search",
            "query": q,
            "page": page,
            "finished": time.time(),
            "user": user_rule.get("display_name", "unknown"),
            "returned": result.get("returned") if isinstance(result, dict) else None,
        }
    return result


@app.post("/api/shodan/host")
async def api_shodan_host(payload: ShodanHostRequest, request: Request):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    if not await validate_and_consume_shodan_token(payload.token, expected_ip=ip):
        return {"ok": False, "reason": "invalid or expired shodan token", "vpn_ip": ip}
    target = (payload.ip or "").strip()
    if not target or len(target) > 64:
        return {"ok": False, "reason": "invalid ip"}
    result = _shodan_run(["host", target], timeout=60)
    async with _shodan_jobs_lock:
        _shodan_jobs[ip] = {
            "action": "host",
            "ip": target,
            "finished": time.time(),
            "user": user_rule.get("display_name", "unknown"),
        }
    return result


@app.post("/api/shodan/dns")
async def api_shodan_dns(payload: ShodanDnsRequest, request: Request):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    if not await validate_and_consume_shodan_token(payload.token, expected_ip=ip):
        return {"ok": False, "reason": "invalid or expired shodan token", "vpn_ip": ip}
    domain = (payload.domain or "").strip()
    if not domain:
        return {"ok": False, "reason": "missing domain"}
    return _shodan_run(["dns", domain], timeout=60)


@app.post("/api/shodan/resolve")
async def api_shodan_resolve(payload: ShodanDnsRequest, request: Request):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    if not await validate_and_consume_shodan_token(payload.token, expected_ip=ip):
        return {"ok": False, "reason": "invalid or expired shodan token", "vpn_ip": ip}
    hosts = (payload.hosts or payload.domain or "").strip()
    if not hosts:
        return {"ok": False, "reason": "missing hosts"}
    return _shodan_run(["resolve", hosts], timeout=60)


@app.post("/api/shodan/reverse")
async def api_shodan_reverse(payload: ShodanDnsRequest, request: Request):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    if not await validate_and_consume_shodan_token(payload.token, expected_ip=ip):
        return {"ok": False, "reason": "invalid or expired shodan token", "vpn_ip": ip}
    ips = (payload.ips or payload.domain or "").strip()
    if not ips:
        return {"ok": False, "reason": "missing ips"}
    return _shodan_run(["reverse", ips], timeout=60)

# =========================================================
# NETWORK EMULATION ROUTES
# =========================================================
@app.post("/api/net-emulate/start")
async def api_netem_start(payload: NetEmulateRequest, request: Request):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    cfg = _netem_normalize(payload.dict())
    cfg["user"] = user_rule.get("display_name", "unknown")
    cfg["role"] = user_rule.get("role", "standard").lower()
    cfg["started"] = time.time()
    cfg["expires"] = time.time() + NETEM_MAX_DURATION
    cfg["vpn_ip"] = ip
    async with _netem_lock:
        _netem_sessions[ip] = cfg
        ok, msg = await _netem_rebuild_all()
        if not ok:
            _netem_sessions.pop(ip, None)
            return {"ok": False, "reason": msg, "vpn_ip": ip}
    return {
        "ok": True,
        "vpn_ip": ip,
        "iface": NETEM_IFACE,
        "expires_in": NETEM_MAX_DURATION,
        "config": {
            "delay_ms": cfg["delay_ms"],
            "jitter_ms": cfg["jitter_ms"],
            "loss_pct": cfg["loss_pct"],
            "corrupt_pct": cfg["corrupt_pct"],
            "reorder_pct": cfg["reorder_pct"],
            "rate_kb": cfg["rate_kb"],
            "direction": cfg["direction"],
            "preset": cfg["preset"],
        },
    }


@app.post("/api/net-emulate/stop")
async def api_netem_stop(request: Request):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    async with _netem_lock:
        existed = ip in _netem_sessions
        _netem_sessions.pop(ip, None)
        ok, msg = await _netem_rebuild_all()
    return {
        "ok": True,
        "stopped": existed,
        "vpn_ip": ip,
        "detail": msg if ok else f"cleared with warning: {msg}",
    }


@app.get("/api/net-emulate/status")
async def api_netem_status(request: Request):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    async with _netem_lock:
        s = _netem_sessions.get(ip)
        if s and s.get("expires", 0) <= time.time():
            _netem_sessions.pop(ip, None)
            await _netem_rebuild_all()
            s = None
        if not s:
            return {
                "ok": True,
                "active": False,
                "vpn_ip": ip,
                "iface": NETEM_IFACE,
            }
        remaining = max(0, int(s["expires"] - time.time()))
        return {
            "ok": True,
            "active": True,
            "vpn_ip": ip,
            "iface": NETEM_IFACE,
            "expires_in": remaining,
            "config": {
                "delay_ms": s.get("delay_ms", 0),
                "jitter_ms": s.get("jitter_ms", 0),
                "loss_pct": s.get("loss_pct", 0),
                "corrupt_pct": s.get("corrupt_pct", 0),
                "reorder_pct": s.get("reorder_pct", 0),
                "rate_kb": s.get("rate_kb", 0),
                "direction": s.get("direction", "both"),
                "preset": s.get("preset", ""),
            },
        }


# =========================================================
# TERMINAL WEBSOCKET
# =========================================================
@app.websocket("/ws/terminal")
async def terminal_ws(websocket: WebSocket):
    await websocket.accept()
    ip = websocket.client.host
    user_rule, error = validate_vpn_user(ip)
    if error:
        await websocket.send_text(f"Access denied: {error.get('reason')}\n")
        await websocket.close()
        return
    # H4: the hardened client sends the terminal token in the Authorization
    # header ("Authorization: Bearer <token>") and no longer puts it in the URL
    # query string (URLs get logged by proxies). Prefer the header; keep the
    # ?token= query param as a short-lived fallback for old clients.
    # DEPRECATED: remove the query fallback once all clients are on the
    # hardened build.
    token = _bearer_token_from_ws(websocket)
    if not token:
        token = websocket.query_params.get("token")  # DEPRECATED legacy fallback
    if not await validate_and_consume_terminal_token(token, expected_ip=ip):
        await websocket.send_text(
            "Access denied: invalid, expired, or missing terminal token\n"
        )
        await websocket.close()
        return
    role = user_rule.get("role", "standard").lower()
    display_name = user_rule.get("display_name", "unknown")
    ssh_user = user_rule.get("ssh_user", "dedsecuser")
    env = os.environ.copy()
    env["TERM"] = "xterm"
    env["DEDSEC_USER"] = display_name
    env["DEDSEC_SSH_USER"] = ssh_user
    env["DEDSEC_SOURCE_IP"] = ip
    env["DEDSEC_ROLE"] = role
    env["SSH_CONNECTION"] = f"{ip} 55555 YOUR_LAB_VPN_IP 22"
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(BASE_DIR)
        os.execvpe(
            "/usr/bin/python3",
            ["python3", os.path.join(BASE_DIR, "access_wrapper.py")],
            env,
        )

    async def read_terminal():
        try:
            while True:
                ready, _, _ = select.select([fd], [], [], 0.1)
                if fd in ready:
                    data = os.read(fd, 4096).decode(errors="ignore")
                    if data:
                        await websocket.send_text(data)
                await asyncio.sleep(0.01)
        except Exception:
            pass

    reader_task = asyncio.create_task(read_terminal())
    try:
        while True:
            message = await websocket.receive_text()
            os.write(fd, message.encode())
    except WebSocketDisconnect:
        pass
    finally:
        reader_task.cancel()
        try:
            os.close(fd)
        except Exception:
            pass
        try:
            os.kill(pid, signal.SIGTERM)
        except Exception:
            pass

# =========================================================
# IP CHECK (live-ping-checker data, VPN + one-time token)
# =========================================================
IPCHECK_SAVE_DIR = os.path.join(BASE_DIR, "ip_saves")
IPCHECK_MONITOR_DIR = os.path.join(BASE_DIR, "monitor_state")
IPCHECK_TOKEN_TTL = 90
IPCHECK_MAX_IPS = 40
_ipcheck_tokens = {}
_ipcheck_tokens_lock = asyncio.Lock()


def _ipcheck_client_id(vpn_ip: str) -> str:
    return hashlib.sha256(vpn_ip.encode("utf-8")).hexdigest()[:32]


def _ipcheck_db_path(vpn_ip: str) -> str:
    return os.path.join(IPCHECK_SAVE_DIR, _ipcheck_client_id(vpn_ip) + ".json")


def _ipcheck_pid_path(vpn_ip: str) -> str:
    return os.path.join(IPCHECK_MONITOR_DIR, _ipcheck_client_id(vpn_ip) + ".pid")


def _ipcheck_load_db(vpn_ip: str):
    path = _ipcheck_db_path(vpn_ip)
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _ipcheck_monitor_running(vpn_ip: str) -> bool:
    path = _ipcheck_pid_path(vpn_ip)
    if not os.path.isfile(path):
        return False
    try:
        with open(path, "r", encoding="utf-8") as f:
            pid = int((f.read() or "").strip() or "0")
        if pid <= 0:
            return False
        os.kill(pid, 0)
        return True
    except Exception:
        return False


async def issue_ipcheck_token(ip: str, display_name: str, role: str) -> str:
    async with _ipcheck_tokens_lock:
        now = time.time()
        for t, m in list(_ipcheck_tokens.items()):
            if m.get("used") or m.get("expires", 0) < now:
                _ipcheck_tokens.pop(t, None)
        token = secrets.token_urlsafe(32)
        _ipcheck_tokens[token] = {
            "ip": ip,
            "user": display_name,
            "role": role,
            "expires": now + IPCHECK_TOKEN_TTL,
            "used": False,
        }
        return token


async def validate_and_consume_ipcheck_token(token: str, expected_ip: str) -> bool:
    if not token or not isinstance(token, str) or len(token) < 16:
        return False
    async with _ipcheck_tokens_lock:
        now = time.time()
        meta = _ipcheck_tokens.get(token)
        if not meta:
            return False
        if meta.get("used") or meta.get("expires", 0) < now:
            _ipcheck_tokens.pop(token, None)
            return False
        if meta.get("ip") != expected_ip:
            return False
        meta["used"] = True
        return True


@app.post("/api/ipcheck/token")
async def api_ipcheck_token(request: Request):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    token = await issue_ipcheck_token(
        ip,
        user_rule.get("display_name", "unknown"),
        user_rule.get("role", "standard"),
    )
    return {"ok": True, "token": token, "expires_in": IPCHECK_TOKEN_TTL, "vpn_ip": ip}


@app.get("/api/ipcheck/status")
async def api_ipcheck_status(request: Request):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    db = _ipcheck_load_db(ip)
    online = sum(1 for x in db if str(x.get("last_status", "")).lower() in ("up", "online", "alive"))
    offline = sum(1 for x in db if str(x.get("last_status", "")).lower() in ("down", "offline", "no_icmp"))
    return {
        "ok": True,
        "vpn_ip": ip,
        "user": user_rule.get("display_name", "unknown"),
        "saved": len(db),
        "online": online,
        "offline": offline,
        "monitor_running": _ipcheck_monitor_running(ip),
        "live_running": _ipcheck_live_running(ip),
        "live_targets": [
            {"ip": x.get("ip"), "mode": x.get("live_mode"), "label": x.get("label")}
            for x in db if x.get("live_enabled")
        ],
        "max_ips": IPCHECK_MAX_IPS,
    }


@app.get("/api/ipcheck/ips")
async def api_ipcheck_ips(request: Request):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    db = _ipcheck_load_db(ip)
    return {"ok": True, "vpn_ip": ip, "count": len(db), "ips": db}



def _ipcheck_save_db(vpn_ip: str, database) -> bool:
    os.makedirs(IPCHECK_SAVE_DIR, exist_ok=True)
    path = _ipcheck_db_path(vpn_ip)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(database, f, indent=2)
        try:
            os.chmod(path, 0o660)
        except Exception:
            pass
        return True
    except Exception:
        return False


def _ipcheck_valid_ipv4(ip: str) -> bool:
    if not ip or not isinstance(ip, str):
        return False
    parts = ip.strip().split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except Exception:
        return False


class IpCheckAddBody(BaseModel):
    token: str
    ip: str
    label: str = ""
    tcp_ports: str = ""


class IpCheckRemoveBody(BaseModel):
    token: str
    ip: str


@app.post("/api/ipcheck/ips")
async def api_ipcheck_add_ip(request: Request, body: IpCheckAddBody):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    if not await validate_and_consume_ipcheck_token(body.token, ip):
        return {"ok": False, "reason": "invalid or expired token"}
    target = (body.ip or "").strip()
    if not _ipcheck_valid_ipv4(target):
        return {"ok": False, "reason": "invalid IPv4"}
    if target.startswith("10.8.0."):
        return {"ok": False, "reason": "VPN pool addresses not allowed"}
    db = _ipcheck_load_db(ip)
    if any(str(x.get("ip")) == target for x in db):
        return {"ok": False, "reason": "IP already saved", "count": len(db)}
    if len(db) >= IPCHECK_MAX_IPS:
        return {"ok": False, "reason": f"max {IPCHECK_MAX_IPS} IPs"}
    from datetime import datetime, timezone
    entry = {
        "ip": target,
        "label": (body.label or "").strip()[:80],
        "tcp_ports": (body.tcp_ports or "").strip()[:80],
        "added": datetime.now(timezone.utc).isoformat(),
        "last_status": "unknown",
        "last_check": "",
        "last_info": {},
        "last_ports": {},
        "fail_streak": 0,
        "history": [],
        "last_alert_ts": 0,
    }
    db.append(entry)
    if not _ipcheck_save_db(ip, db):
        return {"ok": False, "reason": "failed to save database"}
    return {"ok": True, "vpn_ip": ip, "count": len(db), "added": entry}


@app.delete("/api/ipcheck/ips")
async def api_ipcheck_remove_ip(request: Request, body: IpCheckRemoveBody):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    if not await validate_and_consume_ipcheck_token(body.token, ip):
        return {"ok": False, "reason": "invalid or expired token"}
    target = (body.ip or "").strip()
    db = _ipcheck_load_db(ip)
    new_db = [x for x in db if str(x.get("ip")) != target]
    if len(new_db) == len(db):
        return {"ok": False, "reason": "IP not found", "count": len(db)}
    if not _ipcheck_save_db(ip, new_db):
        return {"ok": False, "reason": "failed to save database"}
    return {"ok": True, "vpn_ip": ip, "count": len(new_db), "removed": target}



# =========================================================
# IP CHECK - remaining CLI features
# =========================================================
IPCHECK_SCRIPT = os.path.join(BASE_DIR, "scripts/misc_tools/live-ping-checker.py")
IPCHECK_WEBHOOK_DIR = os.path.join(BASE_DIR, "discord_webhooks")
IPCHECK_PING_TIMEOUT = 6


def _ipcheck_settings_path(vpn_ip: str) -> str:
    return os.path.join(IPCHECK_MONITOR_DIR, _ipcheck_client_id(vpn_ip) + ".json")


def _ipcheck_webhook_path(vpn_ip: str) -> str:
    return os.path.join(IPCHECK_WEBHOOK_DIR, _ipcheck_client_id(vpn_ip) + ".json")


def _ipcheck_load_settings(vpn_ip: str) -> dict:
    path = _ipcheck_settings_path(vpn_ip)
    defaults = {
        "interval_hours": 3,
        "change_only": True,
        "multi_fail": 2,
        "alert_cooldown_sec": 300,
    }
    if not os.path.isfile(path):
        return defaults
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return defaults
        defaults.update(data)
        return defaults
    except Exception:
        return defaults


def _ipcheck_save_settings(vpn_ip: str, settings: dict) -> bool:
    os.makedirs(IPCHECK_MONITOR_DIR, exist_ok=True)
    path = _ipcheck_settings_path(vpn_ip)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2)
        return True
    except Exception:
        return False


def _ipcheck_load_webhook(vpn_ip: str) -> str:
    path = _ipcheck_webhook_path(vpn_ip)
    if not os.path.isfile(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return str(data.get("url") or data.get("webhook") or "")
        if isinstance(data, str):
            return data
    except Exception:
        pass
    return ""


def _ipcheck_save_webhook(vpn_ip: str, url: str) -> bool:
    os.makedirs(IPCHECK_WEBHOOK_DIR, exist_ok=True)
    path = _ipcheck_webhook_path(vpn_ip)
    try:
        u = (url or "").strip()
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"url": u, "webhook": u}, f, indent=2)
        return True
    except Exception:
        return False


def _ipcheck_ping(host: str) -> dict:
    try:
        r = subprocess.run(
            ["ping", "-c", "1", "-W", str(IPCHECK_PING_TIMEOUT), host],
            capture_output=True,
            text=True,
            timeout=IPCHECK_PING_TIMEOUT + 2,
        )
        ok = r.returncode == 0
        out = (r.stdout or "") + (r.stderr or "")
        latency = None
        import re as _re
        m = _re.search(r"time[=<]([\d.]+)\s*ms", out)
        if m:
            latency = float(m.group(1))
        return {
            "ok": ok,
            "status": "up" if ok else "no_icmp",
            "latency_ms": latency,
            "raw": out[-500:],
        }
    except Exception as e:
        return {"ok": False, "status": "error", "latency_ms": None, "raw": str(e)}


def _ipcheck_geo(host: str) -> dict:
    try:
        url = f"http://ip-api.com/json/{host}?fields=status,message,country,countryCode,regionName,city,isp,org,as,query"
        req = urllib.request.Request(url, headers={"User-Agent": "DedSec-IPCheck/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        if data.get("status") != "success":
            return {"error": data.get("message", "lookup failed")}
        return {
            "ip": data.get("query", host),
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "asn": data.get("as"),
        }
    except Exception as e:
        return {"error": str(e)}


def _ipcheck_rdns(host: str) -> str:
    try:
        return socket.gethostbyaddr(host)[0]
    except Exception:
        return ""


class IpCheckBulkBody(BaseModel):
    token: str
    ips: list = []
    text: str = ""


class IpCheckEditBody(BaseModel):
    token: str
    ip: str
    label: str = ""
    tcp_ports: str = ""


class IpCheckTargetBody(BaseModel):
    token: str
    ip: str = ""


class IpCheckWebhookBody(BaseModel):
    token: str
    url: str = ""


class IpCheckSettingsBody(BaseModel):
    token: str
    interval_hours: int = 3
    change_only: bool = True
    multi_fail: int = 2
    alert_cooldown_sec: int = 300


@app.post("/api/ipcheck/ips/bulk")
async def api_ipcheck_bulk(request: Request, body: IpCheckBulkBody):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    if not await validate_and_consume_ipcheck_token(body.token, ip):
        return {"ok": False, "reason": "invalid or expired token"}
    raw = list(body.ips or [])
    if body.text:
        for line in body.text.replace(",", "\n").splitlines():
            line = line.strip()
            if line:
                raw.append(line)
    db = _ipcheck_load_db(ip)
    existing = {str(x.get("ip")) for x in db}
    added = []
    skipped = []
    from datetime import datetime, timezone
    for t in raw:
        t = str(t).strip()
        if not _ipcheck_valid_ipv4(t) or t.startswith("10.8.0."):
            skipped.append({"ip": t, "reason": "invalid"})
            continue
        if t in existing:
            skipped.append({"ip": t, "reason": "duplicate"})
            continue
        if len(db) >= IPCHECK_MAX_IPS:
            skipped.append({"ip": t, "reason": "max"})
            break
        entry = {
            "ip": t,
            "label": "",
            "tcp_ports": "",
            "added": datetime.now(timezone.utc).isoformat(),
            "last_status": "unknown",
            "last_check": "",
            "last_info": {},
            "last_ports": {},
            "fail_streak": 0,
            "history": [],
            "last_alert_ts": 0,
        }
        db.append(entry)
        existing.add(t)
        added.append(t)
    if added and not _ipcheck_save_db(ip, db):
        return {"ok": False, "reason": "failed to save"}
    return {"ok": True, "added": added, "skipped": skipped, "count": len(db)}


@app.patch("/api/ipcheck/ips")
async def api_ipcheck_edit(request: Request, body: IpCheckEditBody):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    if not await validate_and_consume_ipcheck_token(body.token, ip):
        return {"ok": False, "reason": "invalid or expired token"}
    target = (body.ip or "").strip()
    db = _ipcheck_load_db(ip)
    found = None
    for x in db:
        if str(x.get("ip")) == target:
            x["label"] = (body.label or "").strip()[:80]
            x["tcp_ports"] = (body.tcp_ports or "").strip()[:80]
            found = x
            break
    if not found:
        return {"ok": False, "reason": "IP not found"}
    if not _ipcheck_save_db(ip, db):
        return {"ok": False, "reason": "failed to save"}
    return {"ok": True, "entry": found}


@app.post("/api/ipcheck/check")
async def api_ipcheck_check(request: Request, body: IpCheckTargetBody):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    if not await validate_and_consume_ipcheck_token(body.token, ip):
        return {"ok": False, "reason": "invalid or expired token"}
    target = (body.ip or "").strip()
    db = _ipcheck_load_db(ip)
    if target and not any(str(x.get("ip")) == target for x in db):
        return {"ok": False, "reason": "IP not in saved list"}
    targets = [target] if target else [str(x.get("ip")) for x in db if x.get("ip")]
    results = []
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    for host in targets:
        ping = _ipcheck_ping(host)
        geo = _ipcheck_geo(host)
        for x in db:
            if str(x.get("ip")) == host:
                x["last_status"] = ping.get("status", "unknown")
                x["last_check"] = now
                if isinstance(geo, dict) and not geo.get("error"):
                    x["last_info"] = geo
                if ping.get("ok"):
                    x["fail_streak"] = 0
                else:
                    x["fail_streak"] = int(x.get("fail_streak") or 0) + 1
                hist = list(x.get("history") or [])
                hist.append({"ts": now, "status": x["last_status"]})
                x["history"] = hist[-20:]
                break
        results.append({"ip": host, "ping": ping, "info": geo})
    _ipcheck_save_db(ip, db)
    return {"ok": True, "results": results, "count": len(db)}


@app.post("/api/ipcheck/lookup")
async def api_ipcheck_lookup(request: Request, body: IpCheckTargetBody):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    if not await validate_and_consume_ipcheck_token(body.token, ip):
        return {"ok": False, "reason": "invalid or expired token"}
    target = (body.ip or "").strip()
    if not _ipcheck_valid_ipv4(target):
        return {"ok": False, "reason": "invalid IPv4"}
    geo = _ipcheck_geo(target)
    rdns = _ipcheck_rdns(target)
    return {"ok": True, "ip": target, "rdns": rdns, "info": geo}


@app.post("/api/ipcheck/traceroute")
async def api_ipcheck_traceroute(request: Request, body: IpCheckTargetBody):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    if not await validate_and_consume_ipcheck_token(body.token, ip):
        return {"ok": False, "reason": "invalid or expired token"}
    target = (body.ip or "").strip()
    if not _ipcheck_valid_ipv4(target):
        return {"ok": False, "reason": "invalid IPv4"}
    try:
        r = subprocess.run(
            ["traceroute", "-n", "-w", "2", "-m", "20", target],
            capture_output=True,
            text=True,
            timeout=60,
        )
        out = (r.stdout or "") + (r.stderr or "")
        return {"ok": True, "ip": target, "output": out[-8000:]}
    except FileNotFoundError:
        try:
            r = subprocess.run(
                ["tracepath", "-n", target],
                capture_output=True,
                text=True,
                timeout=60,
            )
            out = (r.stdout or "") + (r.stderr or "")
            return {"ok": True, "ip": target, "output": out[-8000:]}
        except Exception as e:
            return {"ok": False, "reason": str(e)}
    except Exception as e:
        return {"ok": False, "reason": str(e)}


@app.get("/api/ipcheck/webhook")
async def api_ipcheck_webhook_get(request: Request):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    url = _ipcheck_load_webhook(ip)
    masked = ""
    if url:
        masked = url[:40] + "..." if len(url) > 40 else url
    return {"ok": True, "configured": bool(url), "url_preview": masked}


@app.post("/api/ipcheck/webhook")
async def api_ipcheck_webhook_set(request: Request, body: IpCheckWebhookBody):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    if not await validate_and_consume_ipcheck_token(body.token, ip):
        return {"ok": False, "reason": "invalid or expired token"}
    url = (body.url or "").strip()
    if url and not (url.startswith("https://") or url.startswith("http://")):
        return {"ok": False, "reason": "webhook must be http(s) URL"}
    if not _ipcheck_save_webhook(ip, url):
        return {"ok": False, "reason": "failed to save"}
    return {"ok": True, "configured": bool(url)}


@app.get("/api/ipcheck/settings")
async def api_ipcheck_settings_get(request: Request):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    return {"ok": True, "settings": _ipcheck_load_settings(ip)}


@app.post("/api/ipcheck/settings")
async def api_ipcheck_settings_set(request: Request, body: IpCheckSettingsBody):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    if not await validate_and_consume_ipcheck_token(body.token, ip):
        return {"ok": False, "reason": "invalid or expired token"}
    interval = max(1, min(24, int(body.interval_hours or 3)))
    multi = max(1, min(10, int(body.multi_fail or 2)))
    cool = max(60, min(86400, int(body.alert_cooldown_sec or 300)))
    settings = {
        "interval_hours": interval,
        "change_only": bool(body.change_only),
        "multi_fail": multi,
        "alert_cooldown_sec": cool,
    }
    if not _ipcheck_save_settings(ip, settings):
        return {"ok": False, "reason": "failed to save"}
    return {"ok": True, "settings": settings}


@app.get("/api/ipcheck/monitor/status")
async def api_ipcheck_monitor_status(request: Request):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    running = _ipcheck_monitor_running(ip)
    pid = None
    path = _ipcheck_pid_path(ip)
    if os.path.isfile(path):
        try:
            pid = int(open(path).read().strip() or "0")
        except Exception:
            pid = None
    return {
        "ok": True,
        "running": running,
        "pid": pid,
        "settings": _ipcheck_load_settings(ip),
        "webhook_configured": bool(_ipcheck_load_webhook(ip)),
        "saved": len(_ipcheck_load_db(ip)),
    }


@app.post("/api/ipcheck/monitor/start")
async def api_ipcheck_monitor_start(request: Request, body: IpCheckTargetBody):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    if not await validate_and_consume_ipcheck_token(body.token, ip):
        return {"ok": False, "reason": "invalid or expired token"}
    if _ipcheck_monitor_running(ip):
        return {"ok": True, "already_running": True, "reason": "monitor already running"}
    if not os.path.isfile(IPCHECK_SCRIPT):
        return {"ok": False, "reason": "live-ping-checker.py missing"}
    env = os.environ.copy()
    env["DEDSEC_SOURCE_IP"] = ip
    env["DEDSEC_USER"] = str(user_rule.get("display_name", "unknown"))
    env["DEDSEC_ROLE"] = str(user_rule.get("role", "standard"))
    env["DEDSEC_SSH_USER"] = str(user_rule.get("ssh_user", "dedsecuser"))
    try:
        proc = subprocess.Popen(
            [sys.executable, IPCHECK_SCRIPT, "--background"],
            env=env,
            cwd=BASE_DIR,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        time.sleep(0.8)
        running = _ipcheck_monitor_running(ip)
        return {
            "ok": True,
            "started": True,
            "spawn_pid": proc.pid,
            "monitor_running": running,
        }
    except Exception as e:
        return {"ok": False, "reason": str(e)}


@app.post("/api/ipcheck/monitor/stop")
async def api_ipcheck_monitor_stop(request: Request, body: IpCheckTargetBody):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    if not await validate_and_consume_ipcheck_token(body.token, ip):
        return {"ok": False, "reason": "invalid or expired token"}
    path = _ipcheck_pid_path(ip)
    if not os.path.isfile(path):
        return {"ok": True, "stopped": False, "reason": "no pid file"}
    try:
        pid = int(open(path).read().strip() or "0")
        if pid > 0:
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.3)
            try:
                os.kill(pid, signal.SIGKILL)
            except Exception:
                pass
        try:
            os.remove(path)
        except Exception:
            pass
        return {"ok": True, "stopped": True, "pid": pid}
    except Exception as e:
        return {"ok": False, "reason": str(e)}




def _ipcheck_live_pid_path(vpn_ip: str) -> str:
    return os.path.join(IPCHECK_MONITOR_DIR, _ipcheck_client_id(vpn_ip) + ".live.pid")


def _ipcheck_live_running(vpn_ip: str) -> bool:
    path = _ipcheck_live_pid_path(vpn_ip)
    try:
        if not os.path.isfile(path):
            return False
        pid = int(open(path).read().strip() or "0")
        if pid <= 0:
            return False
        os.kill(pid, 0)
        return True
    except Exception:
        return False


@app.post("/api/ipcheck/live/start")
async def api_ipcheck_live_start(request: Request, body: IpCheckTargetBody):
    """Mark one IP live_enabled (flip mode) and start --live-background worker."""
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    if not await validate_and_consume_ipcheck_token(body.token, ip):
        return {"ok": False, "reason": "invalid or expired token"}
    target = (body.ip or "").strip()
    if not target or not _ipcheck_valid_ipv4(target):
        return {"ok": False, "reason": "invalid IPv4"}
    if not os.path.isfile(IPCHECK_SCRIPT):
        return {"ok": False, "reason": "live-ping-checker.py missing"}

    db = _ipcheck_load_db(ip)
    found = None
    for e in db:
        if e.get("ip") == target:
            found = e
            break
    if not found:
        return {"ok": False, "reason": "IP not in your list - add it first"}

    for e in db:
        if e.get("ip") == target:
            e["live_enabled"] = True
            e["live_mode"] = "flip"
        else:
            e["live_enabled"] = False
    if not _ipcheck_save_db(ip, db):
        return {"ok": False, "reason": "failed to save DB"}

    if _ipcheck_live_running(ip):
        return {
            "ok": True,
            "already_running": True,
            "ip": target,
            "mode": "flip",
            "message": f"LIVE already running - now watching {target} (flip once).",
        }

    env = os.environ.copy()
    env["DEDSEC_SOURCE_IP"] = ip
    env["DEDSEC_USER"] = str(user_rule.get("display_name", "unknown"))
    env["DEDSEC_ROLE"] = str(user_rule.get("role", "standard"))
    env["DEDSEC_SSH_USER"] = str(user_rule.get("ssh_user", "dedsecuser"))
    try:
        proc = subprocess.Popen(
            [sys.executable, IPCHECK_SCRIPT, "--live-background"],
            env=env,
            cwd=BASE_DIR,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        time.sleep(0.6)
        running = _ipcheck_live_running(ip)
        return {
            "ok": True,
            "ip": target,
            "mode": "flip",
            "spawn_pid": proc.pid,
            "live_running": running,
            "message": (
                f"LIVE track started for {target}. "
                "Discord when status flips once, then auto-off."
            ),
        }
    except Exception as e:
        return {"ok": False, "reason": str(e)}


@app.post("/api/ipcheck/live/stop")
async def api_ipcheck_live_stop(request: Request, body: IpCheckTargetBody):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    if not await validate_and_consume_ipcheck_token(body.token, ip):
        return {"ok": False, "reason": "invalid or expired token"}

    db = _ipcheck_load_db(ip)
    for e in db:
        e["live_enabled"] = False
    _ipcheck_save_db(ip, db)

    path = _ipcheck_live_pid_path(ip)
    stopped = False
    pid = None
    try:
        if os.path.isfile(path):
            pid = int(open(path).read().strip() or "0")
            if pid > 0:
                try:
                    os.kill(pid, signal.SIGTERM)
                    time.sleep(0.3)
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except Exception:
                        pass
                except ProcessLookupError:
                    pass
            try:
                os.remove(path)
            except Exception:
                pass
            stopped = True
    except Exception as e:
        return {"ok": False, "reason": str(e)}

    return {"ok": True, "stopped": stopped, "pid": pid}




# =========================================================
# IP CHECK nmap
# =========================================================
import sys as _sys
_NMAP_HELPER_DIR = os.path.join(BASE_DIR, "scripts/misc_tools")
if _NMAP_HELPER_DIR not in _sys.path:
    _sys.path.insert(0, _NMAP_HELPER_DIR)
try:
    import ipcheck_nmap as _ipcheck_nmap
except Exception:
    _ipcheck_nmap = None


class IpCheckNmapBody(BaseModel):
    token: str
    ip: str = ""
    mode: str = "top1000"


@app.get("/api/ipcheck/nmap/status")
async def api_ipcheck_nmap_status(request: Request):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    if _ipcheck_nmap is None:
        return {"ok": False, "reason": "nmap helper missing"}
    return _ipcheck_nmap.status(ip)


@app.post("/api/ipcheck/nmap/start")
async def api_ipcheck_nmap_start(request: Request, body: IpCheckNmapBody):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    if not await validate_and_consume_ipcheck_token(body.token, ip):
        return {"ok": False, "reason": "invalid or expired token"}
    if _ipcheck_nmap is None:
        return {"ok": False, "reason": "nmap helper missing"}
    return _ipcheck_nmap.start(ip, body.ip, body.mode)


@app.post("/api/ipcheck/nmap/stop")
async def api_ipcheck_nmap_stop(request: Request, body: IpCheckTargetBody):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    if not await validate_and_consume_ipcheck_token(body.token, ip):
        return {"ok": False, "reason": "invalid or expired token"}
    if _ipcheck_nmap is None:
        return {"ok": False, "reason": "nmap helper missing"}
    return _ipcheck_nmap.stop(ip)


# =========================================================
# IP CHECK Discord - exact live-ping-checker style
# =========================================================
DISCORD_GREEN = 0x00FF00
DISCORD_RED = 0xFF0000
DISCORD_CYAN = 0x00FFFF


def _ipcheck_send_discord_cli(webhook: str, title: str, message: str, colour: int, display_user: str):
    if not webhook:
        return {"ok": False, "reason": "webhook not configured"}
    payload = {
        "username": "DedSecEye",
        "embeds": [{
            "title": title,
            "description": message,
            "color": int(colour),
            "footer": {"text": f"DEDSCAN • {display_user}"},
            "timestamp": datetime.now(timezone.utc).isoformat() if "timezone" in dir() else datetime.utcnow().isoformat() + "Z",
        }],
    }
    # timezone-safe
    try:
        from datetime import timezone as _tz
        payload["embeds"][0]["timestamp"] = datetime.now(_tz.utc).isoformat()
    except Exception:
        payload["embeds"][0]["timestamp"] = datetime.utcnow().isoformat() + "Z"
    try:
        req = urllib.request.Request(
            webhook,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "Live-Ping-Checker/2.0"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            code = getattr(resp, "status", 200)
        return {"ok": True, "status_code": code}
    except Exception as e:
        return {"ok": False, "reason": str(e)}


def _ipcheck_build_surveillance_message(ip: str, status: str, info: dict, label: str, owner: str, ports=None):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    details = {
        "isp": (info or {}).get("isp", "Unknown"),
        "org": (info or {}).get("org", "Unknown"),
        "asn": (info or {}).get("asn", "Unknown"),
        "country": (info or {}).get("country", "Unknown"),
        "region": (info or {}).get("region", "Unknown"),
        "city": (info or {}).get("city", "Unknown"),
    }
    if status == "online":
        status_text = "🟢 ONLINE"
        colour = DISCORD_GREEN
        title = "Surveillance - ONLINE"
    else:
        status_text = "🔴 OFFLINE"
        colour = DISCORD_RED
        title = "Surveillance - OFFLINE"
    label_line = f"**Label:** `{label}`\n" if label else ""
    ports_line = ""
    if ports:
        ports_line = "**Ports:** " + ", ".join(
            f"`{p} {'open' if ok else 'closed'}`" for p, ok in sorted(ports.items())
        ) + "\n"
    message = (
        f"{label_line}"
        f"**Target:** `{ip}`\n"
        f"**Status:** {status_text}\n"
        f"**Time:** `{now}`\n"
        f"**Owner:** `{owner}`\n\n"
        f"{ports_line}"
        f"**ISP:** `{details['isp']}`\n"
        f"**Organization:** `{details['org']}`\n"
        f"**ASN:** `{details['asn']}`\n"
        f"**Country:** `{details['country']}`\n"
        f"**Region:** `{details['region']}`\n"
        f"**City:** `{details['city']}`"
    )
    return title, message, colour


@app.post("/api/ipcheck/webhook/test")
async def api_ipcheck_webhook_test(request: Request, body: IpCheckTargetBody):
    ip = get_client_ip(request)
    user_rule, error = validate_vpn_user(ip)
    if error:
        return error
    if not await validate_and_consume_ipcheck_token(body.token, ip):
        return {"ok": False, "reason": "invalid or expired token"}
    name = str(user_rule.get("display_name") or "user")
    webhook = _ipcheck_load_webhook(ip)
    return _ipcheck_send_discord_cli(
        webhook,
        "Webhook Test",
        f"**Owner:** `{name}`\n**VPN:** `{ip}`\n\nDiscord webhook is connected.",
        DISCORD_CYAN,
        name,
    )


# Re-bind CHECK so Discord matches CLI surveillance cards
_old_check = None
_kept = []
for r in app.router.routes:
    methods = getattr(r, "methods", None) or set()
    path = getattr(r, "path", None)
    if path == "/api/ipcheck/check" and "POST" in methods:
        if _old_check is None:
            _old_check = r.endpoint
        continue
    if path == "/api/ipcheck/webhook/test" and "POST" in methods:
        continue
    _kept.append(r)
app.router.routes = _kept

if _old_check is not None:
    async def api_ipcheck_check_surveillance(request: Request, body: IpCheckTargetBody):
        result = await _old_check(request, body)
        try:
            if not isinstance(result, dict) or not result.get("ok"):
                return result
            ip = get_client_ip(request)
            user_rule, _ = validate_vpn_user(ip)
            owner = str((user_rule or {}).get("display_name") or "user")
            webhook = _ipcheck_load_webhook(ip)
            if not webhook:
                result["discord"] = {"ok": False, "reason": "webhook not configured"}
                return result
            rows = result.get("results") or []
            # single-target shape fallback
            if not rows and result.get("status"):
                rows = [result]
            sent = []
            for row in rows:
                target = str(row.get("ip") or body.ip or row.get("target") or "")
                # normalize status from any shape the check API returns
                status = (
                    row.get("status")
                    or row.get("last_status")
                    or (row.get("ping") or {}).get("status")
                    or (row.get("result") or {}).get("status")
                    or ""
                )
                status = str(status).lower().strip()
                if status in ("up", "ok", "alive", "reachable", "success"):
                    status = "online"
                if status in ("down", "offline", "fail", "failed", "timeout", "no_icmp", "unreachable"):
                    status = "no_icmp"
                # explicit Check from app = always notify (like script force_notify)
                if status not in ("online", "no_icmp"):
                    # last resort: treat unknown as offline only if ping false-ish
                    ping = row.get("ping") if isinstance(row.get("ping"), dict) else {}
                    if ping.get("ok") is True or ping.get("alive") is True:
                        status = "online"
                    else:
                        status = "no_icmp"
                info = row.get("info") or row.get("last_info") or row.get("geo") or {}
                if not isinstance(info, dict):
                    info = {}
                label = str(row.get("label") or "")
                ports = row.get("ports") or row.get("last_ports") or None
                if isinstance(ports, dict):
                    try:
                        ports = {int(k): bool(v) for k, v in ports.items()}
                    except Exception:
                        ports = None
                else:
                    ports = None
                if not target:
                    continue
                title, message, colour = _ipcheck_build_surveillance_message(
                    target, status, info, label, owner, ports
                )
                sent.append(_ipcheck_send_discord_cli(webhook, title, message, colour, owner))
            result["discord"] = sent
        except Exception as e:
            if isinstance(result, dict):
                result["discord"] = {"ok": False, "reason": str(e)}
        return result

    app.add_api_route("/api/ipcheck/check", api_ipcheck_check_surveillance, methods=["POST"])
    app.add_api_route("/api/ipcheck/webhook/test", api_ipcheck_webhook_test, methods=["POST"])
