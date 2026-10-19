"""
server.py
---------
Flask server for the hardware locker.
Run this on your server/VPS.

Install:  pip install flask flask-cors
Run:      python server.py

Endpoints:
  POST /api/devices/check      - App calls this on startup
  GET  /api/admin/devices      - List all devices (admin key required)
  POST /api/admin/approve      - Approve a device
  POST /api/admin/revoke       - Revoke a device
  DELETE /api/admin/device     - Delete a device record
  GET  /api/admin/log          - View audit log
  GET  /api/admin/version      - Get current min version
  POST /api/admin/version      - Set minimum allowed version
"""

import sqlite3
import uuid
import os
import hashlib
import hmac
import time
import json
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# --- Configuration -----------------------------------------------------------

DB_PATH = os.environ.get("LOCKER_DB", "locker.db")

ADMIN_KEY = os.environ.get("LOCKER_ADMIN_KEY", "change-me-in-production")

SIGNING_KEY = os.environ.get("LOCKER_SIGNING_KEY", "another-secret-change-me").encode()

# Minimum allowed app version - clients below this get status 'outdated'
# Can be updated at runtime via POST /api/admin/version
MIN_VERSION = os.environ.get("LOCKER_MIN_VERSION", "1.0.1")


# --- Version comparison ------------------------------------------------------

def parse_version(v: str):
    try:
        return tuple(int(x) for x in v.strip().split("."))
    except Exception:
        return (0, 0, 0)

def is_version_allowed(client_version: str) -> bool:
    return parse_version(client_version) >= parse_version(MIN_VERSION)


# --- Database ----------------------------------------------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id           TEXT PRIMARY KEY,
                fingerprint  TEXT UNIQUE NOT NULL,
                label        TEXT,
                status       TEXT NOT NULL DEFAULT 'pending',
                registered_at TEXT NOT NULL,
                updated_at   TEXT NOT NULL,
                approved_by  TEXT,
                notes        TEXT
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id  TEXT NOT NULL,
                action     TEXT NOT NULL,
                actor      TEXT,
                timestamp  TEXT NOT NULL,
                details    TEXT
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS config (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        db.commit()


def get_config(key: str, default: str = "") -> str:
    with get_db() as db:
        row = db.execute("SELECT value FROM config WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default


def set_config(key: str, value: str):
    with get_db() as db:
        db.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", (key, value))
        db.commit()


def get_min_version() -> str:
    return get_config("min_version", MIN_VERSION)


def log_action(device_id: str, action: str, actor: str = None, details: str = None, db=None):
    def _insert(conn):
        conn.execute(
            "INSERT INTO audit_log (device_id, action, actor, timestamp, details) VALUES (?,?,?,?,?)",
            (device_id, action, actor, _now(), details)
        )
    if db is not None:
        _insert(db)
    else:
        with get_db() as conn:
            _insert(conn)
            conn.commit()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --- Auth --------------------------------------------------------------------

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-Admin-Key") or request.args.get("admin_key")
        if not key or not hmac.compare_digest(key, ADMIN_KEY):
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


# --- Signing -----------------------------------------------------------------

def sign_response(payload: dict) -> str:
    data = json.dumps(payload, sort_keys=True).encode()
    sig = hmac.new(SIGNING_KEY, data, hashlib.sha256).hexdigest()
    return sig



def _client_ip():
    xf = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    if xf:
        return xf
    return (request.remote_addr or "").strip()


def _notify_pending_hwid(label, fingerprint, device_id, user, vpn_ip):
    """Discord alert for a NEW pending device only."""
    import json as _json
    import urllib.request
    path = "/opt/secure-scripts/dedsec-labNEW/hardware_locker/hwid_webhook.json"
    try:
        data = _json.loads(open(path, encoding="utf-8").read())
        url = str(data.get("webhook") or data.get("url") or "").strip()
    except Exception:
        return
    if not url.startswith("https://discord.com/api/webhooks/"):
        return
    short = (fingerprint or "")[:16].upper()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    message = (
        f"**Time:** `{now}`\n"
        f"**User:** `{user or label or 'unknown'}`\n"
        f"**VPN IP:** `{vpn_ip or 'unknown'}`\n"
        f"**Fingerprint:** `{short}`\n"
        f"**Device ID:** `{device_id}`\n"
        f"**Status:** `pending`"
    )
    payload = _json.dumps({
        "username": "DedSecEye",
        "embeds": [{
            "title": "HWID request - pending",
            "description": message,
            "color": 0xFFAA00,
            "footer": {"text": "DEDSCAN • HWID locker"},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }],
    }).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "DedSecEye/1.0 (HWID; +https://discord.com)",
        },
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass


# --- Routes ------------------------------------------------------------------

@app.route("/api/devices/check", methods=["POST"])
def check_device():
    """
    Called by the app on every startup.
    Body: { "fingerprint": "<sha256 hex>", "label": "optional device name", "version": "1.0.1" }
    Returns: { "status": "approved|pending|revoked|outdated", "device_id": "...", "signature": "..." }

    Policy:
      - First device ever registered  -> auto-approved (no admin needed)
      - Known device                  -> return its current status as-is
      - New device when others exist  -> registered as 'pending' (admin must approve)
    """
    data = request.get_json(silent=True) or {}
    fingerprint = data.get("fingerprint", "").strip()
    client_version = data.get("version", "0.0.0").strip()

    if not fingerprint or len(fingerprint) != 64:
        return jsonify({"error": "Invalid fingerprint"}), 400

    # Check version before anything else
    min_ver = get_min_version()
    if not is_version_allowed(client_version):
        payload = {
            "status": "outdated",
            "min_version": min_ver,
            "timestamp": int(time.time()),
        }
        payload["signature"] = sign_response(payload)
        return jsonify(payload)

    with get_db() as db:
        # Is this device already known?
        row = db.execute(
            "SELECT * FROM devices WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()

        if row is None:
            # New device - check if ANY approved devices exist yet
            approved_count = db.execute(
                "SELECT COUNT(*) FROM devices WHERE status = 'approved'"
            ).fetchone()[0]

            device_id = str(uuid.uuid4())
            label = data.get("label") or f"Device {device_id[:8].upper()}"

            if approved_count == 0:
                # First device ever - auto-approve, no admin needed
                status = "approved"
                db.execute(
                    """INSERT INTO devices
                       (id, fingerprint, label, status, registered_at, updated_at, approved_by)
                       VALUES (?, ?, ?, 'approved', ?, ?, 'auto-first')""",
                    (device_id, fingerprint, label, _now(), _now())
                )
                log_action(device_id, "registered+auto-approved", actor="server",
                           details="First device - auto-approved", db=db)
            else:
                # Second+ device - register as pending, admin must approve
                status = "pending"
                vpn_ip = (
                    str(data.get("vpn_ip") or data.get("source_ip") or "").strip()
                    or _client_ip()
                )
                user = str(
                    data.get("username")
                    or data.get("user")
                    or data.get("display_name")
                    or label
                    or "unknown"
                ).strip()
                notes = f"user={user} vpn={vpn_ip}"
                db.execute(
                    """INSERT INTO devices
                       (id, fingerprint, label, status, registered_at, updated_at, notes)
                       VALUES (?, ?, ?, 'pending', ?, ?, ?)""",
                    (device_id, fingerprint, label, _now(), _now(), notes)
                )
                log_action(device_id, "registered", details="Pending admin approval", db=db)
                _notify_pending_hwid(label, fingerprint, device_id, user, vpn_ip)

            db.commit()
        else:
            # Known device - return its current status unchanged
            device_id = row["id"]
            status = row["status"]

    payload = {
        "status": status,
        "device_id": device_id,
        "timestamp": int(time.time()),
    }
    payload["signature"] = sign_response(payload)
    return jsonify(payload)


@app.route("/api/admin/devices", methods=["GET"])
@require_admin
def list_devices():
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM devices ORDER BY registered_at DESC"
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/admin/approve", methods=["POST"])
@require_admin
def approve_device():
    data = request.get_json(silent=True) or {}
    device_id = data.get("device_id", "").strip()
    approved_by = data.get("approved_by", "admin")

    if not device_id:
        return jsonify({"error": "device_id required"}), 400

    with get_db() as db:
        row = db.execute("SELECT id FROM devices WHERE id = ?", (device_id,)).fetchone()
        if not row:
            return jsonify({"error": "Device not found"}), 404
        db.execute(
            "UPDATE devices SET status='approved', approved_by=?, updated_at=? WHERE id=?",
            (approved_by, _now(), device_id)
        )
        db.commit()

    log_action(device_id, "approved", actor=approved_by)
    return jsonify({"ok": True, "device_id": device_id, "status": "approved"})


@app.route("/api/admin/revoke", methods=["POST"])
@require_admin
def revoke_device():
    data = request.get_json(silent=True) or {}
    device_id = data.get("device_id", "").strip()

    if not device_id:
        return jsonify({"error": "device_id required"}), 400

    with get_db() as db:
        row = db.execute("SELECT id FROM devices WHERE id = ?", (device_id,)).fetchone()
        if not row:
            return jsonify({"error": "Device not found"}), 404
        db.execute(
            "UPDATE devices SET status='revoked', updated_at=? WHERE id=?",
            (_now(), device_id)
        )
        db.commit()

    log_action(device_id, "revoked", details=data.get("reason"))
    return jsonify({"ok": True, "device_id": device_id, "status": "revoked"})


@app.route("/api/admin/device", methods=["DELETE"])
@require_admin
def delete_device():
    device_id = request.args.get("device_id", "").strip()
    if not device_id:
        return jsonify({"error": "device_id required"}), 400

    with get_db() as db:
        db.execute("DELETE FROM devices WHERE id = ?", (device_id,))
        db.commit()

    return jsonify({"ok": True})


@app.route("/api/admin/log", methods=["GET"])
@require_admin
def audit_log():
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 200"
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/admin/version", methods=["GET"])
@require_admin
def get_version():
    return jsonify({"min_version": get_min_version()})


@app.route("/api/admin/version", methods=["POST"])
@require_admin
def set_version():
    data = request.get_json(silent=True) or {}
    new_version = data.get("min_version", "").strip()

    if not new_version:
        return jsonify({"error": "min_version required"}), 400

    try:
        parse_version(new_version)
    except Exception:
        return jsonify({"error": "Invalid version format, use e.g. 1.2.0"}), 400

    set_config("min_version", new_version)
    return jsonify({"ok": True, "min_version": new_version})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True})


# --- Main --------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    print("Hardware Locker Server starting...")
    print(f"  DB:          {DB_PATH}")
    print(f"  Admin key:   {ADMIN_KEY}")
    print(f"  Min version: {get_min_version()}")
    print()
    app.run(host="0.0.0.0", port=5000, debug=False)
