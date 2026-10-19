#!/usr/bin/env python3
"""DEDSEC LAB · HWID locker admin - menu exit only."""
from __future__ import annotations

import json
import os
import select
import signal
import sqlite3
import sys
import time
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path

RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
DIM = "\033[2m"

LOCKER_DIR = Path("/opt/secure-scripts/dedsec-labNEW/hardware_locker")
DB_PATH = LOCKER_DIR / "locker.db"
LOG_PATH = LOCKER_DIR / "locker.log"
WEBHOOK_FILE = LOCKER_DIR / "hwid_webhook.json"
SEEN_FILE = LOCKER_DIR / "hwid_alert_seen.json"

BANNER = r"""
██████╗ ███████╗██████╗ ███████╗███████╗ ██████╗
██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝
██║  ██║█████╗  ██║  ██║███████╗█████╗  ██║
██║  ██║██╔══╝  ██║  ██║╚════██║██╔══╝  ██║
██████╔╝███████╗██████╔╝███████║███████╗╚██████╗
╚═════╝ ╚══════╝╚═════╝ ╚══════╝╚══════╝ ╚═════╝
"""


def color(text, c):
    return f"{c}{text}{RESET}"


def _ignore(signum, frame):
    print(color("\n  Ctrl+C / Ctrl+Z disabled. Use the menu to exit.", YELLOW))


def install_signal_guards():
    for sig in (signal.SIGINT, signal.SIGTSTP, signal.SIGQUIT):
        try:
            signal.signal(sig, _ignore)
        except Exception:
            pass


def clear():
    os.system("clear" if os.name != "nt" else "cls")


def pause(msg="Press Enter to return to menu..."):
    try:
        input(color(msg, DIM))
    except Exception:
        pass


def recover_terminal():
    os.system("stty sane 2>/dev/null || true")
    os.system("reset || true")
    print(color("Terminal reset.", GREEN))
    pause()


def connect_db():
    return sqlite3.connect(str(DB_PATH))


def print_table(headers, rows):
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(val) if val is not None else "-"))
    fmt = "  ".join(f"{{:<{w}}}" for w in col_widths)
    print()
    print(fmt.format(*headers))
    print("  ".join("-" * w for w in col_widths))
    for row in rows:
        print(fmt.format(*[str(v) if v is not None else "-" for v in row]))
    print()


def short_fp(fp, n=16):
    if not fp:
        return "?"
    return fp[:n].upper() + "..."


def short_id(uid, n=8):
    if not uid:
        return "?"
    return uid[:n].upper()


def short_ts(ts):
    if not ts:
        return "-"
    return str(ts)[:16]


def find_device(cur, query, cols="id, fingerprint, label"):
    clean = query.replace("-", "").upper()
    cur.execute(
        f"""
        SELECT {cols} FROM devices
        WHERE UPPER(REPLACE(fingerprint, '-', '')) LIKE ?
           OR UPPER(fingerprint) LIKE ?
           OR id = ?
        """,
        (f"%{clean}%", f"%{query}%", query.lower()),
    )
    return cur.fetchone()


def load_json(path, default):
    try:
        if path.is_file():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return default


def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def load_webhook():
    data = load_json(WEBHOOK_FILE, {})
    if isinstance(data, dict):
        return str(data.get("webhook") or data.get("url") or data.get("webhook_url") or "").strip()
    if isinstance(data, str):
        return data.strip()
    return ""


def send_discord(title, message, colour=0x00FFFF):
    url = load_webhook()
    if not url:
        return {"ok": False, "reason": "webhook not configured"}
    payload = json.dumps({
        "username": "DedSecEye",
        "embeds": [{
            "title": title,
            "description": message,
            "color": int(colour),
            "footer": {"text": "DEDSCAN • HWID locker"},
            "timestamp": datetime.utcnow().isoformat() + "Z",
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
        with urllib.request.urlopen(req, timeout=12) as resp:
            return {"ok": 200 <= resp.status < 300, "status": resp.status}
    except Exception as e:
        return {"ok": False, "reason": str(e)}


def pending_rows():
    conn = connect_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, fingerprint, label, status, registered_at, notes
        FROM devices
        WHERE status = 'pending'
        ORDER BY registered_at DESC
        """
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def format_hwid_alert(row):
    did, fp, label, status, registered, notes = row
    vpn = "unknown"
    extra = notes or ""
    low = extra.lower()
    if "10.8." in extra:
        for part in extra.replace(",", " ").split():
            if part.startswith("10.8."):
                vpn = part
                break
    return (
        f"**Request:** HWID / device pending\n"
        f"**Label:** `{label or '-'}`\n"
        f"**Fingerprint:** `{fp}`\n"
        f"**DB ID:** `{did}`\n"
        f"**Status:** `{status}`\n"
        f"**VPN IP:** `{vpn}`\n"
        f"**Registered:** `{registered}`\n"
        f"**Notes:** `{extra or '-'}`"
    )


def list_devices():
    conn = connect_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, fingerprint, label, status, approved_by, registered_at
        FROM devices
        ORDER BY registered_at DESC
        """
    )
    rows = cur.fetchall()
    conn.close()
    if not rows:
        print("\nNo devices found.")
        return
    display = [
        (short_id(r[0]), short_fp(r[1]), r[2] or "-", r[3] or "-", r[4] or "-", short_ts(r[5]))
        for r in rows
    ]
    print_table(["ID", "Fingerprint", "Label", "Status", "Approved By", "Registered At"], display)
    print("  (Use device detail for the full fingerprint)\n")


def list_pending_devices():
    rows = pending_rows()
    if not rows:
        print("\nNo pending devices.")
        return
    display = [(short_id(r[0]), short_fp(r[1]), r[2] or "-", short_ts(r[4])) for r in rows]
    print_table(["ID", "Fingerprint", "Label", "Registered At"], display)


def show_latest_pending():
    rows = pending_rows()
    if not rows:
        print("\nNo pending devices.")
        return
    row = rows[0]
    print("\n--- Latest pending device ---")
    print(f"  DB ID      : {row[0]}")
    print(f"  Fingerprint: {row[1]}")
    print(f"  Label      : {row[2]}")
    print(f"  Registered : {row[4]}")
    approve = input("Approve this device now? (y/n): ").strip().lower()
    if approve != "y":
        print("No changes made.")
        return
    conn = connect_db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE devices SET status='approved', approved_by='admin', updated_at=? WHERE id=?",
        (datetime.now().isoformat(), row[0]),
    )
    conn.commit()
    conn.close()
    print(f"\nApproved: [{row[1]}] {row[2]}")


def device_detail():
    query = input("Enter Fingerprint (or part of it) or DB ID: ").strip()
    conn = connect_db()
    cur = conn.cursor()
    row = find_device(
        cur, query,
        cols="id, fingerprint, label, status, approved_by, registered_at, updated_at, notes",
    )
    conn.close()
    if not row:
        print(f"\nNo device found matching '{query}'.")
        return
    fields = ["DB ID", "Fingerprint", "Label", "Status", "Approved By", "Registered At", "Last Updated", "Notes"]
    print("\n--- Device Detail ---")
    for field, val in zip(fields, row):
        print(f"  {field:<15}: {val if val is not None else '-'}")
    print()


def approve_device():
    query = input("Enter Fingerprint (or part of it) or DB ID to approve: ").strip()
    conn = connect_db()
    cur = conn.cursor()
    row = find_device(cur, query)
    if not row:
        print(f"\nNo device found matching '{query}'.")
        conn.close()
        return
    device_id, fingerprint, label = row
    cur.execute(
        "UPDATE devices SET status='approved', approved_by='admin', updated_at=? WHERE id=?",
        (datetime.now().isoformat(), device_id),
    )
    conn.commit()
    conn.close()
    print(f"\nApproved: [{fingerprint}] {label}")


def revoke_device():
    query = input("Enter Fingerprint (or part of it) or DB ID to revoke: ").strip()
    conn = connect_db()
    cur = conn.cursor()
    row = find_device(cur, query)
    if not row:
        print(f"\nNo device found matching '{query}'.")
        conn.close()
        return
    device_id, fingerprint, label = row
    cur.execute(
        "UPDATE devices SET status='revoked', updated_at=? WHERE id=?",
        (datetime.now().isoformat(), device_id),
    )
    conn.commit()
    conn.close()
    print(f"\nRevoked: [{fingerprint}] {label}")


def delete_device():
    query = input("Enter Fingerprint (or part of it) or DB ID to DELETE: ").strip()
    conn = connect_db()
    cur = conn.cursor()
    row = find_device(cur, query)
    if not row:
        print(f"\nNo device found matching '{query}'.")
        conn.close()
        return
    device_id, fingerprint, label = row
    confirm = input(f"Permanently delete [{fingerprint}] {label}? (y/n): ").strip().lower()
    if confirm == "y":
        cur.execute("DELETE FROM devices WHERE id=?", (device_id,))
        conn.commit()
        print(f"\nDeleted: [{fingerprint}] {label}")
    else:
        print("Delete cancelled.")
    conn.close()


def reset_devices():
    confirm = input("Reset ALL devices to pending? This cannot be undone. (y/n): ").strip().lower()
    if confirm != "y":
        print("Reset cancelled.")
        return
    conn = connect_db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE devices SET status='pending', approved_by=NULL, updated_at=?",
        (datetime.now().isoformat(),),
    )
    conn.commit()
    conn.close()
    save_json(SEEN_FILE, {"ids": []})
    rows = pending_rows()
    sent = send_discord(
        "HWID locker - all reset to pending",
        f"**Count:** `{len(rows)}` device(s) set back to pending.\n"
        f"Watcher seen-list cleared. New requests will alert again.",
        0xFFAA00,
    )
    print("All devices reset to pending.")
    print("Discord:", sent)


def auto_approve_if_none():
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM devices WHERE status='approved'")
    count = cur.fetchone()[0]
    if count > 0:
        print(f"\nSkipped: {count} device(s) already approved.")
        conn.close()
        return
    cur.execute(
        """
        SELECT id, fingerprint, label FROM devices
        WHERE status='pending'
        ORDER BY registered_at ASC
        LIMIT 1
        """
    )
    row = cur.fetchone()
    if row:
        device_id, fingerprint, label = row
        cur.execute(
            "UPDATE devices SET status='approved', approved_by='auto', updated_at=? WHERE id=?",
            (datetime.now().isoformat(), device_id),
        )
        conn.commit()
        print(f"\nAuto-approved first pending device: [{fingerprint}] {label}")
    else:
        print("\nNo pending devices to auto-approve.")
    conn.close()


def cleanup_old_pending():
    print("\n--- Clean Up Old Pending Devices ---")
    print("  1) 1 hour")
    print("  2) 6 hours")
    print("  3) 24 hours")
    print("  4) 3 days")
    print("  5) 7 days")
    print("  6) Custom (minutes)")
    choice = input("Select time limit: ").strip()
    minutes_map = {"1": 60, "2": 360, "3": 1440, "4": 4320, "5": 10080}
    if choice in minutes_map:
        minutes = minutes_map[choice]
    elif choice == "6":
        try:
            minutes = int(input("Enter number of minutes: ").strip())
        except ValueError:
            print("Invalid input.")
            return
    else:
        print("Invalid choice.")
        return
    cutoff = (datetime.now() - timedelta(minutes=minutes)).isoformat()
    conn = connect_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, fingerprint, label, registered_at
        FROM devices
        WHERE status = 'pending' AND registered_at < ?
        ORDER BY registered_at ASC
        """,
        (cutoff,),
    )
    rows = cur.fetchall()
    if not rows:
        print(f"\nNo pending devices older than {minutes} minutes.")
        conn.close()
        return
    print_table(["DB ID", "Fingerprint", "Label", "Registered At"], rows)
    confirm = input(f"Permanently delete all {len(rows)} device(s)? (y/n): ").strip().lower()
    if confirm == "y":
        cur.executemany("DELETE FROM devices WHERE id=?", [(r[0],) for r in rows])
        conn.commit()
        print(f"\nDeleted {len(rows)} old pending device(s).")
    else:
        print("Cleanup cancelled.")
    conn.close()


def timed_line(prompt, timeout):
    print(prompt, end="", flush=True)
    r, _, _ = select.select([sys.stdin], [], [], timeout)
    if r:
        return sys.stdin.readline().strip()
    print()
    return ""


def view_live_logins():
    print(color("\nLIVE LOGIN LOGS - type 0 then Enter to stop\n", CYAN))
    if not LOG_PATH.is_file():
        print("No locker.log yet.")
        return
    with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                print(line.strip())
                continue
            stop = timed_line("  [watching] 0 + Enter to stop: ", 2.0)
            if stop == "0":
                print("Stopped live view.")
                return


def set_webhook():
    current = load_webhook()
    print("Current webhook:", "SET" if current else "NOT SET")
    url = input("Paste Discord webhook URL (blank = keep): ").strip()
    if not url:
        print("Unchanged.")
        return
    if not url.startswith("https://discord.com/api/webhooks/"):
        print("Not a Discord webhook URL.")
        return
    save_json(WEBHOOK_FILE, {"webhook": url, "url": url})
    print(color("Webhook saved.", GREEN))


def test_webhook():
    sent = send_discord(
        "HWID locker - webhook test",
        "Owner menu test. You will get alerts when a new pending device is seen.",
        0x00FFFF,
    )
    print(sent)


def watch_pending_alerts():
    if not load_webhook():
        print("Set a webhook first.")
        return
    seen = set(load_json(SEEN_FILE, {}).get("ids") or [])
    print(color("Watching pending HWID requests. Type 0 then Enter to stop.\n", CYAN))
    while True:
        rows = pending_rows()
        fresh = []
        for row in rows:
            if row[0] not in seen:
                fresh.append(row)
                seen.add(row[0])
        if fresh:
            save_json(SEEN_FILE, {"ids": sorted(seen)})
            for row in fresh:
                msg = format_hwid_alert(row)
                sent = send_discord("HWID change / new device request", msg, 0xFFAA00)
                print(color(f"Alert sent for {short_fp(row[1])} ({sent})", GREEN if sent.get("ok") else RED))
        else:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] no new pending")
        stop = timed_line("  0 + Enter to stop: ", 10.0)
        if stop == "0":
            print("Stopped watcher.")
            return


def banner(page=1):
    clear()
    print(color(BANNER, CYAN))
    print(color("  DEDSEC LAB  ·  OWNER TOOLS", BOLD + CYAN))
    print(color("  Hardware locker  ·  HWID admin", DIM))
    print(color("=" * 56, CYAN))
    print(color(f"  DB: {DB_PATH}", DIM))
    print(color(f"  Webhook: {'SET' if load_webhook() else 'NOT SET'}", GREEN if load_webhook() else YELLOW))
    print(color("-" * 56, DIM))
    if page == 1:
        print(color("  PAGE 1 · DEVICES", BOLD + MAGENTA))
    else:
        print(color("  PAGE 2 · ALERTS + LOGS", BOLD + YELLOW))
    print()


def menu():
    install_signal_guards()
    page = 1
    while True:
        banner(page)
        if page == 1:
            print("   1. List all devices")
            print("   2. List pending devices")
            print("   3. Show latest pending / approve")
            print("   4. View device detail")
            print("   5. Approve a device")
            print("   6. Revoke a device")
            print("   7. Delete a device")
            print("   8. Clean up old pending")
            print("   9. Reset all to pending")
            print("  10. Auto-approve first pending")
            print("  11. Next page")
            print("   0. Exit")
        else:
            print("   1. Set Discord webhook")
            print("   2. Test Discord webhook")
            print("   3. Watch pending HWID requests (Discord alerts)")
            print("   4. View live locker log")
            print("   5. Recover stuck terminal")
            print("   6. Previous page")
            print("   0. Exit")
        print()
        print(color("  Ctrl+C / Ctrl+Z ignored. Exit with 0.", DIM))
        choice = input(color("Select option: ", CYAN)).strip()
        if page == 1:
            actions = {
                "1": list_devices,
                "2": list_pending_devices,
                "3": show_latest_pending,
                "4": device_detail,
                "5": approve_device,
                "6": revoke_device,
                "7": delete_device,
                "8": cleanup_old_pending,
                "9": reset_devices,
                "10": auto_approve_if_none,
            }
            if choice == "11":
                page = 2
                continue
            if choice == "0":
                print(color("Goodbye.", DIM))
                return
            fn = actions.get(choice)
            if fn:
                fn()
                pause()
        else:
            if choice == "1":
                set_webhook()
                pause()
            elif choice == "2":
                test_webhook()
                pause()
            elif choice == "3":
                watch_pending_alerts()
                pause()
            elif choice == "4":
                view_live_logins()
                pause()
            elif choice == "5":
                recover_terminal()
            elif choice == "6":
                page = 1
            elif choice == "0":
                print(color("Goodbye.", DIM))
                return


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Run as root.")
        sys.exit(1)
    menu()
