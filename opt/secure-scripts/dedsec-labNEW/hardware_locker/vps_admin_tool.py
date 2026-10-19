#!/usr/bin/env python3
import sqlite3
from datetime import datetime, timedelta
import time
import os

DB_PATH = "/opt/secure-scripts/dedsec-labNEW/hardware_locker/locker.db"

def clear():
    os.system("clear")

# --- Database connection ---
def connect_db():
    return sqlite3.connect(DB_PATH)

# --- Helper: format row columns evenly ---
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

# --- Helper: shorten fingerprint for display ---
def short_fp(fp, n=16):
    if not fp:
        return "?"
    return fp[:n].upper() + "..."

# --- Helper: shorten DB UUID for display ---
def short_id(uid, n=8):
    if not uid:
        return "?"
    return uid[:n].upper()

# --- Helper: shorten timestamp for display ---
def short_ts(ts):
    if not ts:
        return "-"
    return str(ts)[:16]

# --- Helper: find a device by fingerprint substring or DB ID ---
def find_device(cur, query, cols="id, fingerprint, label"):
    clean = query.replace("-", "").upper()
    cur.execute(f"""
        SELECT {cols} FROM devices
        WHERE UPPER(REPLACE(fingerprint, '-', '')) LIKE ?
           OR UPPER(fingerprint) LIKE ?
           OR id = ?
    """, (f"%{clean}%", f"%{query}%", query.lower()))
    return cur.fetchone()

# --- List all devices ---
def list_devices():
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, fingerprint, label, status, approved_by, registered_at
        FROM devices
        ORDER BY registered_at DESC
    """)
    rows = cur.fetchall()
    conn.close()

    if not rows:
        print("\nNo devices found.")
        return

    display = []
    for r in rows:
        display.append((
            short_id(r[0]),
            short_fp(r[1]),
            r[2] or "-",
            r[3] or "-",
            r[4] or "-",
            short_ts(r[5]),
        ))

    print_table(
        ["ID", "Fingerprint", "Label", "Status", "Approved By", "Registered At"],
        display
    )
    print("  (Use 'View device detail' to see full fingerprint)\n")

# --- List pending devices only ---
def list_pending_devices():
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, fingerprint, label, registered_at
        FROM devices
        WHERE status = 'pending'
        ORDER BY registered_at ASC
    """)
    rows = cur.fetchall()
    conn.close()

    if not rows:
        print("\nNo pending devices.")
        return

    display = []
    for r in rows:
        display.append((
            short_id(r[0]),
            short_fp(r[1]),
            r[2] or "-",
            short_ts(r[3]),
        ))

    print_table(["ID", "Fingerprint", "Label", "Registered At"], display)
    print("  (Use 'View device detail' to see full fingerprint)\n")

# --- Show latest pending (most likely to be yours) ---
def show_latest_pending():
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, fingerprint, label, registered_at
        FROM devices
        WHERE status = 'pending'
        ORDER BY registered_at DESC
        LIMIT 1
    """)
    row = cur.fetchone()
    conn.close()

    if not row:
        print("\nNo pending devices.")
        return

    print("\n--- Most Recently Registered Pending Device ---")
    print(f"  DB ID      : {row[0]}")
    print(f"  Fingerprint: {row[1]}")
    print(f"  Label      : {row[2]}")
    print(f"  Registered : {row[3]}")
    print()

    approve = input("Approve this device now? (y/n): ").strip().lower()
    if approve == 'y':
        conn = connect_db()
        cur = conn.cursor()
        cur.execute("""
            UPDATE devices SET status='approved', approved_by='admin', updated_at=?
            WHERE id=?
        """, (datetime.now().isoformat(), row[0]))
        conn.commit()
        conn.close()
        print(f"\nApproved: [{row[1]}] {row[2]}")
    else:
        print("No changes made.")

# --- Device detail view ---
def device_detail():
    query = input("Enter Fingerprint (or part of it) or DB ID: ").strip()
    conn = connect_db()
    cur = conn.cursor()

    row = find_device(cur, query, cols="id, fingerprint, label, status, approved_by, registered_at, updated_at")
    conn.close()

    if not row:
        print(f"\nNo device found matching '{query}'.")
        return

    print("\n--- Device Detail ---")
    fields = ["DB ID", "Fingerprint", "Label", "Status", "Approved By", "Registered At", "Last Updated"]
    for field, val in zip(fields, row):
        print(f"  {field:<15}: {val if val is not None else '-'}")
    print()

# --- Approve a device ---
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
    cur.execute("""
        UPDATE devices SET status='approved', approved_by='admin', updated_at=?
        WHERE id=?
    """, (datetime.now().isoformat(), device_id))
    conn.commit()
    conn.close()
    print(f"\nApproved: [{fingerprint}] {label}")

# --- Revoke a device ---
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
    cur.execute("""
        UPDATE devices SET status='revoked', updated_at=?
        WHERE id=?
    """, (datetime.now().isoformat(), device_id))
    conn.commit()
    conn.close()
    print(f"\nRevoked: [{fingerprint}] {label}")

# --- Delete a device entirely ---
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
    if confirm == 'y':
        cur.execute("DELETE FROM devices WHERE id=?", (device_id,))
        conn.commit()
        print(f"\nDeleted: [{fingerprint}] {label}")
    else:
        print("Delete cancelled.")
    conn.close()

# --- Reset all devices ---
def reset_devices():
    confirm = input("Reset ALL devices to pending? This cannot be undone. (y/n): ").strip().lower()
    if confirm == 'y':
        conn = connect_db()
        cur = conn.cursor()
        cur.execute("""
            UPDATE devices SET status='pending', approved_by=NULL, updated_at=?
        """, (datetime.now().isoformat(),))
        conn.commit()
        conn.close()
        print("All devices reset to pending.")
    else:
        print("Reset cancelled.")

# --- Auto-approve first pending device (only if none approved yet) ---
def auto_approve_if_none():
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM devices WHERE status='approved'")
    count = cur.fetchone()[0]

    if count > 0:
        print(f"\nSkipped: {count} device(s) already approved. This only runs when zero are approved.")
        conn.close()
        return

    cur.execute("""
        SELECT id, fingerprint, label FROM devices
        WHERE status='pending'
        ORDER BY registered_at ASC
        LIMIT 1
    """)
    row = cur.fetchone()

    if row:
        device_id, fingerprint, label = row
        cur.execute("""
            UPDATE devices SET status='approved', approved_by='auto', updated_at=?
            WHERE id=?
        """, (datetime.now().isoformat(), device_id))
        conn.commit()
        print(f"\nAuto-approved first pending device: [{fingerprint}] {label}")
    else:
        print("\nNo pending devices to auto-approve.")

    conn.close()

# --- Clean up old pending devices ---
def cleanup_old_pending():
    print("\n--- Clean Up Old Pending Devices ---")
    print("Remove pending devices that have not been approved within a time limit.")
    print()
    print("  1) 1 hour")
    print("  2) 6 hours")
    print("  3) 24 hours")
    print("  4) 3 days")
    print("  5) 7 days")
    print("  6) Custom (enter minutes)")
    print()
    choice = input("Select time limit: ").strip()

    minutes_map = {
        "1": 60,
        "2": 360,
        "3": 1440,
        "4": 4320,
        "5": 10080,
    }

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
    cur.execute("""
        SELECT id, fingerprint, label, registered_at
        FROM devices
        WHERE status = 'pending'
          AND registered_at < ?
        ORDER BY registered_at ASC
    """, (cutoff,))
    rows = cur.fetchall()

    if not rows:
        print(f"\nNo pending devices older than {minutes} minutes found.")
        conn.close()
        return

    print(f"\nThe following {len(rows)} device(s) have been pending for over {minutes} minutes:\n")
    print_table(["DB ID", "Fingerprint", "Label", "Registered At"], rows)

    confirm = input(f"Permanently delete all {len(rows)} device(s)? (y/n): ").strip().lower()
    if confirm == 'y':
        ids = [r[0] for r in rows]
        cur.executemany("DELETE FROM devices WHERE id=?", [(i,) for i in ids])
        conn.commit()
        print(f"\nDeleted {len(rows)} old pending device(s).")
    else:
        print("Cleanup cancelled.")

    conn.close()

# --- View live logins ---
def view_live_logins():
    log_path = "/opt/secure-scripts/dedsec-labNEW/hardware_locker/locker.log"
    print("\n=== LIVE LOGIN LOGS (Ctrl+C to stop) ===\n")
    try:
        with open(log_path, "r") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                print(line.strip())
    except KeyboardInterrupt:
        print("\nExiting live log view.")

# --- Menu ---
def menu():
    options = [
        ("List all devices",                                list_devices),
        ("List pending devices only",                       list_pending_devices),
        ("Show latest pending device  [approve yours]",     show_latest_pending),
        ("View device detail",                              device_detail),
        ("Approve a device  [by Fingerprint or DB ID]",     approve_device),
        ("Revoke a device   [by Fingerprint or DB ID]",     revoke_device),
        ("Delete a device   [by Fingerprint or DB ID]",     delete_device),
        ("Clean up old pending devices  [by time limit]",   cleanup_old_pending),
        ("Reset all devices to pending",                    reset_devices),
        ("Auto-approve first pending (if none approved)",   auto_approve_if_none),
        ("View live logins",                                view_live_logins),
    ]

    while True:
        clear()
        print("===== VPS ADMIN MENU =====")
        for i, (label, _) in enumerate(options, 1):
            print(f"{i}) {label}")
        print(f"{len(options) + 1}) Exit")

        choice = input("\n> ").strip()

        if choice == str(len(options) + 1):
            clear()
            print("Exiting.")
            break

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(options):
                clear()
                options[idx][1]()
                input("\nPress Enter to return to menu...")
            else:
                input("Invalid choice. Press Enter to try again...")
        except ValueError:
            input("Invalid choice. Press Enter to try again...")

if __name__ == "__main__":
    menu()
