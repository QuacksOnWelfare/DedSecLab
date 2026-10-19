#!/usr/bin/env python3
import os
import pwd
import grp

BASE_DIR = "/opt/secure-scripts/dedsec-labNEW/scripts"

def get_real_user():
    # Get the actual SSH user (not root if using sudo)
    user = os.environ.get("SUDO_USER") or os.environ.get("USER")
    return user

def fix_permissions():
    user = get_real_user()

    try:
        uid = pwd.getpwnam(user).pw_uid
        gid = grp.getgrnam(user).gr_gid
    except KeyError:
        print(f"[!] User not found: {user}")
        return

    for root, dirs, files in os.walk(BASE_DIR):
        for file in files:
            if file.endswith(".py"):
                path = os.path.join(root, file)
                try:
                    os.chmod(path, 0o755)
                    os.chown(path, uid, gid)
                    print(f"[+] Fixed: {path}")
                except Exception as e:
                    print(f"[!] Error: {path} -> {e}")

if __name__ == "__main__":
    fix_permissions()
    print("\nDone.")
