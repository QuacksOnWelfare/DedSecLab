#!/usr/bin/env python3
import re
import subprocess
import sys

target = input("Enter target IP or hostname: ").strip()

if not target:
    print("No target provided.")
    sys.exit(1)

if len(target) > 253:
    print("Invalid target.")
    sys.exit(1)

allowed = re.compile(r"^[A-Za-z0-9.\-_:]+$")

if not allowed.match(target):
    print("Invalid target. Use only IP addresses or hostnames.")
    sys.exit(1)

print(f"\nRunning Nmap scan against: {target}\n")

try:
    result = subprocess.run(
        ["nmap", "-Pn", "-T4", "-p", "1-1000,6672", target],
        check=False
    )
    sys.exit(result.returncode)
except FileNotFoundError:
    print("Nmap is not installed or not found in PATH.")
    sys.exit(1)
