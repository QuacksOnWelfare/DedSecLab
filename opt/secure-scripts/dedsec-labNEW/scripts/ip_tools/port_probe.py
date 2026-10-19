#!/usr/bin/env python3
import socket
import re
import sys

target = input("Enter target IP or hostname: ").strip()
ports = input("Enter port(s), comma-separated (example: 22,80,443): ").strip()

if not target:
    print("No target provided.")
    sys.exit(1)

if not ports:
    print("No ports provided.")
    sys.exit(1)

# 🔒 Validate target (basic safe pattern)
if len(target) > 253 or not re.match(r"^[A-Za-z0-9.\-]+$", target):
    print("Invalid target.")
    sys.exit(1)

# 🔒 Validate ports
port_list = []
for part in ports.split(","):
    part = part.strip()
    if part.isdigit():
        port = int(part)
        if 1 <= port <= 65535:
            port_list.append(port)

if not port_list:
    print("No valid ports provided.")
    sys.exit(1)

print(f"\nProbing {target}\n")

for port in port_list:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)
        result = sock.connect_ex((target, port))
        sock.close()

        if result == 0:
            print(f"Port {port}: OPEN")
        else:
            print(f"Port {port}: CLOSED or FILTERED")

    except socket.gaierror:
        print("Invalid hostname or DNS failure.")
        sys.exit(1)
    except Exception:
        print(f"Error probing port {port}")

