#!/usr/bin/env python3
import socket

target = input("Enter IP address: ").strip()
if not target:
    print("No target provided.")
    raise SystemExit(1)

try:
    hostname, aliases, addresses = socket.gethostbyaddr(target)
    print(f"\nReverse DNS result for {target}\n")
    print(f"Hostname : {hostname}")
    print(f"Aliases  : {', '.join(aliases) if aliases else 'None'}")
    print(f"Addresses: {', '.join(addresses)}")
except Exception as e:
    print(f"\nReverse lookup failed for {target}")
    print(f"Error: {e}")

