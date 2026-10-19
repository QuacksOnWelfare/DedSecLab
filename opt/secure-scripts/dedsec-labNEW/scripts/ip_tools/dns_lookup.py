#!/usr/bin/env python3
import socket

target = input("Enter domain name: ").strip()
if not target:
    print("No target provided.")
    raise SystemExit(1)

try:
    hostname, aliases, addresses = socket.gethostbyname_ex(target)
    print(f"\nDNS lookup result for {target}\n")
    print(f"Hostname : {hostname}")
    print(f"Aliases  : {', '.join(aliases) if aliases else 'None'}")
    print(f"Addresses: {', '.join(addresses)}")
except Exception as e:
    print(f"\nDNS lookup failed for {target}")
    print(f"Error: {e}")
