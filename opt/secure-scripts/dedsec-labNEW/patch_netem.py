path = "app_api.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# 1) Add whitelist constant if missing
if "NETEM_WHITELIST_PORTS" not in content:
    content = content.replace(
        "NETEM_CAP_MIN_RATE_KB = 50.0",
        "NETEM_CAP_MIN_RATE_KB = 50.0\nNETEM_WHITELIST_PORTS = (8443, 80, 443)",
    )
    print("Added NETEM_WHITELIST_PORTS")
else:
    print("NETEM_WHITELIST_PORTS already present")

old = '''        direction = (cfg.get("direction") or "both").lower()
        if direction in ("both", "in", "inbound"):
            _tc(
                "filter", "add", "dev", NETEM_IFACE,
                "protocol", "ip", "parent", "1:", "prio", "1",
                "u32", "match", "ip", "dst", f"{ip}/32",
                "flowid", flow
            )
        if direction in ("both", "out", "outbound"):
            _tc(
                "filter", "add", "dev", NETEM_IFACE,
                "protocol", "ip", "parent", "1:", "prio", "1",
                "u32", "match", "ip", "src", f"{ip}/32",
                "flowid", flow
            )'''

new = '''        direction = (cfg.get("direction") or "both").lower()
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
            )'''

if old not in content:
    print("ERROR: filter block not found - aborting (file not changed)")
    raise SystemExit(1)

content = content.replace(old, new, 1)
with open(path, "w", encoding="utf-8") as f:
    f.write(content)
print("Filter block updated OK")
