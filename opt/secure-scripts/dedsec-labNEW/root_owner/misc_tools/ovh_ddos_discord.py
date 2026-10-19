#!/usr/bin/env python3
"""Loader module - see opt/secure-scripts/ovh-ddos-discord/ for the full implementation."""
from pathlib import Path
import runpy
import sys

target = Path("/opt/secure-scripts/ovh-ddos-discord/ovh_ddos_discord.py")
# Dev / Windows fallback path:
alt = Path(__file__).resolve().parents[3] / "ovh-ddos-discord" / "ovh_ddos_discord.py"
path = target if target.is_file() else alt
if not path.is_file():
    print("OVH DDoS module not found. Place the module under /opt/secure-scripts/ovh-ddos-discord/")
    sys.exit(1)
sys.argv = [str(path)] + sys.argv[1:]
runpy.run_path(str(path), run_name="__main__")
