<div align="center">

<img src="dedseclab/dedsec_logo.png" alt="DedSecLab" width="180">

# DedSecLab

**Open-source cyber lab: Windows client, VPN bridge, and SSH ops in one tree**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](installer/LICENSE.txt)
[![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011-0078D6.svg?logo=windows&logoColor=white)](#)
[![UI: PyQt6](https://img.shields.io/badge/UI-PyQt6-41CD52.svg?logo=qt&logoColor=white)](https://pypi.org/project/PyQt6/)
[![Backend: FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![VPN: OpenVPN](https://img.shields.io/badge/VPN-OpenVPN-EA7E20.svg?logo=openvpn&logoColor=white)](https://openvpn.net/)
[![Server: Linux](https://img.shields.io/badge/Server-Ubuntu%20%7C%20Debian-E95420.svg?logo=ubuntu&logoColor=white)](INSTALL_VPS.md)
[![Build: Nuitka](https://img.shields.io/badge/Build-Nuitka-000000.svg)](https://nuitka.net/)
[![Installer: Inno Setup](https://img.shields.io/badge/Installer-Inno%20Setup-6-blue.svg)](https://jrsoftware.org/isinfo.php)
[![SSH: Python](https://img.shields.io/badge/SSH%20wrappers-Python-3776AB.svg?logo=python&logoColor=white)](#everything-in-dedseclab)
[![Terminal: WebSocket](https://img.shields.io/badge/Terminal-WebSocket-black.svg)](#everything-in-dedseclab)

</div>

**DedSecLab** is a Windows **PyQt6** lab client, an OpenVPN-gated **FastAPI** backend, and ForceCommand SSH menus. Run it on **your** VPS with **your** profiles - this repo is source + placeholders, not a private production stack.

> **Authorised use only.** Use these tools only on systems you own or have written permission to test. Unauthorised access, harassment, or abuse of networking / console-adjacent features is illegal and unsupported.

---

## Why DedSecLab

Most toolkits are a folder of scripts. This one is a full client + VPN + API + SSH menu stack:

| Piece | What it is |
|--------|------------|
| **Desktop client** | Frameless PyQt6 UI - splash, optional VPN gate, login, dashboard, account, IP database, WebSocket terminal, networking hub, themes, hidden updater |
| **VPN trust boundary** | OpenVPN locations you supply; lab API + SSH expect tunnel peers |
| **Lab API** | Login, device lock, IP DB, terminal tokens, net-emulate, John/Shodan/ipcheck proxies - pinned TLS |
| **SSH ForceCommand** | `dedsecuser` Enter Lab menu + root owner panel - whitelist, optional wrapper password, no-shell-exit |
| **Geo** | Custom `/api/ipcheck/lookup` on your backend, public **ip-api.com** fallbacks, local GeoIP/whois on the owner traffic panel |

Full list: **[FEATURES.md](FEATURES.md)**.

---

## Feature highlights

### Desktop client
- **Optional VPN gate** - OpenVPN UI (four example regions; add more), router-mode detection, tray toasts (`REQUIRE_VPN_GATE`; default **off** so you can explore without a tunnel)
- **Session hardening** - lab CA pin, Credential Manager / DPAPI secrets, device fingerprint lockers, single-instance guard
- **IP Database** - lab-backed table with auto geo / ASN enrichment (pro ip-api when you set `IPAPI_KEY`, else manual)
- **Networking hub** - speed test, VPN app bypass whitelist, lag switch (server net-emulate), macros, Geo IP lookup, TCP monitor, plus lab-gated tool panels
- **Terminal** - short-lived Bearer token -> WSS `/ws/terminal`
- **Eight themes** - Default, Dark, Light, Matrix, Crimson, Midnight, Amber, OLED
- **Build / install** - Nuitka standalone build + Inno Setup per-user installer; updater ships as a **hidden** blob

### Self-hosted server
- **OpenVPN bridge** + FastAPI-style `app_api.py`
- **Layered SSH** - VPN-only Match, IP whitelist, optional wrapper password, signal-trapped menus
- **Owner panel** - traffic intelligence, misc_tools drop-in, API service manager, HWID locker, SSH guard, backups
- **User lab menu** - account, tickets, chat, browsable `ip_tools` / `admin_tools` / `misc_tools`

Xbox / console-adjacent UI exists for lab tooling only - never use it without authorisation.

---

## Everything in DedSecLab

Detail with file/route notes: **[FEATURES.md](FEATURES.md)**. Front-page list of what ships here:

### Desktop client (Windows)

**Session flow**
- **Splash** - frameless welcome + logo before the gate / login
- **Single-instance guard** - second launch raises the existing window
- **Optional VPN gate** (`REQUIRE_VPN_GATE`; default off) - OpenVPN UI with four example regions (France / Canada / USA / UK); add more via **Add location**; tray toasts, router-mode detect, lab unlock when the tunnel is up
- **Login** - username / password against your lab API, remember-password via Credential Manager / DPAPI, first-run wizard / terms, device fingerprint lockers, min-version / outdated gate
- **Frameless shell** - custom title bar, edge resize, DedSec dark/cyan UI, click ripple, pressed-button feedback, eight themes

**Sidebar pages**
- **Dashboard** - VPN / session overview, local CPU/RAM-style status, access messaging
- **My Account** - profile from login payload, role / region / expiry, change password
- **Xbox** - Xbox Live-related lab tool page (authorised use only; no attack how-to)
- **VPN** - in-lab OpenVPN status, region list, router-mode lock on disconnect
- **IP Database** - lab-backed IP table with geo / ASN enrichment (pro ip-api when `IPAPI_KEY` is set)
- **Terminal** - short-lived Bearer token then WSS `/ws/terminal` (inline page or DedSec CMD popup)
- **Changelog** - in-client release notes cards
- **Logs** - in-memory client activity / security event log with filter / export
- **Networking** - tabbed hub (see below)
- **Settings** - appearance / themes, connection URL + Test Connection, preferences, updates check, data & storage shortcuts, status cards
- **About** - version, capabilities blurb
- **Disconnect** - end session / close lab

**Networking hub tabs**
- **Network Tools** - Cloudflare multi-stream speed test, VPN app-bypass whitelist, flush DNS, console-share guidance
- **Lag Switch** - latency / loss / rate controls via lab `/api/net-emulate/*`, presets, hotkey
- **Macros** - record / play keyboard & mouse macros and autoclicker (local profiles)
- **Password Cracker** - John the Ripper front-end + CUPP wordlist form (lab-gated API)
- **Shodan** - lab-proxied Shodan search / host / DNS tools
- **Surveillance** - live IP check / monitor / traceroute / Discord webhook test / nmap window
- **IP Lookup** - Geo IP via custom lab `/api/ipcheck/lookup` (server falls back to public ip-api.com)
- **TCP Connections** - local TCP table; end process / open file location

**Client hardening & shipping**
- Lab CA pin (`assets/lab_ca.pem`, fail-closed), TLS helper, secure secret store, atomic config, single instance
- **Hidden updater** blob (`assets/dsl_upd.bin`) - version check, sha256 (+ optional Ed25519), apply via separate process
- **Nuitka** standalone build (`build.py`) + **Inno Setup 6** per-user installer (`installer/DedSecLab.iss`)

### Lab API (`opt/.../app_api.py`)

- **Auth / session** - `POST /api/login`, `POST /api/change-password`, `GET /api/status`, `GET /api/me`
- **Updates** - `GET /api/update/version`, `GET /api/update/download`
- **IP database** - list / add / delete
- **Terminal** - `POST /api/terminal-token`, `WSS /ws/terminal`
- **John / CUPP** - token, status, start, show, wordlist, cupp
- **Shodan proxy** - token, status, count, search, host, dns, resolve, reverse
- **Net emulate** - start / stop / status (lag switch)
- **IP check / geo / nmap** - `/api/ipcheck/*` including **lookup**, traceroute, live, monitor, webhook, nmap
- Callers validated as whitelisted VPN peers; short-lived one-shot tokens on sensitive routes

**Geo layers:** custom lab `/api/ipcheck/lookup` primary for in-app Geo IP / surveillance; server `_ipcheck_geo` uses free **ip-api.com**; IP Database can use pro ip-api when `IPAPI_KEY` is set; SSH pullers use pro then free fallback; owner traffic panel uses local `geoiplookup` + `whois`.

### SSH ForceCommand stack

**Trust layers**
- OpenVPN bridge (lab peers, typically `10.8.0.0/24`)
- VPN-only SSH for `dedsecuser` (non-VPN -> `/bin/false`)
- IP whitelist (`access_rules.json`: role, enabled, expiry)
- Optional wrapper password (`WRAPPER_PASSWORD_HASH`, default off)
- No-shell-exit (signal traps; exit only via menu)
- Root owner allowlist (`root_access_rules.json`) + owner password
- Client TLS pin on the desktop app

**`dedsecuser` access wrapper**
- DedSec Access Gate - session strip, VPN node / service pills, Enter Lab or Decline and Exit
- Discord alert hooks (optional webhook placeholders)

**Lab home menu (`menu.py`)**
- My Account (profile; admin theme picker)
- Updates / Announcements
- Help / Tickets
- General Chat
- Browse Tool Categories (folder-discovered under `scripts/`)
- Exit

**Tool categories (SSH)**
- **ip_tools** - DNS lookup, FiveM / CFX finder, live traffic, Nikto runner, nmap scan, port probe, reverse DNS, vpn_puller / vpn_pullerv2
- **misc_tools** - live ping checker, ipcheck / nmap helper, optional notes
- **admin_tools** (admin role) - SSH whitelist manager, admin dashboard, DNS adblock menu + daemon, maintenance / permissions / service manager, website blocker, VPN access owner menu, ticket panel, tcpdump tool, IP spoofing helper
- **system** (not browsable) - Discord notify, chat, tickets, VPN status helpers

**VPN Tools And Puller Menu** (from puller tools) - GTA / Xbox / Rainbow Six / Fortnite / DayZ / geo-locate style pullers (authorised lab use only)

**Traffic watch** - multi-page game / call / party session monitor (calls, console parties, Steam, Minecraft, CoD, ARK, Fortnite, Apex, Valorant, GTA Online / FiveM, survival titles, and more)

**Root / owner panel**
- `root_owner_wrapper.py` - ForceCommand gate, allowlist, Discord login/deny
- `root_owner_menu.py` - password unlock; Traffic Intelligence (Scapy + GeoIP/whois); Launch Lab Menu as VPN identity; System Security Scanner; Misc Tools browser; Root Logs; Backup Lab (`tar.gz`); danger-zone root shell (YES confirm)
- **misc_tools drop-in** - any `.py` / `.sh` appears in the menu: api_manager, hwid_locker, ssh_guard, openvpn_tcp helpers, proxychains_menu, sftp_maintenance_window, tcp-dumps, ovh_ddos_discord, camera helpers (lab-only)

**Hardware locker** - device fingerprint DB, pending / approve / revoke, Discord HWID alerts, min/latest app version gates used by the Windows login lockers

**Install helpers** - `install.sh`, `setup_security.sh`, `fix_permissions.sh`, example JSON, `certs/README.md`, repo-root `ssh_config.txt`

Xbox / John / nmap / Shodan / pullers exist for **authorised lab tooling only** - never use them without permission.

---

## Screenshots

<img src="dedseclab/1.jpg" alt="VPN gate" width="420">

*VPN gate - connect before login (when `REQUIRE_VPN_GATE` is enabled)*

<img src="dedseclab/2.jpg" alt="Login" width="420">

*Login - username / password against your lab API*

![Dashboard](dedseclab/3.jpg)

*Dashboard - session overview and quick links*

![My Account](dedseclab/4.jpg)

*My Account - profile and membership*

![Xbox tools](dedseclab/5.jpg)

*Xbox tools*

![Xbox tools (alternate)](dedseclab/6.jpg)

*Xbox tools (alternate)*

![VPN connect/status](dedseclab/7.jpg)

*VPN - in-app OpenVPN status and connect / disconnect*

![IP Database](dedseclab/8.jpg)

*IP Database - lab-backed table with geo / ASN enrichment*

![Terminal](dedseclab/9.jpg)

*Terminal - WebSocket lab shell over the VPN*

![Changelog](dedseclab/10.jpg)

*Changelog - release notes inside the client*

![Logs](dedseclab/11.jpg)

*Logs - local / session log viewer*

![Networking speed test](dedseclab/12.jpg)

*Networking - speed test*

![Networking lag switch](dedseclab/13.jpg)

*Networking - lag switch*

![Networking macros](dedseclab/14.jpg)

*Networking - macros*

![Networking password cracker](dedseclab/15.jpg)

*Networking - password cracker (John)*

![Networking Shodan](dedseclab/16.jpg)

*Networking - Shodan*

![IP surveillance](dedseclab/17.jpg)

*Networking - IP surveillance / live ping*

![Geo IP Lookup](dedseclab/18.jpg)

*Networking - Geo IP Lookup*

![TCP Connections](dedseclab/19.jpg)

*Networking - TCP Connections monitor*

![Settings Default theme](dedseclab/20.jpg)

*Settings - Default theme*

![Settings Dark theme](dedseclab/21.jpg)

*Settings - Dark theme*

![Settings Light theme](dedseclab/22.jpg)

*Settings - Light theme*

![Settings Matrix theme](dedseclab/23.jpg)

*Settings - Matrix theme*

![Settings Crimson theme](dedseclab/24.jpg)

*Settings - Crimson theme*

![Settings Midnight theme](dedseclab/25.jpg)

*Settings - Midnight theme*

![Settings Amber theme](dedseclab/26.jpg)

*Settings - Amber theme*

![Settings](dedseclab/27.jpg)

*Settings - theme, connection URL, preferences*

![About](dedseclab/28.jpg)

*About - version and client info*

![SSH DedSec Access Gate](dedseclab/29.jpg)

*SSH DedSec Access Gate - Enter Lab / Decline and Exit*

![SSH lab home menu](dedseclab/30.jpg)

*SSH lab home menu - account, tickets, chat, tools*

![SSH IP Tools](dedseclab/31.jpg)

*SSH IP Tools category - Dns Lookup, Nmap, Vpn Puller, and more*

![SSH VPN Tools And Puller Menu](dedseclab/32.jpg)

*SSH VPN Tools And Puller Menu - game / console IP pullers*

![SSH traffic watch page 1](dedseclab/33.jpg)

*SSH traffic watch - calls and parties (page 1/11)*

![SSH traffic watch page 2](dedseclab/34.jpg)

*SSH traffic watch - console and Call of Duty games (page 2/11)*

![SSH traffic watch page 3](dedseclab/35.jpg)

*SSH traffic watch - Steam, Minecraft, Battlefield (page 3/11)*

![SSH traffic watch page 4](dedseclab/36.jpg)

*SSH traffic watch - EA, Rocket League, Rust, Valheim (page 4/11)*

![SSH traffic watch page 5](dedseclab/37.jpg)

*SSH traffic watch - Terraria, Factorio, Quake, broad UDP/TCP (page 5/11)*

![SSH traffic watch page 6](dedseclab/38.jpg)

*SSH traffic watch - ARK, Fortnite, Apex, Valorant (page 6/11)*

![SSH traffic watch page 7](dedseclab/39.jpg)

*SSH traffic watch - GTA Online / FiveM, R6, PUBG, Destiny 2, Sea of Thieves (page 7/11)*

![SSH traffic watch page 8](dedseclab/40.jpg)

*SSH traffic watch - Palworld, Enshrouded, DayZ / Arma, Project Zomboid, 7 Days to Die (page 8/11)*

![SSH traffic watch page 9](dedseclab/41.jpg)

*SSH traffic watch - Conan Exiles, Don't Starve, Stardew, Dead by Daylight, Phasmophobia (page 9/11)*

![SSH traffic watch page 10](dedseclab/42.jpg)

*SSH traffic watch - Sons of the Forest, V Rising, Helldivers 2, League of Legends, Overwatch (page 10/11)*

![SSH traffic watch page 10 alternate](dedseclab/43.jpg)

*SSH traffic watch - Sons of the Forest, V Rising, Helldivers 2, League of Legends, Overwatch (page 10/11 alternate)*

![SSH traffic watch page 11](dedseclab/44.jpg)

*SSH traffic watch - War Thunder, No Man's Sky, Fallout 76 (page 11/11)*

![FiveM / GTA server puller](dedseclab/45.jpg)

*FiveM / GTA server puller*

![SSH admin menu](dedseclab/admin_menu.jpg)

*SSH admin menu (`dedsecuser` wrapper) - privacy-blurred*

![Owner wrapper](dedseclab/owner_wrapper.jpg)

*Owner wrapper menu - privacy-blurred*

![Root owner menu](dedseclab/root_ownner_menu.jpg)

*Root owner menu - privacy-blurred*

---

## Tech stack

| Layer | Choice |
|-------|--------|
| Language / UI | Python 3.12+, **PyQt6** |
| HTTP / TLS | `requests` + CA pin (`core/tls.py`, `assets/lab_ca.pem`) |
| VPN | OpenVPN (`.ovpn` profiles **you** supply) |
| Geo | Custom lab `/api/ipcheck/lookup` + public ip-api.com / local GeoIP |
| Build | **Nuitka** (`build.py`) -> standalone `DedSecLab.exe` |
| Installer | **Inno Setup 6** (`installer/DedSecLab.iss`) |
| Backend | FastAPI-style `app_api.py` + OpenVPN + SSH ForceCommand wrappers |

Runtime deps: `DedSecLabAPP_Beta/requirements.txt`. Build deps: `requirements-build.txt`.

---

## Quick start (app)

See **[INSTALL_APP.md](INSTALL_APP.md)** for the full guide.

```text
cd DedSecLabAPP_Beta
python -m venv venv
.\venv\Scripts\pip install -r requirements.txt
.\venv\Scripts\python app.py
```

Or build a Windows installer with `build.py` (Nuitka) then `installer/build_installer.ps1` (Inno Setup).

### `REQUIRE_VPN_GATE`

In `DedSecLabAPP_Beta/core/config.py`:

```python
REQUIRE_VPN_GATE = False   # default: open the lab UI without VPN
```

Set `REQUIRE_VPN_GATE = True` when you have your own `.ovpn` profiles and want the gate before login.

Optional geo enrichment for the IP Database page:

```text
set IPAPI_KEY=your_ip_api_pro_key
```

...or set `ipapi_key` in `%APPDATA%\DedSecLab\config.json`. Never commit the key.

---

## Server side / self-hosting

The VPS-side code lives under `opt/secure-scripts/dedsec-labNEW/` (SSH wrappers, lab API, OpenVPN bridge helpers).

### Multi-VPS / unlimited VPN locations

You are **not** stuck with four VPNs. The gate ships four example regions (France / Canada / USA / UK), but you can deploy the same server tree on **as many VPS hosts as you want**. Each VPS can run OpenVPN + the lab API as another location. In the VPN gate use **Add location (.ovpn)** and point the client at that profile / API.

The author runs this on **[OVH](https://www.ovh.com/)** and **[Linode](https://www.linode.com/)** (Akamai). Both have strong DDoS protection and a **network / provider firewall** in front of the VPS's own firewall - useful when the lab API and OpenVPN sit on the public edge.

Practical scale-out steps: **[INSTALL_VPS.md](INSTALL_VPS.md#scale-out-more-vps--more-vpn-locations)** and **[SERVER_SETUP.md](SERVER_SETUP.md)**.

| Doc | Purpose |
|-----|---------|
| **[README_SERVER.md](README_SERVER.md)** | Server front page - trust model & highlights |
| **[INSTALL_VPS.md](INSTALL_VPS.md)** | Step-by-step bring-up (**keep a second SSH window open**) |
| **[SERVER_SETUP.md](SERVER_SETUP.md)** | Architecture, sshd Match, whitelist, API, geo, TLS |
| **[FEATURES.md](FEATURES.md)** | Complete client + server inventory |

Private OpenVPN profiles, production `access_rules.json`, Discord webhooks, and TLS private keys stay on **your** machine - they are not in this tree.

---

## License

See `installer/LICENSE.txt` / `installer/LICENSE_AND_TERMS.txt` for the packaging license text shipped with the Windows installer. If you redistribute a fork, keep the ethical-use disclaimer visible and generate your own Inno `AppId`.

---

## Disclaimer

DedSecLab is for **defensive / authorised lab** work. You follow local law and the rules of any network you touch. Unauthorised access, harassment, DDoS, fraud, or abuse of networking / console-related tools is not supported.
