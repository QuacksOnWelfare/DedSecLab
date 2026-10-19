# DedSecLab - Feature Inventory

**Purpose:** full list of what the DedSecLab Windows app and server stack do (same spirit as [DedSecCCTV](https://github.com/QuacksOnWelfare/DedSecCCTV)).

**App version in sources reviewed:** `1.0.6` (`APP_VERSION` in `core/config.py` / `core/updater.py`).

**Not included here:** secrets, tokens, passwords, private keys, or real public exit IPs. Where those exist in code, this file names the **variable / file** only.

Items marked **(unverified)** are not fully confirmed, or exist as dead/unwired code.

---

## One-line summary

DedSecLab is a **VPN-gated Windows desktop client** (PyQt6): connect over OpenVPN, sign in to a private lab API, then use account, VPN, IP database, terminal, networking tools, settings, and updates. The gate ships four example regions; you can add **unlimited** locations by deploying more VPS hosts. Keep your OpenVPN profiles, lab CA, and private API hosts out of the repo; the code uses placeholders so each deployment supplies its own configs.

---

## Tech stack

| Layer | Choice |
|---|---|
| Language / UI | Python 3.12+ (venv), **PyQt6** (~6.11) |
| HTTP / TLS | `requests` + central pin helper in `core/tls.py` |
| Crypto / secrets | `cryptography`, Windows Credential Manager via `keyring` (optional), DPAPI fallback in `core/secure_store.py` |
| System metrics | `psutil` |
| VPN | OpenVPN GUI / `openvpn.exe` driven from the VPN gate; `.ovpn` profiles |
| Build | **Nuitka** standalone (`build.py` -> `DedSecLab.exe`) |
| Updater binary | Separate Nuitka build (`build_updater.py` / `updater.py`), shipped **hidden** as `assets/dsl_upd.bin` (not a visible `DedSecLabUpdater.exe`) |
| Installer | **Inno Setup 6** (`installer/DedSecLab.iss`) - per-user under `%LOCALAPPDATA%\Programs\DedSecLab` |
| Backend (private) | FastAPI-style APIs on each VPN node (`app_api.py`) behind the lab VPN |

**Runtime deps** (from `requirements.txt`): PyQt6, requests, urllib3, psutil, cryptography, certifi, cffi; `keyring` appears as an optional/garbled line in some copies - treat as **intended** for Credential Manager storage (unverified whether always installed).

---

## App flow (how a session starts)

Controlled by `REQUIRE_VPN_GATE` in `core/config.py` (**default: `False`** - open the lab UI without VPN; set `True` to restore the VPN-locked product flow).

1. **Splash** - frameless welcome + logo (`app.py`); fade in/out; animated backdrop when `ui/fx.py` SplashFx is wired.
2. **Single-instance guard** - `pages/single_instance.py`; second launch warns / raises existing window.
3. **VPN Gate** (only when `REQUIRE_VPN_GATE=True`) - `core/dedsec_vpn_gate.py` (`VpnGate`): choose region, connect OpenVPN, system tray, toasts. Lab unlocks only when the tunnel (or router tunnel) is up. When the flag is `False`, this step is skipped and the main window opens directly.
4. **Main window** - `main_window.py`: login card -> after success, large frameless DedSec Lab shell with sidebar pages (`pages/main_app_page.py`).
5. Closing / VPN down can hide the lab again when the gate is enabled (gate signals `vpn_down` / relaunch).


---

## Desktop shell & chrome

- Frameless window with custom title bar (min / "max"->design size / close).
- Login uses a compact rounded card; main app opens at a large design size (up to ~2560-1600, clamped to the screen).
- Edge resize when not maximised / not on login.
- DedSec dark/cyan visual language; click **ripple** FX (`ui/fx.py`) and theme-aware QSS (`ui/styles.py`).
- Buttons use pressed-state feedback (flat, no thick under-accent) across app / login / VPN gate (recent source work).
- Windows DWM caption tinting helper on the main window (native caption colours).

---

## Themes

Configured in `core/config.py` + `ui/styles.py`:

| Key | Label (UI) | Notes |
|---|---|---|
| `default` | Default | Original DedSec look (cyan on near-black) |
| `dark` | Dark | Deeper / blacker variant |
| `light` | Light | Readable light palette |
| `matrix` | Matrix | Palette theme (green accent) |
| `crimson` | Crimson | Palette theme |
| `midnight` | Midnight | Palette theme |
| `amber` | Amber | Palette theme |
| `oled` | OLED Black | Palette theme |

Theme is persisted in `%APPDATA%\DedSecLab\config.json` (`theme` / `theme_schema`). Wallpaper / logos can be remapped for light and palette themes (`themed_wallpaper`, light applogo).

---

## Pages & modules (sidebar)

Sidebar order in `pages/main_app_page.py`:

### 1. Dashboard (`pages/dashboard_page.py`)
Real-time overview: server/VPN pills, local CPU/RAM/disk-style status from the client, VPN connection summary, access & security messaging, simple network topology blurb, session info (role, VPN IP, terminal auth model).

### 2. My Account (`pages/account_page.py`)
Profile from login payload: display name, role, username, Discord name, VPN IP, region, subscription days left / expiry, security overview, session lines. **Change password** form -> `POST /api/change-password` (requires VPN + session).

### 3. Xbox (`pages/vpn_page.py`) - high level only
Sidebar label **"Xbox"**. UI titled around Xbox Live party tooling (token capture / validate / crash-party style actions; optional Fiddler helpers). Factually: a client-side Xbox Live-related tool page. **No usage instructions here.** Present in the product; treat carefully for any public announcement.

### 4. VPN (`pages/lab_vpn_page.py`)
In-lab VPN status page: map hero, connected country/flag, protocol line read from the active `.ovpn`, list of the four locations. Connect/switch is meant to happen in **DedSec VPN** (the gate). Reflects **router mode** when the PC is on the lab tunnel via a router (shows that server; disconnect in-app is locked because it cannot tear down the router's tunnel).

### 5. IP Database (`pages/ip_database_page.py`)
Paginated threat-intel style IP table from the lab API (`/api/ips`, add, delete). Add-IP dialog **auto-enriches** country / region / city / ISP / ASN:
- **Primary (pro):** `https://pro.ip-api.com/line/...` when `IPAPI_KEY` env or `config.json` -> `ipapi_key` is set (never hardcode the key in source).
- **Without a key:** enrichment is disabled in this page (manual fields still work); other surfaces use the free public endpoint (see **IP geolocation** below).
Theme-aware table colours.

### 6. Terminal (`pages/terminal_page.py` + `pages/dedsec_cmd.py`)
VPN-only secure shell:
- Mint short-lived token: `POST /api/terminal-token`
- Connect: `WSS .../ws/terminal` with `Authorization: Bearer <token>`
- Inline terminal page **or** popup **DedSec CMD** window (`dedsec_cmd.py`) with ANSI stream handling, password-echo masking heuristics, TLS pin acceptance via `core/tls.py`.

### 7. Changelog (`pages/actions_page.py`)
Hard-coded changelog cards (app patches, website, security, bug fixes). Not fetched from the server in the copies reviewed.

### 8. Logs (`pages/logs_page.py`)
In-memory client activity / security event log with stats, filter/export affordances, "stored only in memory unless exported" note.

### 9. Networking (`pages/networking_page.py` + panels)
Tabbed hub:

| Tab | What it does for the user |
|---|---|
| **Network Tools** | Speed test (multi-stream Cloudflare samples + public IP/geo), **VPN app bypass** whitelist (pick running processes; PowerShell rules; seeded by `vpn_app_whitelist.json`), flush DNS, **console share steps** (how to share VPN to a console over Ethernet - guidance UI). |
| **Lag Switch** | "Network impairment engine" - latency / loss / rate / reorder / tamper style controls driven by lab API `/api/net-emulate/*`, presets, hotkey start/stop. |
| **Macros** | Record/play keyboard & mouse macros and autoclicker (`pages/macro_panel.py`, Windows SendInput). Local profiles under app data. |
| **Password Cracker** | John the Ripper front-end (`pages/john_panel.py`) - see Offensive-tool modules. |
| **Shodan** | Shodan intelligence front-end (`pages/shodan_panel.py`) - see Offensive-tool modules. |
| **Surveillance** | Live IP check / monitor / Discord webhook / nmap window (`pages/ipcheck_panel.py`) - see Offensive-tool modules. |
| **IP Lookup** | Geo IP via the **custom lab API** (`POST /api/ipcheck/lookup` after token mint) - see **IP geolocation**. (`pages/geo_ip_panel.py`). |
| **TCP Connections** | Local TCP table; end process / open file location (`pages/tcp_monitor_panel.py`). |

### 10. Settings (`pages/settings_page.py`)
Full-page settings (fills former dead space):
- **Appearance** - theme picker with swatches.
- **Connection** - server URL field, Test Connection.
- **Preferences** - auto-connect, save username, desktop notifications, animations (and related toggles).
- **Updates** - installed version, Check for Updates, Open Website (`https://your-site.example` allow-listed).
- **Data & storage** - config path, **Open Install Folder**, **Open App Data**, Reset local settings.
- **About / Status** side cards.

### 11. About (`pages/about_page.py`)
Brand blurb, version badge, "system profile", client capabilities list (OpenVPN setup, router + GUI support, etc.), terminal tool system notes. Some version strings in the About UI still say `v1.0.0` in older copy - **(unverified)** whether live PC About was bumped to 1.0.6.

### Sidebar footer
- **Disconnect** - ends session / closes lab (styled as danger/red to match window close).

---

## VPN Gate (pre-lab window)

**File:** `core/dedsec_vpn_gate.py`.

**For the user:**
- Standalone frameless VPN UI before the lab unlocks.
- Four **example** built-in regions (`DEFAULT_SERVERS` / `BUILTIN_ORDER`): **France** (`eu`), **Canada**, **United States**, **United Kingdom**. Add more with **Add location (.ovpn)**; deploy extra VPS hosts for unlimited locations.
- Power connect/disconnect, Open Lab when secure, settings sheet for `.ovpn` paths / add location.
- Flag + map artwork per region; load % display (cosmetic defaults in `DEFAULT_SERVERS`).
- **Router mode:** if the machine already has a `10.8.0.x` lab tunnel (e.g. OpenVPN on a router), the gate detects it, maps the **public exit** -> region via `_EXIT_TO_SID`, shows "Router connected * \<server\>", and **locks in-app disconnect** (cannot kill the router's tunnel from the PC app).
- **Notifications:** tray / toast; product intent is **one** VPN toast on open ("Router connected * \<server\>"), not repeated disconnect spam while using the main app (recent fix).
- System tray integration (`QSystemTrayIcon`).
- Public IP probe via `api.ipify.org` / `ifconfig.me` when resolving which exit is live.
- Lab API reachability probe against the pinned lab host (gateway on the VPN) using `lab_ca.pem`.

**Bundled profile names expected:** `eu.ovpn`, `canada.ovpn`, `usa.ovpn`, `uk.ovpn` (paths resolved from config / app data / embed - see Server-dependent pieces).

---

## Login & account security

**File:** `pages/login_page.py` + `core/server.py` + `hardware_locker/fingerprint.py` + `core/secure_store.py`.

- **First-run wizard** - welcome, terms acceptance, "almost ready".
- Stages: detect VPN -> OpenVPN install / pick `.ovpn` / connect -> account login unlocks only when VPN is up.
- Username + password; **Remember password** stored via secure store (not plaintext `config.json`).
- Device lock: login sends hardware **fingerprint** + PC label + client version; server may return `device_pending` / `device_revoked` (locker frames on login).
- Display device ID from `get_display_id()`.
- Optional **min-version / outdated** locker with in-login update download progress.
- Website link on footer.
- Hides visible updater exe names if present (`DedSecLabUpdater.exe` / `updater.exe`) - product ships updater as hidden blob instead.

---

## Self-updater

**Files:** `core/updater.py`, root `updater.py`, `build_updater.py`, Nuitka -> hidden `assets/dsl_upd.bin`.

- Checks `GET {server_url}/api/update/version` over pinned TLS.
- Manifest fields: version, min_version, notes, download_url (same-origin https only), sha256, optional Ed25519 `signature` (`UPDATE_SIGNING_PUBKEY_B64` placeholder in client).
- Downloads zip with size cap; verifies hash (and signature when pubkey set); applies via separate updater process (`APPLY_FLAG`); preserves user files listed in `KEEP_NAMES` / `KEEP_DIR_NAMES` (config, lab CA, logs, etc.).
- Website URL from manifest must be on `ALLOWED_WEBSITE_HOSTS`.

---

## Installer

**Files:** `installer/DedSecLab.iss`, `build_installer.ps1`, wizard assets, `version.inc`.

- Windows setup wizard with DedSec wizard images (large + small, @2x, BMP fallbacks).
- **Per-user only** (`PrivilegesRequired=lowest`); no "install for all users" mode dialog.
- Default dir: `{localappdata}\Programs\DedSecLab`.
- Desktop + Start Menu shortcuts; license / terms / info-before pages.
- Copies Nuitka standalone tree; re-applies **Hidden+System** on `assets` / `dsl_upd.bin` after install (Inno skips hidden sources at compile time, so build scripts un-hide before compile).

---

## Security hardening (client)

| Mechanism | Where | User-facing effect |
|---|---|---|
| Lab CA pin (fail closed) | `core/tls.py`, `assets/lab_ca.pem` | Lab HTTPS/WSS only if pin present; no blanket `verify=False` |
| TLS - 1.2; hostname relax only for lab CN-without-SAN | `core/tls.py` | Works with lab certs that use VPN IP CN |
| Secure secret storage | `core/secure_store.py` | Passwords/secrets in Credential Manager / DPAPI, not plaintext config |
| Plaintext secrets never saved | `ConfigManager` | `password` / `ssh_password` never persisted in `config.json` |
| Atomic config write | `core/config.py` | Avoids half-written config |
| Update same-origin + sha256 (+ optional Ed25519) | `core/updater.py` | Harder to feed arbitrary update zips |
| Device fingerprint | `hardware_locker/fingerprint.py` | Server-side device approval workflow |
| Authenticode helper | `core/winutil.py` | Helpers to inspect/verify signed binaries **(unverified)** how widely used in UI paths |
| Single instance | `pages/single_instance.py` | One lab UI at a time |

Historical issues and remediations are documented in `SECURITY_REPORT.md` / `FIX_NOTES.md` (audit notes, not user features).

---

## Offensive-tool modules (factual, high level)

These appear under **Networking** (and Xbox as its own sidebar page). Descriptions only - no how-to.

| Module | File | Role in the product |
|---|---|---|
| **John the Ripper** | `pages/john_panel.py` | VPN-gated API UI for server-side John: status, start attack, show cracked, wordlist upload, **CUPP** wordlist generation from a profile form. One-time tokens via `/api/john/*`. |
| **CUPP** | inside John panel | "Common User Passwords Profiler" style wordlist generator endpoint `/api/john/cupp`. |
| **Shodan** | `pages/shodan_panel.py` | VPN-gated Shodan proxy: status/credits, count, search, host, DNS, resolve, reverse; plus "open on Shodan [WEB]" browser links. Tokens via `/api/shodan/*`. |
| **nmap** | `pages/ipcheck_panel.py` (`NmapWindow`) | Port-scan start/stop/status through `/api/ipcheck/nmap/*` after confirm dialog. |
| **IP surveillance / live ping** | `pages/ipcheck_panel.py` | Track IPs, background monitor, live track, traceroute, lookup, Discord webhook test - all `/api/ipcheck/*`. |
| **Xbox** | `pages/vpn_page.py` | Xbox Live party-related client tool (see above). |

**Responsible-use note:** do not expand these offensive modules; keep any public description factual and responsible.

---

## Present but unwired / legacy (unverified in live nav)

| Item | Notes |
|---|---|
| `pages/admin_tools_page.py` | Admin control-center UI exists; **not** in current sidebar wiring. |
| `pages/cctv_page.py` | Private RTSP wall (libVLC pool); **commented out** of Networking - CCTV is a separate app (DedSecCCTV). |
| `pages/ip_sniffer_page.py` | "IP sniffer / VPN puller"; **commented out** of sidebar. |
| Older About version strings | May still say 1.0.0 while `APP_VERSION` is 1.0.6. |

---

## Local data locations (Windows)

| Path | Contents |
|---|---|
| `%APPDATA%\DedSecLab\config.json` | Non-secret prefs (server_url, theme, username if saved, ovpn path, lab_ca_path, ...) |
| `%APPDATA%\DedSecLab\` + secure store files | DPAPI blobs / migrated secrets |
| Windows Credential Manager service `DedSecLab` | Preferred secret backend |
| `%LOCALAPPDATA%\Programs\DedSecLab\` | Per-user install (exe, DLLs, assets including hidden updater blob) |
| Gate embed / ovpn config | `embedded_config.json` under app data (gate); `.ovpn` paths per server id |

---

## Public third-party endpoints the client may call

(Not DedSec private API; useful for trust/transparency sections like DedSecCCTV's README.)

- `https://api.ipify.org`, `https://ifconfig.me/ip`, `https://icanhazip.com` - public IP
- `http://ip-api.com/...` (free) / optional `https://pro.ip-api.com/...` (key via `IPAPI_KEY` / `ipapi_key`) - geo/ASN enrichment & VPN-gate country detect
- Cloudflare speed-test sample hosts (Networking speed test)
- `https://your-site.example` - product website (allow-listed)
- `https://openvpn.net/community/` - OpenVPN download link constant
- Shodan website links opened in the system browser (user's own Shodan login)
- Xbox / Microsoft Store URIs from the Xbox page

---

## Server-dependent pieces

> These client values point at your server. Set them to your own hosts and keys before deploying; keep real profiles, CA private keys, and exit IPs out of the repo.

### Lab VPN & API host

| Piece | Where it lives | Notes |
|---|---|---|
| Default API base `server_url` | `core/config.py` `DEFAULTS["server_url"]`; also `DEFAULT_SERVER_URL` in `pages/login_page.py`, `core/updater.py` | Points at the **lab VPN gateway** HTTPS port (pattern `https://<gateway>:8443`). All four regions share that VPN-side API IP in the current design. |
| Lab host set for TLS pin | `core/tls.py` -> `DEFAULT_LAB_HOSTS` | VPN gateway hostname/IP treated as "lab URL". |
| Config override | `%APPDATA%\DedSecLab\config.json` -> `server_url`, `lab_ca_path` | |
| Env override for CA | `DEDSEC_LAB_CA` | |

### TLS pin

| Piece | Where |
|---|---|
| CA file name | `assets/lab_ca.pem` (`CA_FILENAME` in `core/tls.py`) |
| Fail-closed behaviour | `lab_ca_path()`, `http_request()`, `qt_ssl_configuration_for()`, `qt_accept_lab_ssl_errors()` |

### OpenVPN profiles & region metadata

| Piece | Where |
|---|---|
| Built-in server table | `DEFAULT_SERVERS` in `core/dedsec_vpn_gate.py` (ids `eu` / `canada` / `usa` / `uk`; names France / Canada / United States / United Kingdom) |
| Public exit -> region map | `_EXIT_TO_SID` in `core/dedsec_vpn_gate.py` (set your own public VPN exit IPs here) |
| Host display helpers | `_HOST_HINTS` / similar beside `DEFAULT_SERVERS` (also IP-bearing) |
| Expected profile filenames | `eu.ovpn`, `canada.ovpn`, `usa.ovpn`, `uk.ovpn` |
| Per-server ovpn paths in gate config | gate `embedded_config.json` / Settings fields (`canada_path`, `usa_path`, ...) |
| Router detection | local `10.8.0.x` addresses + ping to VPN gateway + exit IP probe |

### Website / branding hosts

| Piece | Where |
|---|---|
| `DEFAULT_WEBSITE_URL`, `ALLOWED_WEBSITE_HOSTS` | `core/updater.py` (`your-site.example`) |
| Hardcoded Open Website / login link | `pages/settings_page.py`, `pages/login_page.py` |

### Update channel

| Piece | Where |
|---|---|
| Version check | `GET /api/update/version` |
| Download | `GET /api/update/download` (and manifest `download_url`, same origin) |
| Client pubkey placeholder | `UPDATE_SIGNING_PUBKEY_B64` in `core/updater.py` |
| Server signing | Ed25519 signature over the update zip (your key) |
| Hidden updater blob | `assets/dsl_upd.bin` (built from `DedSecLabUpdater.exe`) |

### Auth & account API

| Endpoint | Client |
|---|---|
| `POST /api/login` | `core/server.py` (fingerprint, label, version) |
| `POST /api/change-password` | `core/server.py` / Account page |
| `GET /api/status`, `GET /api/me` | present on server; client usage varies |
| Device pending/revoked reasons | login locker frames |

### IP database API

| Endpoint | Client |
|---|---|
| `GET /api/ips` | `core/server.py` / IP Database page |
| `POST /api/ips/add` | |
| `DELETE /api/ips/{ip}` | |

### Terminal

| Endpoint | Client |
|---|---|
| `POST /api/terminal-token` | `terminal_page.py`, `dedsec_cmd.py` |
| `WSS /ws/terminal` | same |
| Auth | short-lived Bearer token, one-shot |

### John / CUPP

| Endpoints | Client |
|---|---|
| `/api/john/token`, `/status`, `/start`, `/show`, `/wordlist`, `/cupp` | `pages/john_panel.py` |

### Shodan

| Endpoints | Client |
|---|---|
| `/api/shodan/token`, `/status`, `/count`, `/search`, `/host`, `/dns`, `/resolve`, `/reverse` | `pages/shodan_panel.py` |

### IP check / nmap / webhooks

| Endpoints | Client |
|---|---|
| `/api/ipcheck/*` (token, status, ips, check, lookup, traceroute, live, monitor, settings, webhook, nmap, ...) | `pages/ipcheck_panel.py`, `pages/geo_ip_panel.py` |

### Net emulate (lag switch)

| Endpoints | Client |
|---|---|
| `/api/net-emulate/start`, `/stop`, `/status` | `pages/networking_page.py` |

### Per-region server API

Each VPN region runs its own instance of the lab API (`app_api.py`) with that region's hosts, certs, and allowlist. The route set is the same across regions (login, IPs, terminal WS, John, Shodan, ipcheck, net-emulate, updates, Discord webhook helpers). Keep live credentials, webhook URLs, and private keys in each host's own config, never in the repo.

### Other embed / whitelist files

| File | Role |
|---|---|
| `vpn_app_whitelist.json` | Default process names for VPN bypass suggestions |
| Gate `embedded_config.json` | Persisted gate server/ovpn selections |
| `assets/lab_ca.pem` | Public CA cert pin (safe to ship only if you intend that pin; private key must never ship) |
| Country flag pack under `assets/flags/` | General flags |
| Region webp/png (`fr.webp`, `gb.webp`, `us.webp`, `ca.webp`, maps) | UI art |

---

## IP geolocation (custom lab API + fallbacks)

DedSecLab uses **layered** geo lookup so the desktop client, lab API, SSH tools, and owner traffic panel stay consistent without baking private hosts into source.

### A. Custom lab geo API (primary for in-app Geo IP / Surveillance)

The Networking -> **IP Lookup** panel (`pages/geo_ip_panel.py`) and Surveillance / live-ping panel (`pages/ipcheck_panel.py`) do **not** call a public geo provider directly for interactive lookups. They talk to **your lab backend** over the pinned TLS URL (`server_url`, typically `https://YOUR_LAB_HOST:8443`):

| Step | Endpoint | Who |
|---|---|---|
| Mint short-lived token | `POST /api/ipcheck/token` | Client (VPN-gated when the product flow is on) |
| Lookup | `POST /api/ipcheck/lookup` `{token, ip}` | Client |
| Server resolve | `_ipcheck_geo()` in `app_api.py` | Lab API |

Returned fields (typical): country, country code, region, city, ISP, org, ASN / AS, plus reverse DNS on the lookup route. Failures surface in the UI without leaking stack traces.

This is a custom geo API served by the lab's own backend (`/api/ipcheck/*`). Point `server_url` at **your** API; the repo ships `YOUR_LAB_HOST` placeholders you replace.

### B. Fallback / public providers

| Surface | Primary | Fallback / notes |
|---|---|---|
| Lab API `_ipcheck_geo` | Free public **`http://ip-api.com/json/{ip}`** (no key) | N/A - this *is* the server-side resolver behind the custom API |
| IP Database page enrichment | **`https://pro.ip-api.com/line/...`** when `IPAPI_KEY` / `config.json` `ipapi_key` is set | Without a key, auto-enrichment is skipped (manual entry still works) |
| SSH IP tools (`vpn_puller.py`, `vpn_pullerv2.py`) | Pro line API when `IPAPI_KEY` env is set | On missing key / pro failure -> free **`http://ip-api.com/line/{ip}`** |
| VPN gate country detect (`core/flags.py`) | Free **`http://ip-api.com/json/{ip}`** | Used to map public exit -> region flag |
| Networking speed-test hero | Free **`http://ip-api.com/json/{ip}`** after public-IP probe (`api.ipify.org` / `ifconfig.me` / `icanhazip.com`) | |
| Owner Traffic Intelligence | Local **`geoiplookup`** (GeoIP Country Edition) + **`whois`** for ISP/org | Offline-friendly; caches in-process |

**Never commit** live `IPAPI_KEY` values, Discord webhooks, or private API hosts. Configure keys via environment / `%APPDATA%\DedSecLab\config.json` on the operator machine only.

---

## Server / VPS feature inventory

Tree: `opt/secure-scripts/dedsec-labNEW/`.

**Multi-VPS:** deploy this tree on as many hosts as you want (each = OpenVPN + lab API = another VPN location). Not limited to four. Author typically uses **OVH** and **Linode** for DDoS protection and provider/network firewalls in front of the VPS firewall. See [INSTALL_VPS.md](INSTALL_VPS.md#scale-out-more-vps--more-vpn-locations).

Deep bring-up: [SERVER_SETUP.md](SERVER_SETUP.md), [INSTALL_VPS.md](INSTALL_VPS.md), [README_SERVER.md](README_SERVER.md).

### Trust model (layers)

1. **OpenVPN bridge** - clients join a private tunnel (stock docs assume `10.8.0.0/24`). Lab API + SSH expect VPN peers, not the open internet.
2. **VPN-only SSH for `dedsecuser`** - `sshd` `Match Address` forces non-VPN sessions to `/bin/false`; VPN peers get ForceCommand -> `access_wrapper.py`.
3. **IP whitelist** - `access_rules.json` maps VPN IP -> display name, role (`standard` / `admin`), enabled flag, subscription expiry.
4. **Optional wrapper password** - `WRAPPER_PASSWORD_HASH` in `access_wrapper.py` (empty = off by default). When set, requires PBKDF2-SHA256 (or hex SHA-256) after whitelist.
5. **No-shell-exit** - wrappers/menus swallow SIGINT / SIGTSTP / SIGQUIT; block `SSH_ORIGINAL_COMMAND` and non-TTY sessions; exit only via menu option 0 / Decline.
6. **Root owner gate** - `root_owner/root_owner_wrapper.py` allowlists source / real IP from `root_access_rules.json`, then execs `root_owner_menu.py` (owner password via PBKDF2).
7. **Client TLS pin** - desktop app fails closed without your `lab_ca.pem`.

Wrappers resolve "real IP" from OpenVPN `CLIENT_LIST` in `/var/log/openvpn-status.log`.

### `access_wrapper.py` (dedsecuser ForceCommand)

- Entry portal: show session (user, role, VPN IP, region, expiry), VPN node status strip (UK / USA / CANADA / EU placeholders), service pills.
- **Enter Lab** -> `execve` `menu.py` with `DEDSEC_USER` / `DEDSEC_ROLE` / `DEDSEC_SOURCE_IP`.
- Deny paths: not whitelisted, disabled, expired, wrapper password fail, non-interactive SSH.
- Discord alert hooks via `scripts/system/discord_notify.py` (optional webhook JSON).

### `menu.py` (Enter Lab home)

Home: My Account (profile + admin-only theme picker), Updates / Announcements, Help / Tickets, General Chat, **Browse Tool Categories**, Exit.

Categories are **folder-discovered** under `scripts/` (except `system/`). `admin_tools` is hidden unless role is `admin`. Tools paginate; usage + Discord start/finish events; errors logged.

| Category (folder) | Tools (high level) |
|---|---|
| **ip_tools** | DNS lookup, FiveM/CFX finder, live traffic, Nikto runner, nmap scan, port probe, reverse DNS, **vpn_puller** / **vpn_pullerv2** (geo primary+fallback as above) |
| **misc_tools** | Live ping checker, ipcheck/nmap helper, optional Grim notes |
| **admin_tools** | SSH whitelist manager (CCD / `.ovpn` user provisioning), admin dashboard (live users, expiry, logs, notices), DNS adblock menu + daemon, maintenance / fix permissions / service manager, website blocker (per-VPN-IP dnsmasq snippets), VPN access owner menu (cooldown / webhook), ticket panel, tcpdump tool, IP spoofing helper |
| **system** (not browsable) | Discord notify, general chat, user tickets, VPN status helpers |

Also: `dedsec.py` (DedSec Crawler - SSH-friendly asset discovery / SQLite), `ip_database_admin.py`, `vps_admin_tool.py` / hardware locker admin, `vpn-adblock.py`, `json_manager.py`, `port_monitor.py`.

### Root owner panel

| Piece | Role |
|---|---|
| `root_owner_wrapper.py` | ForceCommand gate: block remote commands / non-TTY; allowlist; Discord login/deny |
| `root_owner_menu.py` | Password unlock -> Traffic Intelligence, Launch Lab Menu as VPN identity, System Security Scanner, Misc Tools browser, Root Logs, Backup Lab (`tar.gz`), Danger-zone Root Shell (YES confirm) |
| `traffic_intelligence/` | Scapy-based watch panel; local `geoiplookup` + `whois`; SQLite attacker DB; exports |
| `misc_tools/` drop-in | Any `.py` / `.sh` dropped here appears in Misc Tools: **api_manager** (lab API systemd), **hwid_locker**, **ssh_guard** (port / blocklist / auth log), **openvpn_tcp** service helpers, **proxychains_menu**, **sftp_maintenance_window**, **tcp-dumps**, **ovh_ddos_discord**, camera helper scripts (lab-only; authorised use) |

### Lab API (`app_api.py`) - route groups

| Group | Routes (summary) |
|---|---|
| Auth / session | `POST /api/login`, `POST /api/change-password`, `GET /api/status`, `GET /api/me` |
| Updates | `GET /api/update/version`, `GET /api/update/download` |
| IP database | `GET /api/ips`, `POST /api/ips/add`, `DELETE /api/ips/{ip}` |
| Terminal | `POST /api/terminal-token`, `WSS /ws/terminal` |
| John / CUPP | `/api/john/token|status|start|show|wordlist|cupp` |
| Shodan proxy | `/api/shodan/token|status|count|search|host|dns|resolve|reverse` |
| Net emulate | `/api/net-emulate/start|stop|status` |
| IP check / geo / nmap | `/api/ipcheck/*` (token, status, ips, bulk, check, **lookup**, traceroute, live, monitor, settings, webhook, nmap, webhook/test) |

All sensitive routes validate the caller as a whitelisted VPN peer (`validate_vpn_user`). Short-lived one-shot tokens gate John / Shodan / ipcheck / terminal.

### Hardware locker

`hardware_locker/` - device fingerprint DB, pending / approve / revoke workflow, Discord HWID alerts, min/latest app version gates used by the Windows client login lockers.

### Install / security helpers

`install.sh`, `setup_security.sh`, `fix_permissions.sh`, example JSON (`access_rules.example.json`, `ip_database.example.json`), `certs/README.md`, `ssh_config.txt` (repo root) documenting Match / ForceCommand patterns.

---

## Project layout (client, simplified)

```
DedSecLabAPP_Beta/
--- app.py                 # splash -> VpnGate -> MainWindow
--- main_window.py         # frameless shell, login - main stack
--- build.py               # Nuitka release/debug
--- build_updater.py
--- updater.py             # apply-update helper entry
--- requirements.txt
--- vpn_app_whitelist.json
--- assets/                # logos, wallpaper, lab_ca.pem, flags/, hidden dsl_upd.bin
--- core/
|   --- config.py
|   --- server.py          # MockServerClient -> real HTTPS lab API
|   --- tls.py
|   --- secure_store.py
|   --- updater.py
|   --- dedsec_vpn_gate.py # VPN gate window + router mode
|   --- flags.py
|   +-- winutil.py
--- hardware_locker/
|   +-- fingerprint.py
--- pages/                 # all sidebar pages + panels
+-- ui/
    --- styles.py          # themes + QSS
    --- widgets.py
    +-- fx.py              # splash + click ripple
```

Installer sources live beside the app under `installer/`.

