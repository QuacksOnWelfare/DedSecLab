# DedSecLab - Server-Side Setup Guide

This guide is for standing up **your own** DedSecLab back end from the server code in this repo.  
It is grounded in the real files under `opt/secure-scripts/dedsec-labNEW/` and the PyQt6 client under `DedSecLabAPP_Beta/`.

**Placeholders only** - never paste production hosts, IPs, keys, certs, or Discord webhooks into a public repo:

| Placeholder | Meaning |
|-------------|---------|
| `YOUR_LAB_HOST` | Hostname or IP clients use for the lab API (often your VPN tunnel IP) |
| `YOUR_LAB_VPN_IP` | Lab's address on the VPN (commonly `10.8.0.1` on *your* server) |
| `YOUR_VPN_SERVER` | Public IP/DNS of the OpenVPN daemon |
| `YOUR_VPN_EXIT_*` | Public exit IPs per region (France / Canada / USA / UK) |
| `YOUR_CLIENT_VPN_IP` | A user's assigned tunnel IP (e.g. `10.8.0.4`) |
| `YOUR_WEBHOOK_*` | Discord webhook id/token |
| `YOUR_SHA256_PASSWORD_HASH` | App / owner password hash |

Related docs in this tree: `access_rules.example.json`, `certs/README.md`, `ovh-ddos-discord/README.md`.

---

## 1. Architecture overview

```
+--------------------------+         OpenVPN (UDP/TCP)         +-----------------------------+
|  Windows PyQt6 client    | --------------------------------- |  Your VPS                   |
|  DedSecLabAPP_Beta/      |         tunnel 10.8.0.x           |                             |
|                          |                                   |  OpenVPN server             |
|  * VPN gate (optional)   |----- HTTPS :8443 (pinned CA) -----|  lab API  app_api.py        |
|  * Login / tools UI      |----- WSS  /ws/terminal -----------|  (uvicorn + TLS)            |
|  * Terminal (Bearer)     |                                   |                             |
+--------------------------+                                   |  sshd                       |
                                                               |   Match Address 10.8.0.0/24 |
                                                               |   ForceCommand wrappers     |
                                                               +-----------------------------+
```

**Trust model (headline):**

1. **OpenVPN is the bridge.** The client reaches the lab API and SSH as a `10.8.0.x` peer. The API is not meant to be a public internet service.
2. **SSH is VPN-only for `dedsecuser`.** In `ssh_config.txt` / `sshd_config`, non-VPN connections for that user are forced to `/bin/false`. Root always hits the owner ForceCommand, which **refuses to load the menu** unless the source IP is allowlisted.
3. **Every API call is gated by VPN IP allowlist** (`access_rules.json` -> `validate_vpn_user()` in `app_api.py`). Unknown `10.8.0.x` peers get `"VPN IP is not whitelisted"`.
4. **TLS is pinned.** The client verifies the lab with `assets/lab_ca.pem` (`core/tls.py`). Missing CA -> fail closed.

Keeping your **`.ovpn` profiles private** is what keeps the private API private: without a tunnel address that is whitelisted, login, tools, and SSH menus never open.

---

## Scale out (many VPS / many VPN locations)

Nothing in this stack hard-limits you to four VPNs.

| Idea | Practice |
|------|----------|
| **1 VPS = 1 location** | Copy `dedsec-labNEW/` to each host; run OpenVPN + `app_api.py` + SSH wrappers there |
| **Client** | VPN gate **Add location (.ovpn)** for each new profile; set Server URL / `lab_ca.pem` for that API |
| **Allowlists** | Each host keeps its own `access_rules.json` (and root allowlist) for its tunnel peers |
| **Subnets** | Stock docs use `10.8.0.0/24` per server - fine if clients only connect to one host at a time; if you dual-connect, plan non-overlapping tunnels |

**OVH** and **Linode** are what the author uses: good DDoS protection plus a **network/provider firewall** separate from ufw/iptables on the VM. Put OpenVPN and the lab API port behind that provider firewall when you can.

Bring-up checklist per host: [INSTALL_VPS.md](INSTALL_VPS.md).

## 2. OpenVPN bridge

### 2.1 Addressing

Typical layout (you choose the subnet; the stock client and wrappers assume **`10.8.0.0/24`**):

| Role | Address | Notes |
|------|---------|--------|
| Lab / API / VPN gateway | `YOUR_LAB_VPN_IP` (often `10.8.0.1`) | Client default `server_url` points here over TLS |
| Client peers | `10.8.0.2` ... | Each user gets a stable IP that **is the allowlist key** |
| OpenVPN public endpoint | `YOUR_VPN_SERVER` | What appears in client `.ovpn` `remote` lines |

`sshd` Match for lab users is literally `Address 10.8.0.0/24` (see sec 3). If you change the VPN subnet, update sshd Match, client defaults, and docs together.

### 2.2 Region -> exit IP map (client)

In `DedSecLabAPP_Beta/core/dedsec_vpn_gate.py`:

- `DEFAULT_SERVERS` / `BUILTIN_LABELS` - UI slots (France / Canada / USA / UK) with `host` placeholders `YOUR_VPN_EXIT_*`.
- `_EXIT_TO_SID` - maps the machine's **public exit IP** (from `api.ipify.org` / `ifconfig.me`) back to a region id (`eu`, `canada`, `usa`, `uk`) so the UI can show which region the router/VPN is on.

If you run your own server:

1. Run (or rent) exit nodes whose public IPs you control.
2. Put those public IPs into `_EXIT_TO_SID` and `DEFAULT_SERVERS[*].host`.
3. Ship one `.ovpn` per region (or one profile that selects the right remote) - **generated by you**, never committed.

### 2.3 What you must generate yourself

Use Easy-RSA / your PKI (install.sh already apt-installs `openvpn` + `easy-rsa`):

```text
ca.crt / ca.key          # your CA (keep key private)
server.crt / server.key  # OpenVPN server
dh.pem                   # Diffie-Hellman (or use ECDH only)
client.crt / client.key  # per user (or per device)
ta.key                   # optional tls-auth / tls-crypt
```

Example **server** sketch (`/etc/openvpn/server.conf`) - placeholders only:

```conf
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"   # optional
keepalive 10 120
status /var/log/openvpn-status.log        # wrappers read CLIENT_LIST from here
verb 3
```

Example **client** `.ovpn` sketch (keep private):

```conf
client
dev tun
proto udp
remote YOUR_VPN_SERVER 1194
resolv-retry infinite
nobind
remote-cert-tls server
ca ca.crt
cert client.crt
key client.key
verb 3
```

Assign static client IPs (CCD / `ifconfig-push`) so `YOUR_CLIENT_VPN_IP` stays stable - that IP is the key in `access_rules.json`.

Wrappers resolve "real IP" via `/var/log/openvpn-status.log` `CLIENT_LIST` lines (`get_real_ip_from_vpn_status` in both wrappers). Ensure OpenVPN writes that status file.

---

## 3. SSH ForceCommand wrappers + VPN-only hardening

### 3.0 Defense-in-depth: four layers before anything useful runs

SSH into this lab is **not** "password then shell." ForceCommand + wrappers stack several gates. A connection that fails **any** layer never reaches a usable lab menu (and never falls through to a normal shell).

```
Internet / VPN peer
        |
        -
+-----------------------------------------------------------+
|  Layer 1 - Normal SSH authentication                      |
|  sshd: password and/or pubkey (see PermitRootLogin /      |
|  PasswordAuthentication / AllowUsers in ssh_config.txt)   |
+-----------------------------------------------------------+
                              | auth OK
                              -
+-----------------------------------------------------------+
|  Layer 2 - VPN + IP whitelist (connection drops if fail)|
|  * dedsecuser: Match Address 10.8.0.0/24 else /bin/false |
|    then access_wrapper.py -> access_rules.json by VPN IP |
|  * root: root_owner_wrapper.py -> root_access_rules.json |
|    owner.allowed_ips  (menu NEVER loads if not listed)  |
+-----------------------------------------------------------+
                              | IP allowlisted
                              -
+-----------------------------------------------------------+
|  Layer 3 - Wrapper / panel password                       |
|  * root: root_owner_menu.py -> auth_owner() before panel   |
|    (pbkdf2_sha256 vs owner.password_hash, 3 attempts)     |
|  * dedsecuser: VPN-locked by default; OPTIONAL second     |
|    password via WRAPPER_PASSWORD_HASH in access_wrapper   |
|    (empty = disabled). App still uses /api/login hash.    |
+-----------------------------------------------------------+
                              | password OK (owner) / Enter Lab
                              -
+-----------------------------------------------------------+
|  Layer 4 - Locked session: no shell escape                |
|  ForceCommand replaces the login shell; SIGINT/SIGTSTP/   |
|  SIGQUIT swallowed ("Use the menu to exit cleanly");      |
|  exceptions fail closed (sys.exit, never drop to bash).   |
|  Only the OWNER panel offers "Root Shell" (/bin/bash -l). |
|  dedsecuser Exit only closes the session.                 |
+-----------------------------------------------------------+
```

#### Layer 1 - Normal SSH auth

Standard `sshd` authentication (`PasswordAuthentication`, optional pubkey, `AllowUsers root dedsecuser` in the shipped `ssh_config.txt` excerpt). Stealing or guessing nothing past this still leaves layers 2-4.

#### Layer 2 - Locked to the whitelist (non-whitelisted IP drops)

Even after SSH auth succeeds, **ForceCommand** runs a Python gate instead of a shell:

| Account | Gate file | Allowlist file | On failure |
|---------|-----------|----------------|------------|
| `dedsecuser` | `access_wrapper.py` | `access_rules.json` -> `users[<vpn_ip>]` | `deny_access` -> session exit; from **non-VPN** addresses sshd already runs `/bin/false` |
| `root` | `root_owner/root_owner_wrapper.py` | `root_owner/root_access_rules.json` -> `owner.allowed_ips` (+ `owner.enabled`) | `deny("ip not allowlisted")` -> **owner menu never loads** |

Both gates also block `SSH_ORIGINAL_COMMAND` and non-TTY sessions. Root additionally compares OpenVPN `real_ip` from `/var/log/openvpn-status.log` against the same allowlist.

#### Layer 3 - Wrapper password (another secret after the whitelist)

**Root (verified in code):** after the allowlist passes, `root_owner_wrapper.py` only `execve`s `root_owner_menu.py`. That menu's entrypoint is:

```python
if __name__ == "__main__":
    if auth_owner():
        main_menu()
```

`auth_owner()` prompts for the owner password (`getpass`), verifies `owner.password_hash` as `pbkdf2_sha256$...` (`verify_hash`), allows **3 attempts**, logs/Discord-alerts success/failure, and returns without opening the panel on failure. Fill `YOUR_SHA256_PASSWORD_HASH` in `root_access_rules.json` with a real `pbkdf2_sha256` hash before going live.

**dedsecuser (SSH ForceCommand path) - VPN-locked by default; optional second password:**

- By default, after the IP whitelist, `access_wrapper.py` opens the Enter Lab portal with **no** extra password (VPN lock is enough).
- Optional: set `WRAPPER_PASSWORD_HASH` near the top of `access_wrapper.py` (empty string `""` = disabled). When set, `require_optional_wrapper_password()` runs **after** whitelist and **before** the portal (3 attempts; fail -> deny / session exit).
- Accepted hash formats: `pbkdf2_sha256$<rounds>$<salt>$<hex>` (same as owner) **or** a 64-char hex SHA-256 of the password. Example comment in-file uses `YOUR_SALT` / `YOUR_HASH_HEX` placeholders - not a real secret.
- `menu.py` still defines `ADMIN_PASSWORD_HASH`, but `check_admin_password()` remains a **bypass** for admin *tools* ("admin tools password disabled") - *(unverified if you re-enable that separately)*.
- The **desktop app** password gate remains `POST /api/login` against `app_password_hash` in `access_rules.json` (separate from SSH).

#### Layer 4 - No shell exit; only owner may open a shell

Wrappers and menus are written to **fail closed** and never fall through to a login shell:

- `sshd` `ForceCommand` means success never starts the user's normal shell.
- `access_wrapper.py`, `menu.py`, and `root_owner_menu.py` install handlers so **Ctrl+C / Ctrl+Z / Ctrl+\** print *"Use the menu to exit cleanly"* instead of breaking out (`SIGINT` / `SIGTSTP` / `SIGQUIT`).
- `safe_input` / EOF paths end the session cleanly; fatal errors `sys.exit` after logging - comments explicitly say *"never fall through to a shell."*
- **dedsecuser:** home menu option **Exit** only closes the session (`break` / `sys.exit`). No bash option in `menu.py`.
- **root owner only:** panel item **Root Shell** (`open_root_shell()` in `root_owner_menu.py`) warns, then may run `/bin/bash -l`. That is the sole intentional escape hatch; it is behind layers 1-3 and owner auth.

Together: password auth -> whitelist drop -> (owner) panel password -> trapped menu with no accidental shell - and public `dedsecuser` SSH is already `/bin/false` before any wrapper runs.


### 3.1 Headline: public-internet SSH is blocked; SSH works over the VPN

From the shipped `ssh_config.txt` excerpt (apply under `/etc/ssh/sshd_config` or `/etc/ssh/sshd_config.d/dedsec.conf`):

```sshd
AllowUsers root dedsecuser

# Lab user: ONLY from the VPN subnet -> ForceCommand gate
Match User dedsecuser Address 10.8.0.0/24
    ForceCommand /usr/bin/python3 /opt/secure-scripts/dedsec-labNEW/access_wrapper.py
    PermitTTY yes
    AllowTcpForwarding no
    X11Forwarding no

# Lab user from anywhere else (public internet) -> hard deny
Match User dedsecuser
    ForceCommand /bin/false

# Owner: always ForceCommand (no free root shell). Menu loads only if allowlisted.
Match User root
    ForceCommand /usr/bin/python3 /opt/secure-scripts/dedsec-labNEW/root_owner/root_owner_wrapper.py
    PermitTTY yes
    AllowTcpForwarding no
    X11Forwarding no
```

**What this means in practice:**

| Account | From VPN `10.8.0.0/24` | From public internet |
|---------|------------------------|----------------------|
| `dedsecuser` | Runs `access_wrapper.py` -> then `menu.py` **only if** VPN IP is in `access_rules.json` | `ForceCommand /bin/false` - session dies immediately |
| `root` | Runs `root_owner_wrapper.py` -> owner menu **only if** IP is in `root_access_rules.json` allowlist | Same ForceCommand runs, but wrapper **denies** ("ip not allowlisted") and exits - **owner menu never loads** |

Recommended extra hardening *(firewall - verify on your distro)*: allow `tcp/22` only from `10.8.0.0/24` (and a break-glass out-of-band path you control). Pair with `PasswordAuthentication no` + pubkey if you prefer.

After edits: `sshd -t && systemctl reload ssh` (or `ssh.socket` on newer Debian/Ubuntu).

### 3.2 `dedsecuser` wrapper + whitelist

| File | Role |
|------|------|
| `access_wrapper.py` | sshd ForceCommand entry: blocks non-TTY / `SSH_ORIGINAL_COMMAND`, loads rules, allowlists by VPN IP, then `os.execve` -> `menu.py` |
| `menu.py` | Interactive lab menu; discovers tools under `scripts/` (`ip_tools`, `misc_tools`, `system`, `admin_tools`) |
| `access_rules.json` | Allowlist: keys are **VPN IPs** under `"users"` |

Gate logic (simplified):

1. Read source IP from `SSH_CONNECTION`.
2. `load_rules()` from `access_rules.json`.
3. `get_user_rule_by_ip(rules, ip)` - missing / disabled / failed checks -> `deny_access` ("not whitelisted") - **menu never starts**.
4. On success -> `portal(...)` then `os.execve(..., menu.py)`.

App API uses the **same** file via `validate_vpn_user(ip)` - login, John, Shodan, ipcheck, terminal token, etc. all require a whitelisted VPN IP.

Example user entry (see also `access_rules.example.json`):

```json
"users": {
  "YOUR_CLIENT_VPN_IP": {
    "enabled": true,
    "display_name": "Example User",
    "role": "standard",
    "app_username": "example",
    "app_password_hash": "YOUR_SHA256_PASSWORD_HASH",
    "ssh_user": "dedsecuser",
    "current_vpn_region": "uk",
    "subscription_expires": "2099-12-31"
  }
}
```

### 3.3 Root owner wrapper + whitelist (menu will not load if not listed)

| File | Role |
|------|------|
| `root_owner/root_owner_wrapper.py` | ForceCommand for `root`: blocks remote commands & non-TTY; **IP allowlist**; only then execs the menu |
| `root_owner/root_owner_menu.py` | Owner panel (traffic intel, launch lab as admin, misc tools, logs, backup, ...) |
| `root_owner/root_access_rules.json` | Owner allowlist |

Critical checks in `root_owner_wrapper.py` **before** `os.execve(... root_owner_menu.py)`:

1. If `SSH_ORIGINAL_COMMAND` is set -> deny ("ssh command execution blocked").
2. If stdin is not a TTY -> deny.
3. Load `root_access_rules.json` - unreadable -> deny.
4. `owner.enabled` must be true - else deny ("owner access disabled").
5. `source_ip` **or** resolved `real_ip` (from OpenVPN status) must be in `owner.allowed_ips` - else deny (**"ip not allowlisted"**).  
   **If this fails, the owner menu never loads.**

```json
{
  "owner": {
    "enabled": true,
    "display_name": "YOUR_OWNER_DISPLAY_NAME",
    "password_hash": "YOUR_SHA256_PASSWORD_HASH",
    "allowed_ips": ["YOUR_CLIENT_VPN_IP"]
  }
}
```

Note: the live wrapper reads **`allowed_ips`** (not `allowed_vpn_ips`). Put your owner's VPN tunnel IP here. Optionally also list a known public IP if you use `real_ip` matching via `openvpn-status.log`.

Owner menu then password-gates again inside `root_owner_menu.py` using `owner.password_hash` *(confirm hash algorithm matches your deploy)*.

### 3.4 How menus launch tools

- **dedsecuser `menu.py`:** lists categories from `scripts/` directories; runs selected `.py` tools (IP tools include sniffers / `vpn_puller*` / `fivem_finder.py`, etc.). Admin category gated by role.
- **Owner `root_owner_menu.py`:** fixed panel items + scans `root_owner/misc_tools/` for misc scripts (HWID, OpenVPN TCP helpers, proxychains, OVH DDoS **alert helper**, traffic tools, ...).

Both wrappers set env such as `DEDSEC_ROLE`, `DEDSEC_USER`, `DEDSEC_SOURCE_IP` for child menus.

---


### 3.5 Adding your own tools (misc tools drop-in)

Both the **owner** panel and the **lab/admin** menus discover tools by scanning directories - you can drop a Python (or shell) script in and it appears without editing the menu code.

#### Owner panel - `root_owner/misc_tools/`

Grounded in `root_owner/root_owner_menu.py`:

- Constant: `MISC_DIR = .../root_owner/misc_tools`
- Menu item **Misc Tools** -> `browse_misc_tools()`
- Discovery: `os.listdir(MISC_DIR)` for files ending in **`.py` or `.sh`** (files only; subfolders are ignored)
- Empty dir shows: *"Drop .py or .sh files here:"* plus the full `MISC_DIR` path
- Run: `python3 <script>` for `.py`, `bash <script>` for `.sh` (as root, since the owner ForceCommand session is root)
- Label: filename with `_` -> spaces and `.py`/`.sh` stripped (`prettify`)

**To add an owner tool:**

1. SSH in as allowlisted owner (layers sec 3.0) and unlock the panel password.
2. Copy your script to `/opt/secure-scripts/dedsec-labNEW/root_owner/misc_tools/your_tool.py`
3. `chmod 700` (matches `install.sh` style for owner misc tools)
4. Re-open **Misc Tools** - it should list `Your Tool`

No special class or entry-point function is required: the menu just executes the file. Use `if __name__ == "__main__":` in your script. Avoid hard-coding secrets; read env/`YOUR_*` placeholders or a local config you do not commit.

Example owner misc tools: `api_manager.py`, `hwid_locker.py`, `ipcameraexploiter.py`, `openvpn_tcp.py`, `ovh_ddos_discord.py`, `proxychains_menu.py`, `sftp_maintenance_window.py`, `ssh_guard.py`, `tcp-dumps.py`.

#### Lab / admin menus - `scripts/` categories (`menu.py`)

Grounded in `menu.py` -> `get_categories()` / `get_scripts()` / `run_tool_safely()`:

- Every **subdirectory** of `scripts/` (except `system`) becomes a category. `admin_tools` is shown only when `DEDSEC_ROLE=admin`.
- Top-level **`scripts/misc_tools/*.py`** is a normal category ("Misc Tools") for allowlisted lab users.
- Within a category folder, discovery rules are:
  1. Any **`*.py` file** in that folder is listed.
  2. A **subdirectory** is treated as one tool if it contains `main.py` or `<dirname>.py`; otherwise the first `*.py` inside is used.
  3. **Exception:** a nested directory literally named `misc_tools` (or `__pycache__`) is **skipped** when scanning *inside* a category - so `scripts/admin_tools/misc_tools/ip_spoofing.py` is **not** auto-listed under Admin Tools today *(unverified whether anything else launches it; prefer dropping admin-only scripts as `scripts/admin_tools/your_tool.py`)*.
- Run: `python3 script` when root, else `sudo -n python3 script` (needs the sudoers snippets from `install.sh`). Special case: `vpn_puller.py` / `vpn_pullerv2.py` get the user's VPN IP as argv.

**To add a lab (or admin-only) tool:**

| Audience | Drop file here |
|----------|----------------|
| All lab roles | `scripts/misc_tools/my_tool.py` (or `scripts/ip_tools/...`) |
| Admin only | `scripts/admin_tools/my_tool.py` |
| Owner only | `root_owner/misc_tools/my_tool.py` (above) |

```bash
# Example - lab misc drop-in (placeholders only)
install -m 750 /path/to/my_tool.py \
  /opt/secure-scripts/dedsec-labNEW/scripts/misc_tools/my_tool.py
# Next dedsecuser menu -> Browse Tool Categories -> Misc Tools -> "My Tool"
```

No plugin API beyond "runnable script": stdin/stdout are the TTY; exit code is shown after run. Keep Discord webhooks / API keys out of the script body (use `discord_alerts.json` / env with `YOUR_WEBHOOK_*`).



## IP geolocation on the server

Desktop **IP Lookup** / Surveillance call your lab's **custom** endpoints `POST /api/ipcheck/token` and `POST /api/ipcheck/lookup` (VPN peer required). `app_api.py` resolves geo via the free public `http://ip-api.com/json/...` helper (`_ipcheck_geo`).

SSH IP tools (`scripts/ip_tools/vpn_puller*.py`) use **`IPAPI_KEY`** for pro.ip-api.com when set, and fall back to free `http://ip-api.com/line/...`. Owner Traffic Intelligence uses local `geoiplookup` + `whois` (no cloud key).

See [FEATURES.md - IP geolocation](FEATURES.md#ip-geolocation-custom-lab-api--fallbacks) for the full matrix. Never commit live API keys.

---
## 4. SSH terminal API (in-app shell over WSS)

The desktop terminal does **not** open a raw SSH client to the VPS. Flow:

```
Client                         Lab API (app_api.py)
------                         -------------------
POST /api/terminal-token  ->    validate_vpn_user(client VPN IP)
                          -    { token, expires_in: 90 }

WSS  /ws/terminal
  Authorization: Bearer <token>
                          ->    validate VPN IP again
                               consume one-time token (bound to that IP)
                               pty.fork() -> python3 access_wrapper.py
                          -->   bidirectional terminal I/O
```

Implemented in:

- Server: `app_api.py` - `POST /api/terminal-token`, `WebSocket /ws/terminal` (Bearer preferred; `?token=` deprecated).
- Client: `pages/terminal_page.py`, `pages/dedsec_cmd.py` - build `wss://` from `https://` `server_url`, send Bearer header.

Configure:

1. API must be reachable as `https://YOUR_LAB_HOST:8443` **over the VPN**.
2. User's VPN IP must exist in `access_rules.json`.
3. TLS cert on uvicorn must match what `lab_ca.pem` pins.
4. Token TTL defaults to **90 seconds** (`TERMINAL_TOKEN_TTL_SECONDS`) - one-shot consume.

John / Shodan / ipcheck use the same "VPN IP + short-lived token" pattern (`/api/john/token`, `/api/shodan/token`, `/api/ipcheck/token`).

---

## 5. Lab API (`app_api.py`)

### 5.1 How to run *(recommended pattern - exact unit file unverified)*

`requirements.txt` in-tree is minimal (`requests`, `scapy`, `psutil`, `python-dateutil`). Production also needs **FastAPI + uvicorn** (and typically `cryptography` for update signatures). Install into the venv created by `install.sh`:

```bash
cd /opt/secure-scripts/dedsec-labNEW
./venv/bin/pip install fastapi uvicorn[standard] cryptography python-multipart
# plus whatever your tools need (e.g. shodan CLI if you expose Shodan routes)
```

TLS materials: see `certs/README.md`. Then, for example:

```bash
./venv/bin/uvicorn app_api:app \
  --host YOUR_LAB_VPN_IP \
  --port 8443 \
  --ssl-certfile /opt/secure-scripts/dedsec-labNEW/certs/cert.pem \
  --ssl-keyfile  /opt/secure-scripts/dedsec-labNEW/certs/key.pem
```

Bind to the **VPN interface IP** (not `0.0.0.0` on a public NIC) so the API stays off the open internet. Wrap in systemd for restart-on-boot *(unit file not shipped - write your own)*.

`install.sh` installs packages, creates `dedsecuser`, venv, permissions, and limited sudoers for menu/wrapper - run it after copying the tree to `/opt/secure-scripts/dedsec-labNEW`.

### 5.2 Core endpoints

| Method | Path | Needs | Notes |
|--------|------|-------|--------|
| POST | `/api/login` | Whitelisted VPN IP; `app_username` + password vs `app_password_hash`; optional HWID fingerprint | Returns session profile via `build_user_response` |
| POST | `/api/change-password` | Same VPN session | Updates hash in rules *(persist path = access_rules.json)* |
| GET | `/api/me` | Whitelisted VPN IP | Used by client `lab_probe()` |
| GET | `/api/status` | VPN IP | Health / local checks |
| GET/POST/DELETE | `/api/ips`, `/api/ips/add`, `/api/ips/{ip}` | VPN IP | Shared IP database |
| POST | `/api/terminal-token` | VPN IP | See sec 4 |
| WS | `/ws/terminal` | VPN IP + Bearer token | See sec 4 |
| GET | `/api/update/version` | Often called on VPN | Returns `version`, `min_version`, `sha256`, optional Ed25519 `signature`, `download_url` |
| GET | `/api/update/download` | VPN IP | Serves update zip (same bytes as sha256) |
| POST/GET... | `/api/john/*` | VPN + John one-time token | Needs John the Ripper paths on server |
| POST/GET... | `/api/shodan/*` | VPN + Shodan token | Needs Shodan CLI / API key on server *(where you store the key - verify)* |
| POST/GET... | `/api/ipcheck/*` | VPN + ipcheck token | Live ping / monitor / nmap helpers |
| POST/GET... | `/api/net-emulate/*` | VPN | Traffic shaping helpers; whitelist ports include `8443` |

Secrets / config plug-ins:

- **Users / passwords / roles:** `access_rules.json`
- **Owner allowlist:** `root_owner/root_access_rules.json`
- **Discord alerts:** `discord_alerts.json` (`enabled: false` until you paste `YOUR_WEBHOOK_*`)
- **HWID alerts:** `hardware_locker/hwid_webhook.json`
- **Update signing (client):** `DedSecLabAPP_Beta/core/updater.py` -> `UPDATE_SIGNING_PUBKEY_B64` (raw 32-byte Ed25519 pubkey, base64). Private key stays on your build machine.
- **Update artifacts:** directory used by `_update_file_path()` *(path helper in `app_api.py` - confirm on your tree; often under `app_updates/` which the repo ships empty)*.

`app_api.py` uses `YOUR_*` placeholders; fill them before deploy and do not commit real secrets.

---

## 6. Point the client at your server

### 6.1 VPN gate flag

`DedSecLabAPP_Beta/core/config.py`:

```python
REQUIRE_VPN_GATE = False   # default: open lab UI without VPN
# REQUIRE_VPN_GATE = True  # restore VPN-locked gate (needs your .ovpn + exits)
```

`app.py` calls `_after_splash()` -> if False, `show_lab()`; if True, `VpnGate`.

### 6.2 Server URL & lab hosts

| Setting | File | Placeholder |
|---------|------|-----------------|
| Default `server_url` | `core/config.py` -> `ConfigManager.DEFAULTS` | `https://YOUR_LAB_HOST:8443` |
| Lab host pin set | `core/tls.py` -> `DEFAULT_LAB_HOSTS` | `YOUR_LAB_HOST`, `YOUR_LAB_VPN_IP` |
| Region servers / exit map | `core/dedsec_vpn_gate.py` | `YOUR_VPN_EXIT_*` |
| CA pin | `assets/lab_ca.pem` | Copy from your CA; start from `lab_ca.pem.example` |
| Optional CA override | env `DEDSEC_LAB_CA` or config `lab_ca_path` | path to PEM |
| VPN app allow-list (split tunnel helpers) | `vpn_app_whitelist.json` | placeholder exe paths only |

Runtime config also lives under `%APPDATA%\DedSecLab\config.json` on Windows after first run - users can change `server_url` in Settings without rebuilding *(confirm UI field)*.

### 6.3 Website allow-list

`ssh_whitelist_manager.py` ships no companion-website account creation by default (those hooks return "website sync not configured"). `vpn_app_whitelist.json` is **not** a website ACL - it lists local apps allowed through VPN helpers. For any future site you host yourself, keep it **out** of the public lab API trust boundary.

---

## 7. Bring-up checklist

1. **VPS** with a public IP (`YOUR_VPN_SERVER`). Prefer a firewall default-deny.
2. **Copy** `opt/secure-scripts/dedsec-labNEW` -> `/opt/secure-scripts/dedsec-labNEW` on the server.
3. **Run** `bash install.sh` (packages, venv, `dedsecuser`, permissions, sudoers snippet).
4. **PKI + OpenVPN:** generate CA/server/client material; configure `server 10.8.0.0/24`; enable `status /var/log/openvpn-status.log`; `systemctl enable --now openvpn-server@server` *(service name may vary)*.
5. **TLS for API:** create `certs/cert.pem` + `key.pem`; copy the CA (or server cert) to the client as `assets/lab_ca.pem`.
6. **Fill** `access_rules.json` (per-user VPN IPs + password hashes) and `root_owner/root_access_rules.json` (`enabled`, `allowed_ips`).
7. **Discord (optional):** edit `discord_alerts.json` / webhook examples; keep `enabled: false` until ready.
8. **sshd:** merge Match/ForceCommand blocks from `ssh_config.txt`; `sshd -t`; reload. Confirm `dedsecuser` from a non-VPN IP gets `/bin/false`, and root without allowlist never reaches the owner menu.
9. **API:** install FastAPI/uvicorn into the venv; bind to `YOUR_LAB_VPN_IP:8443` with TLS; enable on boot.
10. **Client:** set `REQUIRE_VPN_GATE` as desired; set `server_url` / `_EXIT_TO_SID` / `DEFAULT_SERVERS`; install your private `.ovpn`; place `lab_ca.pem`.
11. **Smoke test over VPN only:**
    - Ping `YOUR_LAB_VPN_IP`
    - `curl -v --cacert lab_ca.pem https://YOUR_LAB_HOST:8443/api/status`
    - App login
    - SSH as `dedsecuser` from VPN -> menu; from public net -> fail
    - SSH as `root` with allowlisted VPN IP -> owner wrapper; without -> denied, no menu
    - In-app terminal -> token + WSS shell

---

## 8. Security notes

- **Layered SSH (see sec 3.0):** sshd auth -> IP whitelist drop -> owner panel password -> no shell escape (only owner Root Shell). Do not weaken ForceCommand or signal traps.
- **Your `.ovpn` files are the keys to the kingdom.** Do not put them in GitHub Releases or the public tree. Anyone with a tunnel IP that you also whitelist can hit the API.
- **VPN-only SSH for `dedsecuser`** (`Match Address` + `/bin/false` fallback) is a primary hardening feature - keep it when customizing sshd.
- **Root never gets a normal shell via ForceCommand.** The owner menu loads **only** after `root_access_rules.json` allowlist (+ enabled flag). Treat that JSON like a password file (`chmod 600`, root-owned).
- **API allowlist = same VPN IPs** as SSH. Disabling a user in `access_rules.json` cuts app login, tools, and wrapper portal together.
- **Pin TLS** with `lab_ca.pem`; never ship `verify=False` clients.
- **Update authenticity:** set `UPDATE_SIGNING_PUBKEY_B64` and sign zips; until then the client still requires matching `sha256`.
- **Webhooks / OVH / Shodan / John** are optional integrations - leave example JSON disabled until configured.
- **Logs and PCAPs** on a live box contain sensitive traffic - do not commit them.
- Break-glass: keep an out-of-band console (provider VNC/serial) before you lock SSH to VPN-only on the firewall.

---

## Unverified / confirm on your deploy

Items marked **(unverified)** or inferred - double-check against your running private server before publishing the guide as gospel:

1. Exact **systemd unit names** for OpenVPN and uvicorn (not shipped in this repo).
2. Exact **`_update_file_path()`** directory and whether Ed25519 signing helpers live beside `app_api.py` (`UPDATE_SIGNING.md` referenced in a docstring but not present in this copy).
3. **Password hash algorithm** for `app_password_hash` / owner `password_hash` (PBKDF2 appears in `ssh_whitelist_manager.py` for app users - confirm `menu.py` / `app_api.verify_password` match).
4. Whether production binds API to tun IP only vs localhost + firewall redirect.
5. Shodan API key storage location on disk.
6. Optional firewall `ListenAddress` / `ufw` rules beyond the sshd Match blocks (recommended, not copied from a live firewall dump).

---

*Placeholders only. No production secrets.*
