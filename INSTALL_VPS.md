# Install DedSecLab on a VPS (server side)

Bring-up for the server code under `opt/secure-scripts/dedsec-labNEW/`.  
Full architecture, placeholders, and hardening notes: **[SERVER_SETUP.md](SERVER_SETUP.md)**.  
Server front page: **[README_SERVER.md](README_SERVER.md)**.

> **Ethical use.** Deploy only on hosts you own or administer, for authorised lab / defensive work. Do not point these tools at third-party systems without permission.

---

## 0. Before you start

| You need | Notes |
|----------|--------|
| A Linux VPS (Debian/Ubuntu-style assumed by `install.sh`) | Root or sudo |
| This repo's `opt/secure-scripts/dedsec-labNEW/` tree | Server scripts + `YOUR_*` placeholders |
| Your own OpenVPN PKI / `.ovpn` clients | **Not** shipped; generate with Easy-RSA (or equivalent) |
| TLS cert + CA for the lab API | Client pins `lab_ca.pem` |
| A second way into the box | Console / cloud serial **or** a second SSH session - see warning below |

Replace every `YOUR_*` placeholder before going live. Never commit production `access_rules.json`, webhooks, or private keys to a public fork.

---

## 1. Copy the lab tree onto the VPS

From your workstation (paths are examples):

```bash
scp -r opt/secure-scripts/dedsec-labNEW root@YOUR_VPS_IP:/opt/secure-scripts/
ssh root@YOUR_VPS_IP
cd /opt/secure-scripts/dedsec-labNEW
chmod +x install.sh setup_security.sh fix_permissions.sh 2>/dev/null || true
```

---

## 2. Run the package installer

```bash
bash install.sh
```

Expect (verify on your distro): system packages, Python deps, permission fixes, `dedsecuser` sudo bits, log paths such as `/var/log/ddos-watch`.

If needed:

```bash
pip3 install --break-system-packages -r requirements.txt
# or use a venv - prefer whatever matches your host policy
```

---

## 3. OpenVPN bridge

1. Install/configure OpenVPN (`install.sh` may pull `openvpn` + `easy-rsa` - verify).
2. Build your PKI; publish **client** `.ovpn` profiles privately to lab users only.
3. Use a tunnel subnet the rest of the stack expects - stock docs assume **`10.8.0.0/24`** with the lab at `YOUR_LAB_VPN_IP` (often `10.8.0.1`).
4. Set `YOUR_VPN_SERVER` / region exit IPs in client config to match **your** exits.
5. Confirm clients get stable `10.8.0.x` addresses - those IPs are the **allowlist keys**.

Details: [SERVER_SETUP.md sec 2](SERVER_SETUP.md).

---

## 4. Lab API (`app_api.py`)

1. Copy `access_rules.example.json` -> `access_rules.json` and add VPN peer IPs -> usernames.
2. Fill in the Discord webhook settings only if you want alerts (`enabled: false` by default in examples).
3. Install your TLS certs under `certs/` (see `certs/README.md` if present).
4. Run the API (uvicorn/TLS on your chosen port - commonly **8443** behind the VPN). Exact unit file / flags: verify against `app_api.py` and `SERVER_SETUP.md`.
5. Confirm `validate_vpn_user()` rejects unknown peers (`"VPN IP is not whitelisted"`).

WSS terminal: clients mint a short-lived token then connect to `/ws/terminal` with `Authorization: Bearer ...`.

---

## 5. SSH ForceCommand wrappers

### WARNING - read this before touching `sshd_config`

```text
+==========================================================================+
|  SETTING UP ForceCommand WRAPPERS CAN LOCK YOU OUT OF SSH.               |
|                                                                          |
|  ALWAYS keep a SECOND SSH session (or cloud/serial console) OPEN for     |
|  the entire time you edit Match/ForceCommand blocks.                     |
|                                                                          |
|  After each change:                                                      |
|    1. sshd -t          # config syntax check                             |
|    2. systemctl reload sshd   (or equivalent)                            |
|    3. Open a NEW SSH login in another window and confirm you can still   |
|       authenticate and reach a shell / expected menu.                    |
|    4. Only then close the original working session.                      |
|                                                                          |
|  If the new session fails, fix or revert from the session that is        |
|  still open. Do not disconnect your only working login.                  |
+==========================================================================+
```

### Intended behaviour (stock)

| User | From VPN `10.8.0.0/24` | From elsewhere |
|------|------------------------|----------------|
| `dedsecuser` | ForceCommand -> lab wrapper / menu | `/bin/false` (or equivalent deny) |
| `root` | ForceCommand -> owner wrapper; menu only if source IP is **whitelisted** (+ optional password hash) | Same ForceCommand; non-allowlisted sources should not get a free root shell |

### Configure

1. Keep session A open. Open session B for tests.
2. Install wrapper scripts (`access_wrapper.py`, `root_owner/`, `menu.py`, ...) with correct paths and `chmod`/`chown` (see `fix_permissions.sh` / `setup_security.sh`).
3. Apply `Match` / `ForceCommand` from `ssh_config.txt` / `SERVER_SETUP.md` into `/etc/ssh/sshd_config` (or a drop-in under `sshd_config.d/`).
4. Optional: set `WRAPPER_PASSWORD_HASH` in the owner wrapper for an extra password gate (SHA-256 placeholder - replace with **your** hash).
5. Maintain the root/owner **IP whitelist** (file or rules referenced by the wrapper - verify path in code).
6. `sshd -t && systemctl reload sshd` - then **test in session B** before closing session A.

Layered defence summary: VPN membership -> allowlisted peer IP -> ForceCommand menu (not a raw shell) -> optional wrapper password -> app/API auth. See [SERVER_SETUP.md](SERVER_SETUP.md).

---

## 6. Smoke test

1. Client OpenVPN connects -> gets `10.8.0.x`.
2. Browser or app hits `https://YOUR_LAB_VPN_IP:8443` with your CA pinned -> login works for a whitelisted user.
3. Terminal page obtains a token and opens WSS.
4. SSH as `dedsecuser` from VPN -> menu; from public IP -> denied.
5. SSH as root from an allowlisted VPN IP -> owner menu; from a non-listed IP -> refused (verify).

---

## Scale out: more VPS / more VPN locations

The stack is **one VPS = one OpenVPN endpoint + one lab API**. Clone it as many times as you want.

1. Spin up another Linux VPS (Debian/Ubuntu). Copy `opt/secure-scripts/dedsec-labNEW/` and run the same bring-up (packages, OpenVPN PKI, `app_api.py`, SSH wrappers).
2. Give that host its own tunnel subnet / peer IPs (or a clearly separated allowlist) and its own `.ovpn` client profile.
3. On the Windows client, open the VPN gate -> **Add location (.ovpn)** and select the new profile. Point Server URL / TLS pin at that lab API when you use that location.
4. Repeat. There is **no hard cap** at four locations - the four built-ins are examples only.

**Providers the author uses:** [OVH](https://www.ovh.com/) and [Linode](https://www.linode.com/) (Akamai). Both have strong DDoS protection and a **network / provider firewall** separate from the VPS's own firewall - worth enabling in front of OpenVPN and the lab API port.

Keep each host's `access_rules.json`, TLS keys, and webhooks private. Do not commit production secrets.

## 7. Client pointer

Once the VPS is up, install the Windows app per [INSTALL_APP.md](INSTALL_APP.md): set Server URL, install `lab_ca.pem`, optionally enable `REQUIRE_VPN_GATE = True`.

---

## Disclaimer

ForceCommand, firewall, and VPN mistakes can lock you out. Keep an `sshd_config` backup and a non-SSH recovery path. Authorised lab use only.
