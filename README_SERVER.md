# DedSecLab - Server / VPS

### OpenVPN, lab API, and ForceCommand SSH menus

Back-end half of DedSecLab - what the Windows client talks to when the VPN gate is on. Point the client at **your** host. The code ships with placeholders, not a live private deployment.

Client docs: [README.md](README.md) * Full inventory: [FEATURES.md](FEATURES.md)

> **Ethical use.** Run this stack only on infrastructure you own or administer, for authorised lab and defensive security work. Do not expose the API or SSH menus to the public internet without understanding the risk. Misuse of the included tools may be illegal.

---

## What you are installing

Tree: `opt/secure-scripts/dedsec-labNEW/`

| Pillar | Role |
|--------|------|
| **OpenVPN bridge** | Clients join a private subnet (docs assume `10.8.0.0/24`); API + SSH expect VPN peers |
| **Lab API (`app_api.py`)** | Login, device lock, IP database, update channel, terminal WSS, John / Shodan / ipcheck / net-emulate |
| **Custom geo API** | `POST /api/ipcheck/lookup` - VPN-gated lookups for the desktop Geo IP + Surveillance panels; server resolves via public **ip-api.com** (free). SSH pullers optionally use pro ip-api (`IPAPI_KEY`) with free-line **fallback** |
| **`dedsecuser` wrapper** | ForceCommand -> whitelist -> optional wrapper password -> Enter Lab `menu.py` (no raw shell) |
| **Root owner panel** | Allowlisted ForceCommand -> password -> traffic intelligence, misc_tools drop-in, backups, danger-zone root shell |
| **Hardware locker** | Fingerprint approve / revoke + Discord alerts + min-version gates |

Replace every `YOUR_*` placeholder on your private host. **Do not commit production secrets.**

---

## Trust model (short)

1. **OpenVPN is the bridge** - the API is meant for tunnel peers, not the open internet.
2. **`dedsecuser` is VPN-only** - `Match Address 10.8.0.0/24`; non-VPN hits `/bin/false`.
3. **Whitelist + expiry** - `access_rules.json` maps VPN IP -> role / subscription.
4. **Optional wrapper password** - `WRAPPER_PASSWORD_HASH` (empty = VPN lock only).
5. **No-shell-exit** - menus trap Ctrl+C / Ctrl+Z; remote one-shot commands blocked.
6. **Root is allowlisted** - `root_access_rules.json` + owner PBKDF2 password.
7. **Client TLS pin** - desktop app fails closed without your `lab_ca.pem`.

Keeping **`.ovpn` profiles private** is what keeps a private lab private.

---

## Feature highlights (server)

- **Enter Lab menu** - account, themes (admin), tickets, general chat, browsable tool categories (`ip_tools`, `admin_tools`, `misc_tools`)
- **Admin toolkit** - SSH whitelist / `.ovpn` provisioning, dashboard, DNS adblock, website blocker, service manager, ticket panel
- **Owner misc_tools drop-in** - drop a `.py` / `.sh` into `root_owner/misc_tools/` and it appears in the panel (API manager, HWID locker, SSH guard, OpenVPN helpers, ...)
- **Traffic intelligence** - live watch panel with local GeoIP (`geoiplookup`) + whois ISP labelling
- **Discord hooks** - optional alert routing for login / deny / tool start-finish (webhook JSON you supply)

Deep route list and wrapper behaviour: **[FEATURES.md - Server / VPS feature inventory](FEATURES.md#server--vps-feature-inventory)**.

---

## Multi-VPS / unlimited locations

Deploy this tree on **as many VPS hosts as you want**. Each host is another OpenVPN endpoint + lab API. The desktop VPN gate ships four example regions; use **Add location (.ovpn)** for more - no four-location cap.

Author's usual hosts: **OVH** and **Linode** - strong DDoS protection and a provider/network firewall in front of the VPS firewall. See [INSTALL_VPS.md - Scale out](INSTALL_VPS.md#scale-out-more-vps--more-vpn-locations).

## Docs

| Doc | Purpose |
|-----|---------|
| [INSTALL_VPS.md](INSTALL_VPS.md) | Step-by-step bring-up + **ForceCommand lockout warning** (keep a second SSH window open) |
| [SERVER_SETUP.md](SERVER_SETUP.md) | Architecture, sshd Match, whitelist, API, geo lookup, TLS pin, wrapper password |
| [opt/secure-scripts/dedsec-labNEW/README.md](opt/secure-scripts/dedsec-labNEW/README.md) | Quick restore / `install.sh` notes from the lab tree |

---

## Related client pieces

- App install: [INSTALL_APP.md](INSTALL_APP.md)
- Feature list: [FEATURES.md](FEATURES.md)

---

## Disclaimer

Defensive / authorised-lab use only. Harden the box, keep backups, follow the law on your VPS.
