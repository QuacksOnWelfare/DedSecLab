# Install the DedSecLab desktop app (Windows)

Windows app install from `DedSecLabAPP_Beta/` and `installer/`.

---

## Prerequisites

| Item | Notes |
|------|--------|
| **OS** | Windows 10/11 (x64) |
| **Python** | **3.12+** recommended (venv) |
| **OpenVPN** | Needed if you enable the VPN gate / in-app VPN (`openvpn.exe` / OpenVPN GUI) |
| **VLC** | Optional - only if you use the CCTV / media page (`python-vlc`); install [VideoLAN VLC](https://www.videolan.org/) for Windows |
| **Inno Setup 6** | Only for building the Windows installer (`winget install --id JRSoftware.InnoSetup -e`) |
| **Your lab** | Self-hosted API + CA + (optional) `.ovpn` - see [INSTALL_VPS.md](INSTALL_VPS.md) |

---

## Path A - run from source

```powershell
cd DedSecLabAPP_Beta
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

### Point the app at your server

1. **`REQUIRE_VPN_GATE`** - in `core/config.py`:

   ```python
   REQUIRE_VPN_GATE = False   # default: skip VPN gate, open lab UI
   # REQUIRE_VPN_GATE = True  # require OpenVPN before login
   ```

2. **Hosts / URL** - Settings -> Connection -> **Server URL**, or defaults in `core/config.py` / gate config. Use your lab HTTPS URL (often `https://YOUR_LAB_VPN_IP:8443` over the tunnel). Replace the `YOUR_*` placeholders with **your** values.

3. **CA pin** - place your lab CA at `assets/lab_ca.pem` (see `lab_ca.pem.example` if present). The client verifies TLS via `core/tls.py`; missing/wrong CA -> fail closed.

4. **OpenVPN profiles** - if `REQUIRE_VPN_GATE = True`, supply your own `.ovpn` files where the gate expects them (do not commit production profiles to a public fork).

5. **Exit / region map** - if you use multi-region exits, update `YOUR_VPN_EXIT_*` / `_EXIT_TO_SID` in `core/dedsec_vpn_gate.py` to match **your** public exit IPs (verify).

---

## Path B - build a Windows installer

### 1. Nuitka standalone build

```powershell
cd DedSecLabAPP_Beta
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -r requirements-build.txt
python build.py
```

Choose the **Release** option (see `build.py` menu; typically option **2**). Output: `DedSecLabAPP_Beta/DedSecLab/DedSecLab.exe` (folder created by the build; not committed).

Optional updater blob: `build_updater.py` -> hidden `assets/dsl_upd.bin` (verify; the repo does not include a prebuilt updater).

### 2. Compile the Inno installer

From repo `installer/`:

```powershell
powershell -ExecutionPolicy Bypass -File .\build_installer.ps1 -AppVersion 1.0.6
```

Requires Inno Setup 6 on `PATH` / default install location.

**Hidden / System assets (do not skip):**

Inno Setup **skips** files marked Hidden+System. `build_installer.ps1` **clears** those attributes on the source dist `assets` folder **before** compile, then **re-applies** them afterward. The installer `[Code]` `HideAssets` procedure marks `{app}\assets` (and `dsl_upd.bin` if present) Hidden+System again after install. If you compile `.iss` by hand, un-hide assets first or the setup will omit them.

Setup exe lands in `installer/Output/` (keep empty in git).

### 3. Fork customisation

- Generate a new **AppId** GUID in `DedSecLab.iss` so uninstall keys do not collide with another fork.
- Code signing is not included - add `SignTool` yourself if you redistribute.

More detail: [installer/README.md](installer/README.md).

---

## After install / first run

1. Set Server URL (and username prefs) under **Settings**.
2. Confirm **Lab TLS** status shows OK when your CA is in place.
3. If using VPN gate, connect OpenVPN, then log in.
4. Terminal and most lab APIs require a **whitelisted VPN peer IP** on the server (`access_rules.json`).

---

## Related docs

- Features: [FEATURES.md](FEATURES.md)
- Server: [README_SERVER.md](README_SERVER.md), [INSTALL_VPS.md](INSTALL_VPS.md), [SERVER_SETUP.md](SERVER_SETUP.md)

---

## Disclaimer

Authorised / own-lab use only. You are responsible for how the client is configured and what networks you target.
