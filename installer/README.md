# DedSecLab Windows installer

Inno Setup 6 project to pack the Nuitka standalone build into `DedSecLab-Setup-<version>.exe`.

## Layout

```
DedSecLab/
  DedSecLabAPP_Beta/          # app source
    DedSecLab/                # created by build.py (Nuitka standalone) - NOT in git
  installer/                  # this folder
    DedSecLab.iss
    build_installer.ps1
    assets/                   # wizard images + icon
    Output/                   # setup exe lands here (keep empty in git)
```

## Build steps

1. From `DedSecLabAPP_Beta`:

```text
python -m venv venv
.\venv\Scripts\pip install -r requirements.txt
.\venv\Scripts\pip install -r requirements-build.txt
.\venv\Scripts\python build.py
```

Choose option **2** (Release). That produces `DedSecLabAPP_Beta/DedSecLab/DedSecLab.exe`.

2. Install Inno Setup 6 (`winget install --id JRSoftware.InnoSetup -e`).

3. From this folder:

```powershell
powershell -ExecutionPolicy Bypass -File .\build_installer.ps1 -AppVersion 1.0.6
```

## Hidden / System assets (important)

Inno Setup **skips** Hidden+System files. `build_installer.ps1` clears those attributes on the **source** dist `assets` folder before compiling, then re-applies them. The installer `[Code]` `HideAssets` procedure marks `{app}\assets` (and `dsl_upd.bin` if present) Hidden+System again after install.

## What you must customize

- **AppId GUID** in `DedSecLab.iss` - generate your own for a public fork so uninstall registry keys do not collide.
- **Code signing** - not included; add `SignTool` yourself if you redistribute.
- **Updater blob** - produced by `build_updater.py`; do not commit private signing keys. The repo does not include a prebuilt updater exe / `dsl_upd.bin`.

## Not included

- Compiled `Output\DedSecLab-Setup-*.exe`
- Private certificates / SignTool configs
- Hardcoded `C:\Users\...` paths
