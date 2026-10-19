# DedSec Lab App (Beta)

Windows desktop app (PyQt6). After a fresh Windows install you need Python, a venv, and the packages below.

## What you need

- Windows 10/11
- Python 3.12 or 3.14 (tick **Add python.exe to PATH** when installing)
- This folder: `DedSecLabAPP_Beta`

## First-time setup

Open PowerShell in this folder.

```powershell
cd C:\Path\To\DedSecLabAPP_Beta
```

Create a virtual environment (only once):

```powershell
py -3 -m venv venv
```

If `py` is not found, use the full path to python.exe instead.

Install packages:

```powershell
.\venv\Scripts\python.exe -m pip install --upgrade pip
.\venv\Scripts\python.exe -m pip install -r requirements.txt
```

If `requirements.txt` is missing, install the minimum set:

```powershell
.\venv\Scripts\python.exe -m pip install PyQt6 requests urllib3 psutil cryptography
```

## Run the app

Always use the venv Python, not the system one:

```powershell
.\venv\Scripts\python.exe .\app.py
```

## VS Code

1. Open the `DedSecLabAPP_Beta` folder
2. `Ctrl+Shift+P` -> **Python: Select Interpreter**
3. Choose `.\venv\Scripts\python.exe`

If it says "Python is not installed", Python is not on PATH or no interpreter is selected.

## After a Windows reinstall

The `venv` folder does not survive a wipe. Repeat:

1. Install Python again (Add to PATH)
2. `py -3 -m venv venv`
3. `.\venv\Scripts\python.exe -m pip install -r requirements.txt`
4. `.\venv\Scripts\python.exe .\app.py`

Do not `pip install` into a uv-managed Python. That hits `externally-managed-environment`. Always use the project `venv`.

## Common errors

| Error | Fix |
|---|---|
| `No module named 'PyQt6'` | Install into the venv, then run with `.\venv\Scripts\python.exe` |
| `externally-managed-environment` | You used the uv Python. Create `venv` first |
| `.\venv\Scripts\python.exe` not recognized | Venv was not created. Run `py -3 -m venv venv` |
| App window never opens | Run from this folder so `assets/` and `login.key` resolve |

## VPN / FileZilla (separate from this app)

- Connect OpenVPN before using `YOUR_LAB_VPN_IP`
- FileZilla protocol must be **SFTP**, host `YOUR_LAB_VPN_IP`, port `51222`, user `root`
