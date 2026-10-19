import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

AppName = "DedSecLab"
EntryFile = "app.py"
IconFile = os.path.join("assets", "dedsec_logo.ico")
BuildDir = "nuitka_build"
APP_DIR = Path(__file__).resolve().parent  # relative to this folder
VENV_PY = APP_DIR / "venv" / "Scripts" / "python.exe"
Company = "DedSec Lab"
Copyright = "(c) DedSec Lab"


def python_bin() -> str:
    if VENV_PY.is_file():
        return str(VENV_PY)
    return sys.executable


def app_version() -> str:
    # Pull the version the client reports so the .exe metadata matches it.
    for rel in ("core/config.py", "core/updater.py", "updater.py", "app.py"):
        p = APP_DIR / rel
        if not p.is_file():
            continue
        try:
            txt = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        m = re.search(r'(?:APP_VERSION|VERSION|__version__)\s*=\s*["\']([0-9]+(?:\.[0-9]+){1,3})["\']', txt)
        if m:
            return m.group(1)
    return "1.0.6"


def _norm4(v: str) -> str:
    parts = (v.split(".") + ["0", "0", "0", "0"])[:4]
    return ".".join(parts)


def pause():
    try:
        input("\nPress Enter to return to menu...")
    except (KeyboardInterrupt, EOFError):
        print("\nUse 0 to exit.")


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def clean_builds():
    print("Cleaning old builds...")
    os.chdir(APP_DIR)
    shutil.rmtree(APP_DIR / BuildDir, ignore_errors=True)
    shutil.rmtree(APP_DIR / AppName, ignore_errors=True)
    for root, dirs, _files in os.walk(APP_DIR):
        if "venv" in Path(root).parts:
            continue
        for d in list(dirs):
            if d == "__pycache__":
                shutil.rmtree(os.path.join(root, d), ignore_errors=True)
    print("Clean complete.")


def _win_hide(path):
    """Mark a file or folder Hidden + System so it stays out of normal Explorer views."""
    if os.name != "nt":
        return
    import ctypes
    try:
        ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x02 | 0x04)
    except Exception:
        pass


def harden_output(dest: Path):
    """Tidy and hide what we can in the shipped folder (free tier)."""
    dest = Path(dest)
    # Drop any leftover Python source/bytecode that slipped into the dist.
    removed = 0
    for p in list(dest.rglob("*")):
        if p.is_file() and p.suffix.lower() in {".py", ".pyc", ".pyo"}:
            try:
                p.unlink(); removed += 1
            except OSError:
                pass
    if removed:
        print(f"Stripped {removed} leftover .py/.pyc file(s) from the build.")
    # Remove source junk that should never ship.
    for pat in ("*.rar", "*.README", "*.bak*", "*.zip"):
        for p in dest.rglob(pat):
            try:
                p.unlink()
            except OSError:
                pass
    # Hide the loose data folders and small data files from casual users.
    for rel in ("assets", "tools", "assets/flags", "assets/icons"):
        p = dest / rel
        if p.exists():
            _win_hide(p)
    for p in (dest / "assets").glob("*"):
        if p.is_file():
            _win_hide(p)
    print("Data folders marked Hidden + System.")


def build_updater(py: str) -> bool:
    script = APP_DIR / "build_updater.py"
    if not script.is_file():
        print("build_updater.py not found; skipping updater build.")
        return False
    print("Building the updater (build_updater.py)...")
    r = subprocess.run([py, str(script)], cwd=str(APP_DIR))
    ok = r.returncode == 0 and (APP_DIR / "DedSecLabUpdater.exe").is_file()
    print("Updater built." if ok else "Updater build did not produce DedSecLabUpdater.exe.")
    return ok


def build_nuitka(debug=False, build_upd=True):
    os.chdir(APP_DIR)
    py = python_bin()
    if not Path(py).is_file():
        print("No project venv found.")
        print(f"Expected: {VENV_PY}")
        print("Create it first, or run option 4.")
        return

    check = subprocess.run([py, "-c", "import PyQt6; print(PyQt6.__file__)"], capture_output=True, text=True)
    if check.returncode != 0:
        print("PyQt6 is not in the project venv. Run option 4 first.")
        print(check.stderr[-400:] if check.stderr else "")
        return

    # Fail early on a syntax error in any client module, before a long build.
    comp = subprocess.run([py, "-m", "compileall", "-q", "-x", r"(venv|nuitka_build|DedSecLab)", "."],
                          capture_output=True, text=True)
    if comp.returncode != 0:
        print("Python compile check failed; fix these before building:")
        print((comp.stdout or "") + (comp.stderr or ""))
        return

    clean_builds()

    if build_upd and not (APP_DIR / "DedSecLabUpdater.exe").is_file():
        build_updater(py)

    ver = app_version()
    mode = "DEBUG (console on)" if debug else "RELEASE"
    print(f"Building {AppName} v{ver} with Nuitka [{mode}]")
    print(f"Python: {py}")

    loc = subprocess.run(
        [py, "-c", "import PyQt6, os; print(os.path.join(os.path.dirname(PyQt6.__file__), 'Qt6', 'plugins', 'platforms'))"],
        capture_output=True, text=True, check=True,
    )
    pyqt_path = loc.stdout.strip()
    if not os.path.isdir(pyqt_path):
        print(f"Cannot find PyQt6 platforms folder at {pyqt_path}")
        return

    # Warn about assets the hardened client needs but don't block the build.
    if not (APP_DIR / "assets" / "lab_ca.pem").is_file():
        print("WARNING: assets/lab_ca.pem is missing. The hardened client pins this CA;")
        print("         without it the app will refuse every server call. Add it before shipping.")

    console_mode = "force" if debug else "disable"
    cmd = [
        py, "-m", "nuitka",
        "--standalone",
        "--enable-plugin=pyqt6",
        "--remove-output",
        "--python-flag=no_docstrings",
        "--python-flag=no_asserts",
        "--python-flag=no_warnings",
        "--nofollow-import-to=*.tests",
        "--nofollow-import-to=*.test",
        "--nofollow-import-to=unittest",
        f"--windows-console-mode={console_mode}",
        f"--windows-icon-from-ico={IconFile}",
        # Version metadata so the .exe matches the client version.
        f"--company-name={Company}",
        f"--product-name={AppName}",
        f"--file-version={_norm4(ver)}",
        f"--product-version={_norm4(ver)}",
        f"--file-description={AppName} secure access client",
        f"--copyright={Copyright}",
        # Data: assets (icons, flags, applogo_light.png, lab_ca.pem) and tools.
        "--include-data-dir=assets=assets",
        "--include-data-dir=tools=tools",
        f"--include-data-dir={pyqt_path}=platforms",
        "--include-package=hardware_locker",
        "--include-package=cryptography",
        "--include-package=cryptography.fernet",
        "--include-package=cryptography.hazmat.primitives",
        "--include-package=cryptography.hazmat.primitives.asymmetric",
        "--include-package=cryptography.hazmat.primitives.serialization",
        "--include-package=cryptography.hazmat.backends",
        "--include-package=requests",
        "--include-package=urllib3",
        "--include-package=certifi",
        "--include-package-data=certifi",
        "--include-package=charset_normalizer",
        "--include-package=idna",
        "--include-package=vlc",
        "--lto=yes",
        f"--jobs={os.cpu_count() or 4}",
        "--assume-yes-for-downloads",
        f"--output-dir={BuildDir}",
        f"--output-filename={AppName}.exe",
        EntryFile,
    ]
    print("Running:")
    print(" ".join(cmd))
    print()
    subprocess.run(cmd, check=True)

    dist_path = APP_DIR / BuildDir / "app.dist"
    if dist_path.is_dir():
        dest = APP_DIR / AppName
        # The old folder can be briefly locked by antivirus/Search after a build.
        # Retry, and if it stays locked fall back to a side folder instead of crashing.
        if dest.exists():
            removed = False
            for _ in range(8):
                try:
                    shutil.rmtree(dest)
                    removed = True
                    break
                except (PermissionError, OSError):
                    time.sleep(2)
            if not removed:
                dest = APP_DIR / (AppName + "_new")
                if dest.exists():
                    shutil.rmtree(dest, ignore_errors=True)
                print("NOTE: old DedSecLab folder is locked (antivirus/Explorer).")
                print(f"      Writing this build to {dest.name} instead.")
                print("      Close that folder / let your antivirus finish, delete the old")
                print("      DedSecLab folder, then rename this one to DedSecLab.")
        shutil.move(str(dist_path), str(dest))
        updater = APP_DIR / "DedSecLabUpdater.exe"
        if updater.is_file():
            # Ship as a non-.exe blob under assets so users never see DedSecLabUpdater.exe
            assets = dest / "assets"
            assets.mkdir(parents=True, exist_ok=True)
            placed = assets / "dsl_upd.bin"
            shutil.copy2(updater, placed)
            _win_hide(placed)
            print(f"Updater embedded (hidden): {placed}")
        else:
            print("DedSecLabUpdater.exe not found. Run build_updater.py (option 5), then build again.")
        harden_output(dest)
        exe = dest / (AppName + ".exe")
        size_mb = exe.stat().st_size / (1024 * 1024) if exe.is_file() else 0
        print(f"\nBuild complete: {exe}  ({size_mb:.1f} MB)")
    else:
        print("Build finished but dist folder was not found.")


def install_tools():
    py = python_bin()
    if not Path(py).is_file():
        print(f"Creating venv at {APP_DIR / 'venv'} ...")
        subprocess.run([sys.executable, "-m", "venv", str(APP_DIR / "venv")], check=False)
        py = python_bin()
    if not Path(py).is_file():
        print("Could not create or find the project venv.")
        return
    print(f"Installing tools into:\n  {py}")
    pkgs = [
        "pip", "nuitka", "ordered-set", "zstandard", "PyQt6",
        "cryptography", "requests", "certifi", "python-vlc",
    ]
    cmd = [py, "-m", "pip", "install", "--upgrade", *pkgs]
    r = subprocess.run(cmd)
    if r.returncode != 0:
        print("pip failed. Do not use the uv system Python for this builder.")
        print("Use the project venv:")
        print(f'  {VENV_PY} "{Path(__file__).resolve()}"')
        return
    print("Tools installed.")


def main_menu():
    while True:
        clear()
        print("==============================")
        print(f" {AppName} Build Menu")
        print("==============================")
        print(f" App : {APP_DIR}")
        print(f" Py  : {python_bin()}")
        print(f" Ver : {app_version()}")
        print("------------------------------")
        print("1. Clean old builds")
        print("2. Build with Nuitka (Release)")
        print("3. Build with Nuitka (Debug - console ON)")
        print("4. Install/update build tools")
        print("5. Build updater only")
        print("0. Exit")
        try:
            choice = input("\nChoose an option: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nUse 0 to exit.")
            pause()
            continue
        if choice == "1":
            clean_builds()
            pause()
        elif choice == "2":
            try:
                build_nuitka(debug=False)
            except subprocess.CalledProcessError as e:
                print(f"Build failed: {e}")
            pause()
        elif choice == "3":
            try:
                build_nuitka(debug=True)
            except subprocess.CalledProcessError as e:
                print(f"Build failed: {e}")
            pause()
        elif choice == "4":
            try:
                install_tools()
            except subprocess.CalledProcessError as e:
                print(f"Install failed: {e}")
            pause()
        elif choice == "5":
            try:
                build_updater(python_bin())
            except subprocess.CalledProcessError as e:
                print(f"Updater build failed: {e}")
            pause()
        elif choice == "0":
            break
        else:
            print("Invalid option.")
            pause()


if __name__ == "__main__":
    if not APP_DIR.is_dir():
        print(f"APP_DIR not found: {APP_DIR}")
        sys.exit(1)
    os.chdir(APP_DIR)
    main_menu()
