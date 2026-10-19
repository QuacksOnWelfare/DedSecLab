import os
import shutil
import subprocess
import sys
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
os.chdir(APP_DIR)

EntryFile = "updater.py"
OutName = "DedSecLabUpdater.exe"
BuildDir = "nuitka_updater"
IconFile = os.path.join("assets", "dedsec_logo.ico")


def pause():
    input("\nPress Enter to continue...")


def main():
    if not Path(EntryFile).is_file():
        print(f"Missing {EntryFile} in {APP_DIR}")
        print("Copy updater.py into the project root first.")
        pause()
        return

    shutil.rmtree(BuildDir, ignore_errors=True)
    print("Building DedSecLabUpdater.exe with Nuitka...")

    cmd = [
        sys.executable, "-m", "nuitka",
        "--onefile",
        "--windows-console-mode=hide",
        "--assume-yes-for-downloads",
        f"--output-dir={BuildDir}",
        f"--output-filename={OutName}",
        EntryFile,
    ]
    if Path(IconFile).is_file():
        cmd.insert(-1, f"--windows-icon-from-ico={IconFile}")

    print(" ".join(cmd))
    r = subprocess.run(cmd)
    if r.returncode != 0:
        print("Build failed.")
        pause()
        return

    built = Path(BuildDir) / OutName
    if not built.is_file():
        # nuitka onefile sometimes lands as EntryFile.dist sibling
        for cand in Path(BuildDir).rglob(OutName):
            built = cand
            break
    if not built.is_file():
        print("Built exe not found.")
        pause()
        return

    dest_dir = Path("DedSecLab")
    dest_dir.mkdir(exist_ok=True)
    dest = dest_dir / OutName
    shutil.copy2(built, dest)
    root_copy = Path(OutName)
    shutil.copy2(built, root_copy)
    print(f"OK  {dest}")
    print(f"OK  {root_copy}")
    print("Put DedSecLabUpdater.exe next to DedSecLab.exe in the zip.")
    pause()


if __name__ == "__main__":
    main()
