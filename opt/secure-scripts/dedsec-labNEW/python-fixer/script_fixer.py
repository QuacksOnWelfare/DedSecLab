#!/usr/bin/env python3

import os
import sys
import shutil
import subprocess
import py_compile
from pathlib import Path
from datetime import datetime

import json
import importlib.util

DEDSEC_BASE_DIR = "/opt/secure-scripts/dedsec-labNEW"
DEDSEC_THEMES_FILE = f"{DEDSEC_BASE_DIR}/user_themes.json"
DEDSEC_BANNER_FILE = f"{DEDSEC_BASE_DIR}/utils/banner.py"

RESET = "\033[0m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
WHITE = "\033[97m"
RED = "\033[31m"
BOLD = "\033[1m"


def get_theme_key():
    ip = os.environ.get("DEDSEC_SOURCE_IP", "").strip()
    if ip and ip != "unknown":
        return ip
    user = os.environ.get("DEDSEC_USER", "").strip()
    if user:
        return user
    return "default"


def load_theme():
    try:
        with open(DEDSEC_THEMES_FILE, "r", encoding="utf-8") as f:
            themes = json.load(f)
    except Exception:
        return "default"

    role = os.environ.get("DEDSEC_ROLE", "standard").strip().lower()
    if role != "admin":
        return "default"

    return themes.get(get_theme_key(), "default")


def apply_theme():
    global GREEN, CYAN, WHITE, YELLOW, RED

    GREEN = "\033[32m"
    CYAN = "\033[36m"
    WHITE = "\033[97m"
    YELLOW = "\033[33m"
    RED = "\033[31m"

    theme = load_theme()

    if theme == "red":
        GREEN = "\033[31m"
        CYAN = "\033[31m"
        YELLOW = "\033[91m"
    elif theme == "minimal":
        GREEN = "\033[97m"
        CYAN = "\033[97m"
        YELLOW = "\033[97m"
        RED = "\033[97m"
    elif theme == "blue":
        GREEN = "\033[34m"
        CYAN = "\033[94m"
        YELLOW = "\033[94m"
    elif theme == "purple":
        GREEN = "\033[35m"
        CYAN = "\033[95m"
        YELLOW = "\033[95m"
    elif theme == "cyan":
        GREEN = "\033[36m"
        CYAN = "\033[36m"
        YELLOW = "\033[96m"
    elif theme == "yellow":
        GREEN = "\033[33m"
        CYAN = "\033[93m"
        YELLOW = "\033[93m"


class C:
    RED = RED
    GREEN = GREEN
    YELLOW = YELLOW
    BLUE = CYAN
    RESET = RESET


try:
    import banner
except ImportError:
    banner = None


VENV_DIR = Path.home() / "fixer-env"
VENV_BIN = VENV_DIR / "bin"
VENV_PYTHON = VENV_BIN / "python"
VENV_PIP = VENV_BIN / "pip"

TOOL_PATHS = {
    "ruff": VENV_BIN / "ruff",
    "black": VENV_BIN / "black",
    "isort": VENV_BIN / "isort",
    "autopep8": VENV_BIN / "autopep8",
}

PROJECT_DIR = Path(__file__).resolve().parent
BACKUP_DIR = PROJECT_DIR / "backups"
BROKEN_DIR = PROJECT_DIR / "broken-scripts"

BACKUP_DIR.mkdir(exist_ok=True)
BROKEN_DIR.mkdir(exist_ok=True)


def show_banner():
    apply_theme()
    os.system("clear")

    if os.path.isfile(DEDSEC_BANNER_FILE):
        try:
            spec = importlib.util.spec_from_file_location("dedsec_banner", DEDSEC_BANNER_FILE)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            mod.dedsec_banner(GREEN, CYAN, RESET, BOLD, apply_theme)
            return
        except Exception:
            pass

    print(f"{GREEN}{'=' * 60}{RESET}")
    print(f"{CYAN}{BOLD}        ADVANCED PYTHON SCRIPT FIXER{RESET}")
    print(f"{GREEN}{'=' * 60}{RESET}")


def pause():
    input(f"\n{YELLOW}Press Enter to continue...{RESET}")


def in_venv():
    return sys.prefix != sys.base_prefix


def tool_exists(tool_name):
    tool_path = TOOL_PATHS.get(tool_name)
    return tool_path and tool_path.exists()


def tool_cmd(tool_name):
    return str(TOOL_PATHS[tool_name])


def show_rules():
    print("\n" + "=" * 60)
    print("                PYTHON FIXER RULES")
    print("=" * 60)

    print("""
1. DO NOT RUN WITH SUDO
   Use:
   python3 script_fixer.py

2. USE fixer-env
   Tools should be installed in:
   ~/fixer-env/bin/

3. INSTALL TOOLS FIRST
   Use menu option 3.

4. FORMATTERS DO NOT FIX ALL BROKEN CODE
   Ruff, Black, isort, and autopep8 mostly fix valid Python.

5. BACKUPS ARE IMPORTANT
   This tool creates a backup before editing.

6. REVIEW YOUR FILE AFTER FIXING
   Auto-fix tools can make mistakes.

7. DIAGNOSE BEFORE AUTO-REPAIR
   Use option 7 before option 8 if you want to see what is wrong.

8. AUTO-REPAIR IS LIMITED
   Option 8 only attempts simple fixes like:
   - uneven indentation
   - missing quote in simple print statements
   - one-line if print statements
""")


def create_venv():
    if VENV_DIR.exists():
        print(f"{C.GREEN}[OK]{C.RESET} Virtual environment exists: {VENV_DIR}")
        return True

    print(f"[INFO] Creating virtual environment at {VENV_DIR}...")
    result = subprocess.run([sys.executable, "-m", "venv", str(VENV_DIR)])

    if result.returncode == 0:
        print(f"{C.GREEN}[OK]{C.RESET} Virtual environment created.")
        return True

    print(f"{C.RED}[ERROR]{C.RESET} Failed to create virtual environment.")
    print("Try:")
    print("sudo apt install python3-venv python3-full")
    return False


def install_tools_in_venv():
    if not create_venv():
        return

    if not VENV_PIP.exists():
        print(f"{C.RED}[ERROR]{C.RESET} pip not found inside fixer-env.")
        return

    print(f"{C.BLUE}[INFO]{C.RESET} Installing tools inside fixer-env...")
    subprocess.run(
        [
            str(VENV_PIP),
            "install",
            "--upgrade",
            "pip",
            "ruff",
            "black",
            "isort",
            "autopep8",
        ],
        check=False,
    )


def restart_inside_venv():
    if not create_venv():
        pause()
        return

    if not VENV_PYTHON.exists():
        print(f"{C.RED}[ERROR]{C.RESET} venv Python not found.")
        pause()
        return

    print(f"{C.BLUE}[INFO]{C.RESET} Restarting inside fixer-env...")
    os.execv(str(VENV_PYTHON), [str(VENV_PYTHON), __file__])


def open_venv_shell():
    if not create_venv():
        pause()
        return

    print(f"{C.BLUE}[INFO]{C.RESET} Opening shell inside fixer-env.")
    print(f"{C.BLUE}[INFO]{C.RESET} Type 'exit' to return.")
    subprocess.run(["bash", "-c", f"source {VENV_DIR}/bin/activate && exec bash"])


def ask_script_path():
    path = input("\nEnter full path to Python script: ").strip().strip('"')
    file_path = Path(path).expanduser()

    if not file_path.exists():
        print(f"{C.RED}[ERROR]{C.RESET} File does not exist.")
        return None

    if file_path.suffix != ".py":
        print(f"{C.RED}[ERROR]{C.RESET} File must be a .py script.")
        return None

    return file_path




def ask_backup():
    choice = input("Create backup before modifying? (y/n): ").strip().lower()
    return choice == "y"
def make_backup(file_path):
    BACKUP_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_name = f"{file_path.stem}.backup_{timestamp}.py"
    backup_path = BACKUP_DIR / backup_name
    shutil.copy2(file_path, backup_path)
    print(f"{C.GREEN}[OK]{C.RESET} Backup created: {backup_path}")


def run_command(command, file_path):
    full_command = command + [str(file_path)]
    print(f"\n> {' '.join(full_command)}")

    result = subprocess.run(
        full_command,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.stdout:
        print(result.stdout)

    if result.stderr:
        print(result.stderr)

    return result.returncode == 0


def basic_cleanup(file_path):
    print(f"\n{C.BLUE}[INFO]{C.RESET} Running built-in cleanup...")

    try:
        text = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        text = file_path.read_text(encoding="latin-1")

    lines = []
    for line in text.splitlines():
        lines.append(line.rstrip().replace("\t", "    "))

    file_path.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")
    print(f"{C.GREEN}[OK]{C.RESET} Basic cleanup complete.")


def check_syntax(file_path):
    print(f"\n{C.BLUE}[INFO]{C.RESET} Checking syntax...")

    try:
        py_compile.compile(str(file_path), doraise=True)
        print(f"{C.GREEN}[OK]{C.RESET} No syntax errors found.")
        return True
    except py_compile.PyCompileError as error:
        print(f"{C.RED}[ERROR]{C.RESET} Syntax error still exists:")
        print(error)
        return False


def diagnose_script(file_path):
    print(f"\n{GREEN}" + "=" * 60 + f"{RESET}")
    print(f"{CYAN}{BOLD}                 SCRIPT DIAGNOSIS{RESET}")
    print(f"{GREEN}" + "=" * 60 + f"{RESET}")

    try:
        py_compile.compile(str(file_path), doraise=True)
        print(f"{C.GREEN}[OK]{C.RESET} No syntax errors found.")
    except py_compile.PyCompileError as error:
        print(f"{C.RED}[ERROR]{C.RESET} Python reported:")
        print(error)

    lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()

    print(f"\n{YELLOW}{BOLD}Suggested checks:{RESET}")

    found = False

    for index, line in enumerate(lines, start=1):
        stripped = line.strip()

        if not stripped:
            continue

        current_indent = len(line) - len(line.lstrip(" "))

        if current_indent % 4 != 0:
            found = True
            suggested_indent = max(4, round(current_indent / 4) * 4)
            suggested_line = " " * suggested_indent + stripped

            print(f"\n{YELLOW}{BOLD}Line {index}: uneven indentation{RESET}")
            print(f"{CYAN}Current indentation:{RESET} {RED}{current_indent} spaces{RESET}")
            print(f"{CYAN}Suggested indentation:{RESET} {GREEN}{suggested_indent} spaces{RESET}")
            print(f"{RED}Current:{RESET}")
            print(f"{RED}{line}{RESET}")
            print(f"{GREEN}Suggested:{RESET}")
            print(f"{GREEN}{suggested_line}{RESET}")

        if stripped.startswith("print(") and stripped.count('"') % 2 != 0:
            found = True
            suggested = stripped.rstrip()[:-1] + '")'
            print(f"\n{YELLOW}{BOLD}Line {index}: possible missing quote{RESET}")
            print(f"{RED}Current:{RESET}")
            print(f"{RED}{stripped}{RESET}")
            print(f"{GREEN}Suggested:{RESET}")
            print(f"{GREEN}{suggested}{RESET}")

        if stripped.startswith("if ") and ": print(" in stripped:
            found = True
            condition, action = stripped.split(":", 1)
            print(f"\n{YELLOW}{BOLD}Line {index}: one-line if statement{RESET}")
            print(f"{RED}Current:{RESET}")
            print(f"{RED}{stripped}{RESET}")
            print(f"{GREEN}Suggested:{RESET}")
            print(condition + ":")
            print(f"{GREEN}    " + action.strip() + f"{RESET}")

    if not found:
        print("No simple repair suggestions found.")


def auto_repair_common_errors(file_path):
    print(f"\n{C.BLUE}[INFO]{C.RESET} Attempting common auto-repairs...")
    if ask_backup():
        make_backup(file_path)

    text = file_path.read_text(encoding="utf-8", errors="replace")
    raw_lines = text.splitlines()
    fixed = []

    previous_opens_block = False
    previous_indent = 0

    for line in raw_lines:
        stripped = line.strip()

        if not stripped:
            fixed.append("")
            continue

        # Fix one-line if print into normal block
        if stripped.startswith("if ") and ": print(" in stripped:
            indent = line[: len(line) - len(line.lstrip())]
            condition, action = stripped.split(":", 1)
            fixed.append(indent + condition + ":")
            fixed.append(indent + "    " + action.strip())
            previous_opens_block = False
            previous_indent = len(indent) + 4
            continue

        # Fix simple missing quote: print("hello)
        if stripped.startswith("print(") and stripped.count('"') % 2 != 0:
            line = line.rstrip()[:-1] + '")'
            stripped = line.strip()

        leading = len(line) - len(line.lstrip(" "))

        # If previous line ended with :, current real code must be indented
        if previous_opens_block and leading <= previous_indent:
            leading = previous_indent + 4
            line = " " * leading + stripped

        # Round weird indentation to a 4-space block, but never to 0
        leading = len(line) - len(line.lstrip(" "))
        if leading and leading % 4 != 0:
            nearest = max(4, round(leading / 4) * 4)
            line = " " * nearest + line.lstrip()

        fixed.append(line)

        previous_indent = len(line) - len(line.lstrip(" "))
        previous_opens_block = stripped.endswith(":")

    file_path.write_text("\n".join(fixed).strip() + "\n", encoding="utf-8")
    print(f"{C.GREEN}[OK]{C.RESET} Common auto-repair pass complete.")


def fix_script(file_path):
    if ask_backup():
        make_backup(file_path)

    found_tool = False

    if tool_exists("ruff"):
        found_tool = True
        run_command([tool_cmd("ruff"), "check", "--fix"], file_path)
        run_command([tool_cmd("ruff"), "format"], file_path)

    if tool_exists("isort"):
        found_tool = True
        run_command([tool_cmd("isort")], file_path)

    if tool_exists("black"):
        found_tool = True
        run_command([tool_cmd("black")], file_path)

    if tool_exists("autopep8"):
        found_tool = True
        run_command(
            [
                tool_cmd("autopep8"),
                "--in-place",
                "--aggressive",
                "--aggressive",
            ],
            file_path,
        )

    if not found_tool:
        print(f"\n{C.YELLOW}[WARN]{C.RESET} No fixer tools found inside fixer-env.")
        print("Use menu option 3 to install them.")
        basic_cleanup(file_path)

    check_syntax(file_path)
    print("\n[DONE] Fix complete.")


def show_tool_status():
    print("\nPython executable:")
    print(sys.executable)

    print("\nVirtual environment active:")
    print("YES" if in_venv() else "NO")

    print("\nExpected fixer-env:")
    print(VENV_DIR)

    print("\nTool status:")
    for tool in ["ruff", "black", "isort", "autopep8"]:
        path = TOOL_PATHS[tool]
        status = "installed" if path.exists() else "missing"
        print(f"- {tool}: {status} ({path})")


def main_menu():
    while True:
        show_banner()

        print(f"Running Python: {sys.executable}")
        print(f"Venv active: {'YES' if in_venv() else 'NO'}")

        if str(sys.executable).startswith("/root/"):
            print("\n[WARNING] You are running from /root.")
            print("You probably used sudo. Exit and run without sudo.")

        print(f"\n{CYAN}{BOLD}1.{RESET}  {WHITE}Fix a Python script{RESET}")
        print(f"{CYAN}{BOLD}2.{RESET}  {WHITE}Check installed fixer tools{RESET}")
        print(f"{CYAN}{BOLD}3.{RESET}  {WHITE}Install tools into fixer-env{RESET}")
        print(f"{CYAN}{BOLD}4.{RESET}  {WHITE}Restart this fixer inside fixer-env{RESET}")
        print(f"{CYAN}{BOLD}5.{RESET}  {WHITE}Open shell inside fixer-env{RESET}")
        print(f"{CYAN}{BOLD}6.{RESET}  {WHITE}Show rules{RESET}")
        print(f"{CYAN}{BOLD}7.{RESET}  {WHITE}Diagnose script errors{RESET}")
        print(f"{CYAN}{BOLD}8.{RESET}  {WHITE}Attempt auto-repair then fix{RESET}")
        print(f"{CYAN}{BOLD}9.{RESET}  {WHITE}Exit{RESET}")

        choice = input(f"\n{YELLOW}Select an option:{RESET} ").strip()

        if choice == "1":
            file_path = ask_script_path()
            if file_path:
                fix_script(file_path)
            pause()

        elif choice == "2":
            show_tool_status()
            pause()

        elif choice == "3":
            install_tools_in_venv()
            pause()

        elif choice == "4":
            restart_inside_venv()

        elif choice == "5":
            open_venv_shell()
            pause()

        elif choice == "6":
            show_rules()
            pause()

        elif choice == "7":
            file_path = ask_script_path()
            if file_path:
                diagnose_script(file_path)
            pause()

        elif choice == "8":
            file_path = ask_script_path()
            if file_path:
                auto_repair_common_errors(file_path)
                fix_script(file_path)
            pause()

        elif choice == "9":
            print("Goodbye.")
            break

        else:
            print(f"{C.RED}[ERROR]{C.RESET} Invalid option.")
            pause()


if __name__ == "__main__":
    main_menu()

