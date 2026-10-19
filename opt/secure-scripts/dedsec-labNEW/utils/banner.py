"""DedSec Lab banner - matches the menu.py visual system.

Signature is unchanged: dedsec_banner(GREEN, CYAN, RESET, BOLD, apply_theme)
Uses only the passed-in theme colours for green/cyan (never hard-coded),
plus standard ANSI WHITE / DIM for text hierarchy.

When `lolcat` is on PATH the DEDSEC wordmark is rainbowed through one
`lolcat -f` call; the cyan frame and tagline stay themed. If lolcat is
missing or fails, the existing theme shading is used instead.
"""
import os
import re
import shutil
import subprocess
import sys

# Standard ANSI (not theme hues). WHITE is never re-themed in menu.py;
# DIM is an attribute, not a colour.
WHITE = "\033[97m"
DIM = "\033[2m"
RESET = "\033[0m"  # default; dedsec_banner may rebind locally

# Strip any CSI sequence (SGR + anything else lolcat might emit).
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

# Cached shutil.which("lolcat") result. None = not looked up yet;
# False = looked up and missing; str = absolute path.
_LOLCAT_PATH = None

_WORDMARK = [
    "██████╗ ███████╗██████╗ ███████╗███████╗ ██████╗",
    "██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝",
    "██║  ██║█████╗  ██║  ██║███████╗█████╗  ██║     ",
    "██║  ██║██╔══╝  ██║  ██║╚════██║██╔══╝  ██║     ",
    "██████╔╝███████╗██████╔╝███████║███████╗╚██████╗",
    "╚═════╝ ╚══════╝╚═════╝ ╚══════╝╚══════╝ ╚═════╝",
]

_ASCII_WORDMARK = [
    "######   ####### ######   ####### #######  ###### ",
    "##   ##  ##      ##   ##  ##      ##      ##      ",
    "##   ##  #####   ##   ##  ####### #####   ##      ",
    "##   ##  ##      ##   ##       ## ##      ##      ",
    "######   ####### ######   ####### #######  ###### ",
    "                                                  ",
]


def _supports_utf8():
    """Same detection as menu.py."""
    enc = (sys.stdout.encoding or "").lower()
    if "utf" in enc:
        return True
    for var in ("LC_ALL", "LC_CTYPE", "LANG"):
        if "utf" in os.environ.get(var, "").lower():
            return True
    return False


UTF8 = _supports_utf8()

if UTF8:
    BX = {"tl": "\u256d", "tr": "\u256e", "bl": "\u2570", "br": "\u256f",
          "h": "\u2500", "v": "\u2502", "lt": "\u251c", "rt": "\u2524"}
    BULLET = "\u2022"
else:
    BX = {"tl": "+", "tr": "+", "bl": "+", "br": "+",
          "h": "-", "v": "|", "lt": "+", "rt": "+"}
    BULLET = "*"


def vlen(s):
    return len(_ANSI_RE.sub("", s))


def term_width():
    """Match menu.py: terminal width clamped to 60-90."""
    cols = shutil.get_terminal_size((80, 24)).columns
    return max(60, min(90, cols))


def _pad(s, width):
    gap = width - vlen(s)
    return s + (" " * gap if gap > 0 else "")


def _lolcat_bin():
    """Return the lolcat executable path, or None. Cached for the process."""
    global _LOLCAT_PATH
    if _LOLCAT_PATH is None:
        found = shutil.which("lolcat")
        _LOLCAT_PATH = found if found else False
    return _LOLCAT_PATH if _LOLCAT_PATH else None


def _shade_wordmark(line, GREEN, CYAN, BOLD, RESET):
    """Main fill in CYAN+BOLD; GREEN only on shadow/outline glyphs."""
    out = []
    run = []
    mode = None  # "fill" | "shadow" | "plain"

    def flush():
        nonlocal run, mode
        if not run:
            return
        text = "".join(run)
        if mode == "fill":
            out.append(f"{CYAN}{BOLD}{text}{RESET}")
        elif mode == "shadow":
            out.append(f"{GREEN}{text}{RESET}")
        else:
            out.append(text)
        run = []

    for ch in line:
        if ch == "█":
            m = "fill"
        elif ch in "╗╔╝╚═║":
            m = "shadow"
        else:
            m = "plain"
        if m != mode:
            flush()
            mode = m
        run.append(ch)
    flush()
    return "".join(out)


def _rainbow_wordmark(padded_lines):
    """Pipe a plain wordmark block through `lolcat -f`.

    Returns a list of coloured lines matching the input length, or None
    if lolcat is missing / fails / returns the wrong number of lines.
    Never raises.
    """
    bin_path = _lolcat_bin()
    if not bin_path:
        return None
    try:
        payload = "\n".join(padded_lines) + "\n"
        proc = subprocess.run(
            [bin_path, "-f"],
            input=payload,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0 or not proc.stdout:
        return None
    # Drop a trailing empty split caused by the final newline.
    coloured = proc.stdout.splitlines()
    if len(coloured) != len(padded_lines):
        return None
    return coloured


def _draw_box_lines(lines, color, width, title=None, reset=None):
    """Replica of menu.py draw_box - returns lines (does not print)."""
    if reset is None:
        reset = RESET
    inner = width - 4
    out = []
    if title:
        t = f" {title} "
        fill = width - 2 - vlen(t)
        if fill < 0:
            fill = 0
        out.append(f"{color}{BX['tl']}{BX['h']}{t}{BX['h'] * fill}{BX['tr']}{reset}")
    else:
        out.append(f"{color}{BX['tl']}{BX['h'] * (width - 2)}{BX['tr']}{reset}")
    for ln in lines:
        if ln == "__sep__":
            out.append(f"{color}{BX['lt']}{BX['h'] * (width - 2)}{BX['rt']}{reset}")
            continue
        out.append(f"{color}{BX['v']}{reset} {_pad(ln, inner)} {color}{BX['v']}{reset}")
    out.append(f"{color}{BX['bl']}{BX['h'] * (width - 2)}{BX['br']}{reset}")
    return out


def dedsec_banner(GREEN, CYAN, RESET, BOLD, apply_theme):
    apply_theme()
    width = term_width()
    inner = width - 4

    wordmark = list(_WORDMARK if UTF8 else _ASCII_WORDMARK)
    # Drop a trailing blank ASCII row if present.
    while wordmark and not wordmark[-1].strip():
        wordmark.pop()

    mark_w = max(len(w) for w in wordmark)
    # Centre the wordmark inside the content area.
    left_pad = max(0, (inner - mark_w) // 2)
    pad = " " * left_pad

    # Build the plain, already-padded wordmark block first so we can feed
    # it to lolcat as one shot (or colour it ourselves on fallback).
    plain_padded = []
    for wm in wordmark:
        plain = wm.ljust(mark_w)[:mark_w]
        plain_padded.append(pad + plain)

    rainbowed = _rainbow_wordmark(plain_padded)

    body = []
    body.append("")  # top breathing room
    if rainbowed is not None:
        body.extend(rainbowed)
    else:
        for plain in plain_padded:
            # plain already includes left_pad; shade only the mark part.
            mark = plain[left_pad:]
            if UTF8:
                coloured = _shade_wordmark(mark, GREEN, CYAN, BOLD, RESET)
            else:
                coloured = f"{CYAN}{BOLD}{mark}{RESET}"
            body.append(pad + coloured)

    body.append("")  # gap before tagline

    # Tagline mirrors the status-bar bullet style:
    #   WHITE primary  •  DIM secondary
    # Never lolcat'd - stays themed.
    tag = (
        f"{WHITE}{BOLD}DEDSEC LAB{RESET}"
        f"  {DIM}{BULLET}{RESET}  "
        f"{DIM}secure access terminal{RESET}"
    )
    tag_pad = max(0, (inner - vlen(tag)) // 2)
    body.append((" " * tag_pad) + tag)
    body.append("")  # bottom breathing room

    for line in _draw_box_lines(body, CYAN, width, reset=RESET):
        print(line)


if __name__ == "__main__":
    # Preview: banner + sample status bar + sample menu box, all sharing
    # the same width / frame / colour system as menu.py.
    GREEN = "\033[32m"
    CYAN = "\033[36m"
    RESET = "\033[0m"
    BOLD = "\033[1m"
    YELLOW = "\033[33m"
    RED = "\033[31m"

    def _noop():
        return None

    dedsec_banner(GREEN, CYAN, RESET, BOLD, _noop)

    width = term_width()
    sep = f"  {DIM}{BULLET}{RESET}  "
    status = sep.join([
        f"{WHITE}YOUR_OWNER_DISPLAY_NAME{RESET}",
        f"{RED}{BOLD}[OWNER]{RESET}",
        f"{CYAN}UK{RESET}",
        f"{GREEN}42d left{RESET}",
        f"{DIM}15:16{RESET}",
    ])
    for line in _draw_box_lines([status], CYAN, width):
        print(line)

    print(f"{CYAN}{BOLD}>{RESET} "
          f"{DIM}Main{RESET} {DIM}{BULLET}{RESET} {WHITE}Tools{RESET}\n")

    inner = width - 4
    items = [
        (f"{CYAN}{BOLD} 1{RESET}  {WHITE}Network Tools{RESET}",
         f"{DIM}scanners, sniffers{RESET}"),
        (f"{CYAN}{BOLD} 2{RESET}  {WHITE}Web Tools{RESET}",
         f"{DIM}recon, proxies{RESET}"),
        (f"{CYAN}{BOLD} 3{RESET}  {WHITE}Back{RESET}",
         f"{DIM}return{RESET}"),
    ]
    menu_lines = []
    for left, right in items:
        gap = inner - vlen(left) - vlen(right)
        if gap < 1:
            gap = 1
        menu_lines.append(left + (" " * gap) + right)
    for line in _draw_box_lines(menu_lines, CYAN, width, title="TOOLS"):
        print(line)
