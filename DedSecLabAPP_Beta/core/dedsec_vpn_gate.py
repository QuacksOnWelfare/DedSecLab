"""DedSec VPN gate - in-process. Skip if already on 10.8.0.x (router)."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import threading
from pathlib import Path

from PyQt6.QtCore import QPoint, QRectF, QThread, QUrl, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QAction, QColor, QDesktopServices, QFont, QIcon, QPainter, QPainterPath, QPixmap, QRegion
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QFrame,
    QGraphicsDropShadowEffect,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QProgressBar,
    QScrollArea,
    QPushButton,
    QSizePolicy,
    QStackedWidget,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

try:
    from core import flags as _flags
except ImportError:  # pragma: no cover - package-relative fallback
    from . import flags as _flags

CYAN = "#2ee6ff"
BG = "#0a1624"
CARD = "#102033"
PANEL = "#0d1c2c"
MUTED = "#7d93a8"
TEXT = "#eef6ff"

STYLE = """
QWidget#VpnRoot {
    background-color: transparent;
    color: #eef6ff;
    font-family: "Segoe UI";
    border: 2px solid #2ee6ff;
    border-radius: 16px;
}
QWidget#VpnRoot QWidget {
    background-color: transparent;
    color: #eef6ff;
    font-family: "Segoe UI";
}
QWidget#VpnRoot QLabel {
    background: transparent;
    border: none;
    color: #eef6ff;
    padding: 0;
}
QWidget#VpnRoot QLabel#brand {
    color: #2ee6ff;
    font-size: 18px;
    font-weight: 800;
    letter-spacing: 4px;
}
QWidget#VpnRoot QLabel#kicker {
    color: #7d93a8;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1.4px;
}
QWidget#VpnRoot QLabel#city {
    font-size: 26px;
    font-weight: 800;
}
QWidget#VpnRoot QLabel#zone {
    color: #7d93a8;
    font-size: 13px;
}
QWidget#VpnRoot QLabel#ip {
    color: #7d93a8;
    font-size: 11px;
}
QWidget#VpnRoot QLabel#on {
    color: #2ee6ff;
    font-weight: 800;
    font-size: 18px;
}
QWidget#VpnRoot QLabel#proto {
    color: #7d93a8;
    font-weight: 600;
    font-size: 12px;
}
QWidget#VpnRoot QPushButton#iconBtn {
    background: transparent;
    border: none;
    color: #7d93a8;
    font-size: 16px;
    min-width: 28px;
    max-width: 28px;
}
QWidget#VpnRoot QPushButton#iconBtn:pressed {
    color: #2ee6ff;
    background: rgba(46,230,255,0.12);
    border-radius: 6px;
}
QWidget#VpnRoot QPushButton#power {
    background: #0d1c2c;
    border: 2px solid #2ee6ff;
    border-radius: 42px;
    min-width: 84px;
    max-width: 84px;
    min-height: 84px;
    max-height: 84px;
    padding: 0;
    margin: 0;
    color: #2ee6ff;
    font-size: 28px;
    font-weight: 800;
}
QWidget#VpnRoot QPushButton#power:hover {
    background: rgba(46,230,255,0.08);
}
QWidget#VpnRoot QPushButton#power:pressed {
    background: rgba(46,230,255,0.24);
    border: 2px solid #5af0ff;
    padding-top: 3px;
}
QWidget#VpnRoot QPushButton#power:disabled {
    border: 2px solid #3a5166;
    color: #5b6f82;
    background: #102033;
}
QWidget#VpnRoot QPushButton#power[connected="true"] {
    background: #0d1c2c;
    border: 2px solid #00e68a;
    color: #00e68a;
}
QWidget#VpnRoot QPushButton#power[connected="true"]:pressed {
    background: rgba(0,230,138,0.22);
    border: 2px solid #00e68a;
    padding-top: 3px;
}
QWidget#VpnRoot QPushButton#lab {
    background: #2ee6ff;
    color: #04212a;
    border: none;
    border-radius: 10px;
    padding: 10px 14px;
    font-weight: 800;
}
QWidget#VpnRoot QPushButton#lab:disabled {
    background: #1a2a38;
    color: #5b6f82;
}
QWidget#VpnRoot QPushButton#ghost {
    background: #152433;
    color: #eef6ff;
    border: 1px solid #24384c;
    border-radius: 8px;
    padding: 8px 12px;
}
QWidget#VpnRoot QLineEdit {
    background: #0b1722;
    border: 1px solid #24384c;
    border-radius: 8px;
    padding: 8px;
    color: #eef6ff;
}
QWidget#VpnRoot QFrame#hero, QWidget#VpnRoot QFrame#fw, QWidget#VpnRoot QFrame#foot {
    background: #0d1c2c;
    border: none;
    border-radius: 16px;
}
QWidget#VpnRoot QFrame#loc {
    background: #102033;
    border: 1px solid #1b3044;
    border-radius: 12px;
}
QWidget#VpnRoot QFrame#VpnSettingsSection {
    background: #0d1c2c;
    border: 1px solid #1b3044;
    border-radius: 14px;
}
QWidget#VpnRoot QLabel#VpnSettingsSectionTitle {
    color: #2ee6ff;
    font-size: 11px;
    font-weight: 800;
    letter-spacing: 1.4px;
}
QWidget#VpnRoot QLabel#VpnSettingsRowTitle {
    color: #eef6ff;
    font-size: 13px;
    font-weight: 700;
    background: transparent;
    border: none;
}
QWidget#VpnRoot QLabel#VpnSettingsRowHint {
    color: #7d93a8;
    font-size: 11px;
    background: transparent;
    border: none;
}
QWidget#VpnRoot QPushButton#VpnToggle {
    background: #152433;
    border: 1px solid #24384c;
    border-radius: 12px;
    color: #7d93a8;
    font-size: 11px;
    font-weight: 800;
    min-width: 52px;
    max-width: 52px;
    min-height: 24px;
    max-height: 24px;
    padding: 0;
}
QWidget#VpnRoot QPushButton#VpnToggle:pressed {
    background: rgba(46, 230, 255, 0.18);
    border: 1px solid #2ee6ff;
}
QWidget#VpnRoot QPushButton#VpnToggle[on="true"] {
    background: rgba(46, 230, 255, 0.18);
    border: 1px solid #2ee6ff;
    color: #2ee6ff;
}
QWidget#VpnRoot QPushButton#VpnToggle[on="true"]:pressed {
    background: rgba(46, 230, 255, 0.30);
}
QWidget#VpnRoot QScrollArea#VpnSettingsScroll {
    background: transparent;
    border: none;
}
QWidget#VpnRoot QScrollArea#VpnSettingsScroll > QWidget {
    background: transparent;
}
QWidget#VpnRoot QScrollArea,
QWidget#VpnRoot QScrollArea > QWidget,
QWidget#VpnRoot QScrollArea > QWidget > QWidget {
    background: transparent;
    border: none;
}
QWidget#VpnRoot QWidget#VpnSettingsBody,
QWidget#VpnRoot QWidget#VpnLocHost,
QWidget#VpnRoot QWidget#VpnCfgHost {
    background: transparent;
}
QWidget#VpnRoot QScrollBar:vertical {
    background: #0b1722;
    width: 8px;
    margin: 0;
    border: none;
    border-radius: 4px;
}
QWidget#VpnRoot QScrollBar::handle:vertical {
    background: #24384c;
    min-height: 24px;
    border-radius: 4px;
}
QWidget#VpnRoot QScrollBar::handle:vertical:hover {
    background: #2ee6ff;
}
QWidget#VpnRoot QScrollBar::add-line:vertical,
QWidget#VpnRoot QScrollBar::sub-line:vertical,
QWidget#VpnRoot QScrollBar::add-page:vertical,
QWidget#VpnRoot QScrollBar::sub-page:vertical {
    background: transparent;
    height: 0;
    border: none;
}
QWidget#VpnRoot QPushButton {
    background: #152433;
    color: #eef6ff;
    border: 1px solid #24384c;
    border-radius: 8px;
    padding: 6px 12px;
    font-weight: 700;
}
QWidget#VpnRoot QPushButton:hover {
    border: 1px solid #2ee6ff;
    color: #2ee6ff;
}
QWidget#VpnRoot QPushButton:pressed {
    background: rgba(46,230,255,0.18);
    border: 1px solid #2ee6ff;
    padding-top: 8px;
    padding-bottom: 4px;
}
QWidget#VpnRoot QPushButton:disabled {
    background: #102033;
    color: #5b6f82;
    border: 1px solid #1b3044;
}
QWidget#VpnRoot QPushButton#ghost:hover {
    border: 1px solid #2ee6ff;
    color: #2ee6ff;
}
QWidget#VpnRoot QPushButton#ghost:pressed {
    background: rgba(46,230,255,0.18);
    border: 1px solid #2ee6ff;
    padding-top: 10px;
    padding-bottom: 6px;
}
QWidget#VpnRoot QPushButton#lab:hover {
    background: #5af0ff;
    color: #04212a;
    border: none;
}
QWidget#VpnRoot QPushButton#lab:pressed {
    background: #1bb8d4;
    color: #04212a;
    border: none;
    padding-top: 12px;
    padding-bottom: 8px;
}
QWidget#VpnRoot QLineEdit {
    background: #0b1722;
    color: #eef6ff;
    border: 1px solid #24384c;
    border-radius: 8px;
    padding: 6px 8px;
    selection-background-color: #2ee6ff;
    selection-color: #04212a;
}
QWidget#VpnRoot QLineEdit:focus {
    border: 1px solid #2ee6ff;
}
QWidget#VpnRoot QComboBox {
    background: #0b1722;
    color: #eef6ff;
    border: 1px solid #24384c;
    border-radius: 8px;
    padding: 4px 8px;
    font-size: 12px;
}
QWidget#VpnRoot QComboBox:hover,
QWidget#VpnRoot QComboBox:focus {
    border: 1px solid #2ee6ff;
}
QWidget#VpnRoot QComboBox::drop-down {
    border: none;
    width: 18px;
}
QWidget#VpnRoot QComboBox QAbstractItemView {
    background: #0d1c2c;
    color: #eef6ff;
    border: 1px solid #2ee6ff;
    selection-background-color: #2ee6ff;
    selection-color: #04212a;
    outline: none;
}
QWidget#VpnRoot QMessageBox,
QWidget#VpnRoot QDialog {
    background: #0d1c2c;
    color: #eef6ff;
}
QWidget#VpnRoot QMessageBox QLabel {
    color: #eef6ff;
    background: transparent;
}
QWidget#VpnRoot QMessageBox QPushButton {
    min-width: 72px;
}
QWidget#VpnRoot QProgressBar {
    background: #0b1722;
    color: #eef6ff;
    border: 1px solid #24384c;
    border-radius: 6px;
}
QWidget#VpnRoot QProgressBar::chunk {
    background: #2ee6ff;
}
QWidget#VpnRoot QLabel#VpnProtoBadge {
    color: #7d93a8;
    font-size: 11px;
    background: #102033;
    border: 1px solid #1b3044;
    border-radius: 8px;
    padding: 6px 10px;
}
"""


MENU_STYLE = """
QMenu {
    background-color: #0d1c2c;
    color: #eef6ff;
    border: 1px solid #2ee6ff;
    border-radius: 8px;
    padding: 6px 4px;
    font-family: "Segoe UI";
    font-size: 13px;
}
QMenu::item {
    background-color: transparent;
    color: #eef6ff;
    padding: 7px 22px 7px 14px;
    border-radius: 6px;
    margin: 1px 4px;
}
QMenu::item:selected {
    background-color: #2ee6ff;
    color: #04212a;
}
QMenu::item:disabled {
    color: #5b6f82;
}
QMenu::separator {
    height: 1px;
    background: #1b3044;
    margin: 4px 10px;
}
"""

# Opt the gate out of the app-wide light/dark inline remap (ui/styles.py).
THEME_EXEMPT_PROP = "dslThemeExempt"


def _dedsec_dark_palette():
    from PyQt6.QtGui import QPalette
    pal = QPalette()
    for role, col in (
        ("Window", "#0d1c2c"), ("Base", "#0b1722"), ("AlternateBase", "#102033"),
        ("Button", "#152433"), ("WindowText", "#eef6ff"), ("Text", "#eef6ff"),
        ("ButtonText", "#eef6ff"), ("Highlight", "#2ee6ff"), ("HighlightedText", "#04212a"),
        ("ToolTipBase", "#0d1c2c"), ("ToolTipText", "#eef6ff"), ("PlaceholderText", "#7d93a8"),
    ):
        pal.setColor(getattr(QPalette.ColorRole, role), QColor(col))
    return pal


# ---------------------------------------------------------------------------
# Light theme for the mini window. The gate is exempt from the app-wide inline
# remap, so it swaps its own colours: dark source hex -> light hex.
# ---------------------------------------------------------------------------
import re as _re
import weakref as _weakref

_GATE_D2L = {
    "#2ee6ff": "#00707f",   # cyan accent
    "#5af0ff": "#008596",   # primary hover
    "#04212a": "#ffffff",   # text on cyan
    "#0a1624": "#f3f7fa",   # BG
    "#102033": "#ffffff",   # CARD
    "#0d1c2c": "#ffffff",   # PANEL (hero / firewall / footer)
    "#7d93a8": "#4a6178",   # MUTED
    "#eef6ff": "#0d1b2a",   # TEXT
    "#24384c": "#cfdde6",   # borders
    "#1b3044": "#d5e2ea",
    "#3a5166": "#c3d3de",
    "#0b1722": "#f3f7fa",   # inputs / scroll track
    "#152433": "#eef4f8",   # buttons
    "#1a2a38": "#dbe6ed",   # disabled primary
    "#5b6f82": "#5f7080",   # disabled text
    "#00e68a": "#11733a",   # ON green
    "#ff5c7a": "#d92b3a",   # danger
    "#1bb8d4": "#155e75",   # pressed cyan shade
    "rgba(46,230,255,": "rgba(0,112,127,",
    "rgba(46, 230, 255,": "rgba(0, 112, 127,",
    "rgba(0,230,138,": "rgba(18,161,80,",
}
# Reverse map for inline sheets authored while light (canonical dark choice).
_GATE_L2D = {
    "#00707f": "#2ee6ff", "#008596": "#5af0ff", "#f3f7fa": "#0a1624",
    "#ffffff": "#102033", "#4a6178": "#7d93a8", "#0d1b2a": "#eef6ff",
    "#cfdde6": "#24384c", "#d5e2ea": "#1b3044", "#c3d3de": "#3a5166",
    "#eef4f8": "#152433", "#dbe6ed": "#1a2a38", "#5f7080": "#5b6f82",
    "#11733a": "#00e68a", "#d92b3a": "#ff5c7a",
    "#155e75": "#1bb8d4",
    "rgba(0,112,127,": "rgba(46,230,255,", "rgba(0, 112, 127,": "rgba(46, 230, 255,",
    "rgba(18,161,80,": "rgba(0,230,138,",
}


def _mk_sub(mapping):
    keys = sorted(mapping, key=len, reverse=True)
    rx = _re.compile("|".join(_re.escape(k) for k in keys), _re.IGNORECASE)
    low = {k.lower(): v for k, v in mapping.items()}
    return lambda text: rx.sub(lambda m: low[m.group(0).lower()], text)


_to_light = _mk_sub(_GATE_D2L)
_to_dark = _mk_sub(_GATE_L2D)

_LIGHT_EXTRA = """
QWidget#VpnRoot QPushButton#iconBtn { color: #33475b; font-family: "Segoe UI Symbol"; }
QWidget#VpnRoot QLineEdit { placeholder-text-color: #4a6178; }

QWidget#VpnRoot QFrame#hero, QWidget#VpnRoot QFrame#fw, QWidget#VpnRoot QFrame#foot {
    border: 1px solid #d5e2ea;
}
QWidget#VpnRoot QPushButton#lab { color: #ffffff; }
QWidget#VpnRoot QPushButton#lab:hover { color: #ffffff; }
QWidget#VpnRoot QPushButton#lab:pressed {
    background: #005a66; color: #ffffff; border: none;
    padding-top: 12px; padding-bottom: 8px;
}
QWidget#VpnRoot QPushButton#power:pressed { background: rgba(0,112,127,0.20); }
"""

_gate_state = {"light": None, "mode": None}
_gate_instances = _weakref.WeakSet()
_gate_menus = _weakref.WeakSet()
# themed sheet -> dark-authored source, so palette themes can swap in place
_GATE_SRC: dict = {}


def _gate_mode() -> str:
    """'dark' (Default/Dark), 'light', or a ui.styles palette-theme key."""
    if _gate_state["mode"] is None:
        mode = "dark"
        try:
            from ui.styles import current_theme, THEME_SPECS
            eff = current_theme()
            if eff == "light":
                mode = "light"
            elif eff in THEME_SPECS:
                mode = eff
        except Exception:
            pass
        _gate_state["mode"] = mode
        _gate_state["light"] = mode == "light"
    return _gate_state["mode"]


def _gate_is_light() -> bool:
    return _gate_mode() == "light"


def _conv(text: str, mode) -> str:
    if mode is True or mode == "light":
        return _to_light(text)
    if not mode or mode == "dark":
        return text
    try:
        from ui.styles import theme_remap
        return theme_remap(text, mode)
    except Exception:
        return text


def _mode_of(mode):
    if mode is True:
        return "light"
    if mode is False or mode is None:
        return "dark"
    return mode


def _tc(text: str) -> str:
    """Theme a dark-authored colour string for the active gate theme."""
    mode = _gate_mode()
    if mode == "dark":
        return text
    out = _conv(text, mode)
    if out != text:
        if len(_GATE_SRC) > 2048:
            _GATE_SRC.clear()
        _GATE_SRC[out] = text
    return out


_STYLE_CACHE: dict = {}


def gate_style(light) -> str:
    mode = _mode_of(light)
    key = ("gate", mode)
    if key not in _STYLE_CACHE:
        if mode == "light":
            _STYLE_CACHE[key] = _to_light(STYLE) + _LIGHT_EXTRA
        elif mode == "dark":
            _STYLE_CACHE[key] = STYLE
        else:
            # palette themes: monochrome gear so the emoji glyph doesn't clash
            _STYLE_CACHE[key] = _conv(STYLE, mode) + (
                '\nQWidget#VpnRoot QPushButton#iconBtn { font-family: "Segoe UI Symbol"; }\n')
    return _STYLE_CACHE[key]


def gate_menu_style(light) -> str:
    mode = _mode_of(light)
    key = ("menu", mode)
    if key not in _STYLE_CACHE:
        _STYLE_CACHE[key] = _conv(MENU_STYLE, mode)
    return _STYLE_CACHE[key]


def _dedsec_palette(light):
    mode = _mode_of(light)
    pal = _dedsec_dark_palette()
    if mode == "dark":
        return pal
    from PyQt6.QtGui import QPalette
    for role in (
        "Window", "Base", "AlternateBase", "Button", "WindowText", "Text",
        "ButtonText", "Highlight", "HighlightedText", "ToolTipBase", "ToolTipText",
        "PlaceholderText",
    ):
        r = getattr(QPalette.ColorRole, role)
        pal.setColor(r, QColor(_conv(pal.color(r).name(), mode)))
    return pal


def retheme_all(eff=None):
    """Called by ui.styles.apply_theme after a theme change."""
    _gate_state["mode"] = None
    mode = _gate_mode()
    for m in list(_gate_menus):
        try:
            m.setPalette(_dedsec_palette(mode))
            m.setStyleSheet(gate_menu_style(mode))
        except RuntimeError:
            pass
    for g in list(_gate_instances):
        try:
            g.on_theme_changed()
        except RuntimeError:
            pass


def styled_menu(parent=None) -> QMenu:
    """Readable DedSec menu that follows the gate light/dark theme."""
    menu = QMenu(parent)
    menu.setProperty(THEME_EXEMPT_PROP, True)
    mode = _gate_mode()
    menu.setPalette(_dedsec_palette(mode))
    menu.setStyleSheet(gate_menu_style(mode))
    _gate_menus.add(menu)
    menu.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)
    return menu


def _appdata() -> Path:
    base = os.environ.get("APPDATA") or str(Path.home() / ".dedsec-vpn")
    p = Path(base) / "DedSecVPN"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _cfg_path() -> Path:
    return _appdata() / "embedded_config.json"


def local_ipv4s() -> list:
    ips = []
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip not in ips:
            ips.append(ip)
    except Exception:
        pass
    try:
        import psutil as _ps
        for _addrs in _ps.net_if_addrs().values():
            for _a in _addrs:
                if _a.family == socket.AF_INET and _a.address and _a.address not in ips:
                    ips.append(_a.address)
        return ips
    except Exception:
        pass
    if sys.platform == "win32":
        try:
            out = subprocess.check_output(
                ["ipconfig"],
                text=True,
                errors="ignore",
                stdin=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            for line in out.splitlines():
                line = line.strip()
                if line.lower().startswith("ipv4"):
                    part = line.split(":")[-1].strip()
                    if part and part not in ips:
                        ips.append(part)
        except Exception:
            pass
    return ips


_EXIT_TO_SID = {
    # Map your public VPN exit IPs -> region ids used by the UI.
    "YOUR_VPN_EXIT_FRANCE": "eu",
    "YOUR_VPN_EXIT_CANADA": "canada",
    "YOUR_VPN_EXIT_USA": "usa",
    "YOUR_VPN_EXIT_UK": "uk",
}
_lab_cache = {"live": False, "sid": "", "busy": False, "want_exit": False, "exit_ip": ""}
_lab_lock = threading.Lock()


def _exit_ip_to_sid(ip: str) -> str:
    """Map a public exit IP to a server id: built-in table first, then the
    host/ip of every saved location (so custom / re-IP'd servers still match)."""
    ip = str(ip or "").strip()
    if not ip:
        return ""
    sid = _EXIT_TO_SID.get(ip, "")
    if sid:
        return sid
    try:
        for k, srv in (load_cfg().get("servers") or {}).items():
            if ip in (str(srv.get("host") or "").strip(), str(srv.get("ip") or "").strip()):
                return str(k)
    except Exception:
        pass
    return ""


def _win_cmd_text(args) -> str:
    try:
        return subprocess.check_output(
            args,
            text=True,
            errors="ignore",
            stdin=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception:
        return ""


def _probe_lab_state(resolve_exit: bool = False) -> None:
    """Update tunnel cache. Public-IP resolve is optional (slow) - skip during connect."""
    with _lab_lock:
        if _lab_cache["busy"]:
            # Don't drop an exit-IP request just because a quick probe is running.
            if resolve_exit:
                _lab_cache["want_exit"] = True
            return
        _lab_cache["busy"] = True
        if _lab_cache.get("want_exit"):
            resolve_exit = True
            _lab_cache["want_exit"] = False
    live = False
    sid = ""
    exit_ip = ""
    try:
        has_tun = any(str(ip).startswith("10.8.0.") for ip in local_ipv4s())
        if not has_tun:
            blob = _win_cmd_text(["ipconfig"])
            has_tun = "10.8.0." in blob
        if not has_tun:
            # Router hard-lock: the PC has a LAN address only, but the lab
            # gateway answers through the router's tunnel.
            try:
                r = subprocess.run(
                    ["ping", "-n", "1", "-w", "300", "YOUR_LAB_VPN_IP"],
                    capture_output=True,
                    timeout=1.0,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                has_tun = r.returncode == 0
            except Exception:
                has_tun = False
        # Only treat as live if we still have a 10.8.0.x address AND
        # (OpenVPN is running OR the gateway answers). Orphan TAP IPs after
        # disconnect must not lock the UI in "router" mode.
        if has_tun:
            if _openvpn_running():
                live = True
            else:
                try:
                    r = subprocess.run(
                        ["ping", "-n", "1", "-w", "250", "YOUR_LAB_VPN_IP"],
                        capture_output=True,
                        timeout=0.8,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    )
                    live = r.returncode == 0
                except Exception:
                    live = False
        else:
            live = False
        # Mark live ASAP so connect polling can finish; resolve exit IP later.
        with _lab_lock:
            _lab_cache["live"] = live
        if live and resolve_exit:
            import urllib.request
            for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "DedSecLab"})
                    with urllib.request.urlopen(req, timeout=3.0) as resp:
                        ip = resp.read().decode("utf-8", "ignore").strip()
                    exit_ip = ip or exit_ip
                    sid = _exit_ip_to_sid(ip)
                    if sid:
                        break
                except Exception:
                    continue
    finally:
        with _lab_lock:
            _lab_cache["live"] = live
            if sid:
                _lab_cache["sid"] = sid
            if exit_ip:
                _lab_cache["exit_ip"] = exit_ip
            _lab_cache["busy"] = False


def _kick_lab_probe(resolve_exit: bool = False) -> None:
    threading.Thread(target=_probe_lab_state, args=(resolve_exit,), daemon=True).start()


def clear_lab_cache() -> None:
    """Forget cached tunnel state (call on intentional disconnect)."""
    with _lab_lock:
        _lab_cache["live"] = False
        _lab_cache["sid"] = ""
        _lab_cache["busy"] = False
        _lab_cache["want_exit"] = False
        _lab_cache["exit_ip"] = ""


def _openvpn_running() -> bool:
    if sys.platform != "win32":
        return False
    try:
        import psutil as _ps
        for _p in _ps.process_iter(["name"]):
            if (_p.info.get("name") or "").lower() == "openvpn.exe":
                return True
        return False
    except Exception:
        pass
    try:
        out = subprocess.check_output(
            ["tasklist", "/FI", "IMAGENAME eq openvpn.exe", "/NH"],
            text=True,
            errors="ignore",
            stdin=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return "openvpn.exe" in out.lower()
    except Exception:
        return False


def already_on_lab_vpn() -> bool:
    with _lab_lock:
        return bool(_lab_cache["live"])


def vpn_tunnel_up() -> bool:
    """Fresh local check for 10.8.0.x - never trust a stale cache alone."""
    try:
        if any(str(ip).startswith("10.8.0.") for ip in local_ipv4s()):
            return True
    except Exception:
        pass
    return False



def _router_server_id() -> str:
    with _lab_lock:
        return str(_lab_cache.get("sid") or "")



MAP_FILES = {
    "eu": ("maps/fr.png", "maps/france.png", "fr-map.png", "map_fr.png"),
    "canada": ("maps/ca.png", "maps/canada.png", "ca-map.png", "map_ca.png"),
    "usa": ("us.png", "usa.png", "maps/us.png", "maps/usa.png"),
    "uk": ("maps/uk.png", "maps/gb.png", "uk-map.png", "map_uk.png"),
}


def _asset_dirs():
    here = Path(__file__).resolve()
    root = here.parents[1] if len(here.parents) > 1 else here.parent
    # Keep the normal project locations first, then include a few common
    # asset layouts so a newly-added flag is found even when the script is
    # launched from a different working directory.
    dirs = [
        Path.cwd() / "assets",
        here.parent / "assets",
        root / "assets",
        root / "assets" / "vpn",
        here.parent,
        _appdata(),
    ]
    out = []
    for folder in dirs:
        if folder not in out:
            out.append(folder)
    return out


def _map_file(sid: str):
    for folder in _asset_dirs():
        for name in MAP_FILES.get(sid, ()):
            path = folder / name
            if path.is_file():
                return path
    return None


def _map_pixmap(sid: str, w: int, h: int) -> QPixmap:
    found = _map_file(sid)
    if not found:
        return QPixmap()
    raw = QPixmap(str(found))
    if raw.isNull():
        return QPixmap()
    return raw.scaled(w, h, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)


def find_openvpn() -> str:
    for g in (
        shutil.which("openvpn") or "",
        r"C:\\Program Files\\OpenVPN\\bin\\openvpn.exe",
        r"C:\\Program Files (x86)\\OpenVPN\\bin\\openvpn.exe",
    ):
        if g and Path(g).is_file() and Path(g).name.lower() in ("openvpn", "openvpn.exe"):
            return g
    return ""


def bundled_ovpn(name: str) -> str:
    here = Path(__file__).resolve()
    for p in (
        Path.cwd() / "assets" / "vpn" / name,
        here.parents[1] / "assets" / "vpn" / name,
        _appdata() / name,
    ):
        if p.is_file():
            return str(p)
    return ""


DEFAULT_SERVERS = {
    "eu": {
        "id": "eu",
        "name": "France",
        "city": "OVH France",
        "host": "YOUR_VPN_EXIT_FRANCE",
        "ovpn": "",
        "load": 12,
    },
    "canada": {
        "id": "canada",
        "name": "Canada",
        "city": "OVH Canada",
        "host": "YOUR_VPN_EXIT_CANADA",
        "ovpn": "",
        "load": 28,
    },
    "usa": {
        "id": "usa",
        "name": "United States",
        "city": "Chicago",
        "host": "YOUR_VPN_EXIT_USA",
        "ovpn": "",
        "load": 22,
    },
    "uk": {
        "id": "uk",
        "name": "United Kingdom",
        "city": "Linode UK",
        "host": "YOUR_VPN_EXIT_UK",
        "ovpn": "",
        "load": 8,
    },
}


BUILTIN_ORDER = ("eu", "canada", "usa", "uk")
BUILTIN_LABELS = {
    "eu": ("France", "OVH France", "YOUR_VPN_EXIT_FRANCE"),
    "canada": ("Canada", "OVH Canada", "YOUR_VPN_EXIT_CANADA"),
    "usa": ("United States", "Chicago", "YOUR_VPN_EXIT_USA"),
    "uk": ("United Kingdom", "Linode UK", "YOUR_VPN_EXIT_UK"),
}


def _apply_builtin_labels(sid: str, srv: dict) -> None:
    """Built-in slot labels, unless a detected/manual country overrides them."""
    if srv.get("cc_source") in ("auto", "manual") and srv.get("cc"):
        srv["name"] = srv.get("country") or _flags.code_to_name(srv["cc"])
        ip = srv.get("ip") or ""
        city = srv.get("geo_city") or ""
        srv["city"] = f"{city} · {ip}" if city and ip else (city or ip or srv.get("name", ""))
        if ip:
            srv["host"] = ip
        return
    srv.pop("cc", None)
    srv.pop("country", None)
    srv.pop("cc_source", None)
    name, city, host = BUILTIN_LABELS[sid]
    srv["name"], srv["city"], srv["host"] = name, city, host


def ordered_server_ids(servers: dict) -> list[str]:
    ids = [s for s in BUILTIN_ORDER if s in servers]
    ids += [s for s in servers if s not in BUILTIN_ORDER]
    return ids


def server_cc(sid: str, srv: dict | None) -> str | None:
    srv = srv or {}
    if srv.get("cc"):
        return str(srv["cc"]).lower()
    return _flags.SLOT_CODES.get(sid)


CFG_DEFAULTS = {
    "last_server": "eu",
    "auto_connect": False,
    "display_name": "",
    "kill_switch": True,
    "notifications": True,
    "run_at_boot": False,
    "start_minimized": False,
    "auto_reconnect": True,
}


def load_cfg() -> dict:
    data = {
        **CFG_DEFAULTS,
        "servers": json.loads(json.dumps(DEFAULT_SERVERS)),
    }
    if _cfg_path().is_file():
        try:
            saved = json.loads(_cfg_path().read_text(encoding="utf-8"))
            data["last_server"] = saved.get("last_server", "eu")
            data["auto_connect"] = bool(saved.get("auto_connect", False))
            data["display_name"] = saved.get("display_name", "")
            data["kill_switch"] = bool(saved.get("kill_switch", True))
            data["notifications"] = bool(saved.get("notifications", True))
            data["run_at_boot"] = bool(saved.get("run_at_boot", False))
            data["start_minimized"] = bool(saved.get("start_minimized", False))
            data["auto_reconnect"] = bool(saved.get("auto_reconnect", True))
            rec = saved.get("recent_servers") or []
            data["recent_servers"] = [str(s) for s in rec if isinstance(s, str)][:8]
            for sid, srv in (saved.get("servers") or {}).items():
                data["servers"].setdefault(sid, {})
                data["servers"][sid].update(srv)
        except Exception:
            pass
    for sid, fname in (
        ("eu", "eu.ovpn"),
        ("canada", "canada.ovpn"),
        ("usa", "usa.ovpn"),
        ("uk", "uk.ovpn"),
    ):
        data["servers"].setdefault(sid, json.loads(json.dumps(DEFAULT_SERVERS[sid])))
        ovpn = str(data["servers"][sid].get("ovpn") or "").strip()
        if ovpn and not Path(ovpn).is_file():
            ovpn = ""
        data["servers"][sid]["ovpn"] = ovpn or bundled_ovpn(fname)
    for sid, srv in data["servers"].items():
        srv.pop("detecting", None)
        if sid in BUILTIN_LABELS:
            _apply_builtin_labels(sid, srv)
    return data


def push_recent(cfg: dict, sid: str) -> None:
    """Most-recent-first list of picked locations (shown as 'Recents')."""
    rec = [s for s in (cfg.get("recent_servers") or []) if s != sid]
    cfg["recent_servers"] = ([sid] + rec)[:8]


def cfg_mtime() -> float:
    try:
        return _cfg_path().stat().st_mtime
    except OSError:
        return 0.0


def save_cfg(cfg: dict) -> None:
    slim = {
        "last_server": cfg.get("last_server"),
        "auto_connect": cfg.get("auto_connect"),
        "display_name": cfg.get("display_name"),
        "kill_switch": bool(cfg.get("kill_switch", True)),
        "notifications": bool(cfg.get("notifications", True)),
        "run_at_boot": bool(cfg.get("run_at_boot", False)),
        "start_minimized": bool(cfg.get("start_minimized", False)),
        "auto_reconnect": bool(cfg.get("auto_reconnect", True)),
        "recent_servers": [
            s for s in (cfg.get("recent_servers") or [])
            if s in (cfg.get("servers") or {})
        ][:8],
        "servers": cfg.get("servers"),
    }
    _cfg_path().write_text(json.dumps(slim, indent=2), encoding="utf-8")


def _exe_for_boot() -> str:
    """Path written into HKCU Run for launch-at-boot."""
    if getattr(sys, "frozen", False):
        return str(Path(sys.executable).resolve())
    # Dev: launch this package's app.py with the current interpreter.
    app_py = Path(__file__).resolve().parents[1] / "app.py"
    if app_py.is_file():
        return f'"{sys.executable}" "{app_py}"'
    return f'"{sys.executable}"'


def get_run_at_boot() -> bool:
    if sys.platform != "win32":
        return False
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_READ,
        ) as key:
            winreg.QueryValueEx(key, "DedSecLab")
            return True
    except OSError:
        return False


def set_run_at_boot(enabled: bool) -> str:
    """Enable/disable HKCU Run entry. Returns error string or ''."""
    if sys.platform != "win32":
        return "Run at boot is only available on Windows"
    try:
        import winreg
        path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE
        ) as key:
            if enabled:
                winreg.SetValueEx(key, "DedSecLab", 0, winreg.REG_SZ, _exe_for_boot())
            else:
                try:
                    winreg.DeleteValue(key, "DedSecLab")
                except FileNotFoundError:
                    pass
        return ""
    except Exception as e:
        return str(e)


def _logo_paths() -> list[Path]:
    root = Path(__file__).resolve().parents[1]
    return [
        root / "assets" / "dedsec_logo.ico",
        root / "assets" / "dedsec_logo.png",
        root / "assets" / "logo.ico",
        root / "assets" / "logo.png",
        root / "assets" / "applogo.png",
    ] + (
        [
            Path(sys.executable).resolve().parent / "assets" / "dedsec_logo.ico",
            Path(sys.executable).resolve().parent / "assets" / "dedsec_logo.png",
        ]
        if getattr(sys, "frozen", False)
        else []
    )


_APP_ICON: QIcon | None = None


def app_icon_path() -> Path | None:
    for path in _logo_paths():
        if path.is_file():
            return path
    return None


def app_icon() -> QIcon:
    """DedSec logo for window, tray and balloon notifications."""
    global _APP_ICON
    if _APP_ICON is not None and not _APP_ICON.isNull():
        return _APP_ICON
    path = app_icon_path()
    icon = QIcon(str(path)) if path else QIcon()
    if icon.isNull():
        icon = make_icon(False)
    _APP_ICON = icon
    return icon


def make_icon(on: bool) -> QIcon:
    pm = QPixmap(64, 64)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setBrush(QColor(CYAN if on else "#3a4a5e"))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawEllipse(4, 4, 56, 56)
    p.setPen(QColor("#04211c" if on else TEXT))
    p.setFont(QFont("Segoe UI", 22, QFont.Weight.Black))
    p.drawText(pm.rect(), Qt.AlignmentFlag.AlignCenter, "D")
    p.end()
    return QIcon(pm)


class VpnProcess:
    def __init__(self):
        self.proc: subprocess.Popen | None = None

    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def start(self, ovpn: str, kill_switch: bool = True) -> str:
        self.stop(kill_all=False)
        exe = find_openvpn()
        if not exe:
            return "OpenVPN is not installed"
        if not ovpn or not Path(ovpn).is_file():
            return "Add EU / USA configs in Settings"
        log = _appdata() / "openvpn.log"
        cfg_dir = str(Path(ovpn).resolve().parent)
        extra = [
            "--cd", cfg_dir,
            "--register-dns",
            "--sndbuf", "0",
            "--rcvbuf", "0",
            "--mssfix", "1400",
        ]
        if kill_switch:
            extra.insert(2, "--block-outside-dns")
        try:
            if sys.platform == "win32":
                import ctypes
                block = " --block-outside-dns" if kill_switch else ""
                argline = (
                    f'--config "{ovpn}" --log "{log}" --cd "{cfg_dir}"'
                    f' --register-dns{block} --sndbuf 0 --rcvbuf 0 --mssfix 1400'
                )
                rc = ctypes.windll.shell32.ShellExecuteW(
                    None,
                    "runas",
                    exe,
                    argline,
                    None,
                    0,
                )
                if rc <= 32:
                    return f"Admin prompt blocked ({rc}). Click Yes on UAC."
                self.proc = None
            else:
                self.proc = subprocess.Popen(
                    [exe, "--config", ovpn, "--log", str(log), *extra],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
        except Exception as e:
            return str(e)
        return ""

    def stop(self, kill_all: bool = True) -> None:
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=4)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
        self.proc = None
        if kill_all and sys.platform == "win32":
            try:
                import ctypes
                ctypes.windll.shell32.ShellExecuteW(
                    None,
                    "runas",
                    "taskkill.exe",
                    "/F /IM openvpn.exe /T",
                    None,
                    0,
                )
            except Exception:
                try:
                    subprocess.run(
                        ["taskkill", "/F", "/IM", "openvpn.exe", "/T"],
                        capture_output=True,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    )
                except Exception:
                    pass


ON_GREEN = "#00e68a"

FLAG_FILES = {
    # Prefer clean CC0 PNGs under assets/flags/, then root assets copies, then webp fallbacks.
    "eu": (
        "flags/france.png", "france.png", "fr.png",
        "fr.webp", "fr.jpg",
    ),
    "canada": (
        "flags/canada.png", "canada.png", "ca.png",
        "ca.webp", "ca.jpg",
    ),
    "usa": (
        "flags/usa.png", "usa.png", "us.png",
        "us.webp", "usa.webp", "us.jpg",
    ),
    "uk": (
        "flags/uk.png", "uk.png", "gb.png",
        "uk.webp", "gb.webp", "uk_flag.png", "uk-flag.png",
        "gb.jpg", "uk.jpg",
        "united_kingdom.png", "united-kingdom.png", "unitedkingdom.png",
        "united kingdom.png", "britain.png",
    ),
}


def _flag_dirs() -> list[Path]:
    here = Path(__file__).resolve()
    root = here.parents[1] if len(here.parents) > 1 else here.parent
    return [
        Path.cwd() / "assets" / "flags",
        Path.cwd() / "assets",
        root / "assets" / "flags",
        root / "assets",
        here.parent / "assets" / "flags",
        here.parent / "assets",
        root / "assets" / "vpn",
        here.parent,
        _appdata(),
    ]


def _flag_file(sid: str) -> Path | None:
    names = FLAG_FILES.get(sid, ())
    wanted = {name.lower() for name in names}
    for folder in _flag_dirs():
        for name in names:
            path = folder / name
            if path.is_file():
                return path
        # Windows paths are case-insensitive, but Path matching is not on
        # every filesystem. Check the immediate assets folder case-insensitively.
        try:
            for path in folder.iterdir():
                if path.is_file() and path.name.lower() in wanted:
                    return path
        except OSError:
            pass

    # Last fallback for an asset such as "United Kingdom.png" placed in an
    # assets subfolder. Only image files whose names clearly identify the UK
    # flag are considered, so unrelated images cannot be selected.
    if sid == "uk":
        for folder in _flag_dirs():
            if not folder.is_dir():
                continue
            try:
                for path in folder.rglob("*"):
                    if not path.is_file() or path.suffix.lower() not in {".png", ".webp", ".jpg", ".jpeg"}:
                        continue
                    stem = path.stem.lower().replace(" ", "_").replace("-", "_")
                    if stem in {"uk", "uk_flag", "gb", "gb_flag", "united_kingdom", "unitedkingdom", "britain"}:
                        return path
            except OSError:
                continue
    return None


def _circular_pixmap(src: QPixmap, size: int) -> QPixmap:
    out = QPixmap(size, size)
    out.fill(Qt.GlobalColor.transparent)
    scaled = src.scaled(
        size,
        size,
        Qt.AspectRatioMode.KeepAspectRatioByExpanding,
        Qt.TransformationMode.SmoothTransformation,
    )
    x = max(0, (scaled.width() - size) // 2)
    y = max(0, (scaled.height() - size) // 2)
    p = QPainter(out)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    path = QPainterPath()
    path.addEllipse(1, 1, size - 2, size - 2)
    p.setClipPath(path)
    p.drawPixmap(0, 0, scaled, x, y, size, size)
    p.end()
    return out


def _flag_pixmap(sid: str, size: int = 38, cc: str | None = None) -> QPixmap:
    code = (cc or _flags.SLOT_CODES.get(sid) or "").lower() or None
    found = None
    if code:
        found = _flags.flag_path(code)  # prefers assets/flags/<cc>.png
        if found and found.name == "unknown.png" and sid in _flags.SLOT_CODES and not cc:
            found = None
    if found is None and sid in _flags.SLOT_CODES and not cc:
        found = _flag_file(sid)  # legacy france.png / fr.webp ...
    if found is None and code is None:
        found = _flags.unknown_flag_path()
    if found:
        raw = QPixmap(str(found))
        if not raw.isNull():
            return _circular_pixmap(raw, size)
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setPen(Qt.PenStyle.NoPen)
    if sid == "eu":
        p.setBrush(QColor("#0055a4"))
        p.drawEllipse(1, 1, size - 2, size - 2)
        p.setBrush(QColor("#ef4135"))
        p.drawPie(1, 1, size - 2, size - 2, 16 * 300, 16 * 120)
        p.setBrush(QColor("#ffffff"))
        p.drawPie(1, 1, size - 2, size - 2, 16 * 60, 16 * 120)
    else:
        p.setBrush(QColor("#ff0000"))
        p.drawEllipse(1, 1, size - 2, size - 2)
        p.setBrush(QColor("#ffffff"))
        p.drawEllipse(size // 4, size // 4, size // 2, size // 2)
    p.end()
    return pm


class _GeoThread(QThread):
    """Background .ovpn -> remote -> IP -> country lookup (never blocks UI)."""
    done = pyqtSignal(str, dict)

    def __init__(self, sid: str, path: str, parent=None):
        super().__init__(parent)
        self.sid = sid
        self.path = path

    def run(self):
        try:
            res = _flags.detect_ovpn_country(self.path, timeout=4.0)
        except Exception as e:  # never crash the gate
            res = {"ok": False, "error": str(e)}
        self.done.emit(self.sid, res)


class LocationRow(QFrame):
    def __init__(self, sid: str, title: str, subtitle: str, selected: bool, live: bool,
                 cc: str | None = None, detecting: bool = False):
        super().__init__()
        self.sid = sid
        self.setObjectName("loc")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(64)
        if live:
            border = ON_GREEN
            accent = ON_GREEN
        elif selected:
            border = CYAN
            accent = CYAN
        else:
            border = "#1b3044"
            accent = MUTED
        self.setStyleSheet(_tc(
            f"QFrame#loc {{ background:#102033; border:1px solid {border}; border-radius:12px; }}"
        ))
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 8, 14, 8)
        badge = QLabel()
        badge.setFixedSize(38, 38)
        badge.setPixmap(_flag_pixmap(sid, 38, cc))
        badge.setStyleSheet("background:transparent;border:none;")
        col = QVBoxLayout()
        col.setSpacing(0)
        t = QLabel(title)
        t.setStyleSheet("font-weight:800;font-size:14px;background:transparent;border:none;")
        s = QLabel("Detecting country..." if detecting else subtitle)
        s.setStyleSheet(_tc(
            f"color:{CYAN if detecting else MUTED};font-size:11px;background:transparent;border:none;"
        ))
        col.addWidget(t)
        col.addWidget(s)
        lay.addWidget(badge)
        lay.addLayout(col, 1)
        if live:
            on = QLabel("● ON")
            on.setStyleSheet(_tc(
                f"color:{ON_GREEN};font-size:11px;font-weight:800;"
                f"background:rgba(0,230,138,0.14);border:1px solid {ON_GREEN};"
                "border-radius:9px;padding:3px 8px;"
            ))
            lay.addWidget(on)

    def mousePressEvent(self, e):
        # Walk parents so rows work both in the standalone VpnGate window
        # and when VpnGate is embedded inside the lab MainWindow.
        w = self.parent()
        while w is not None:
            if hasattr(w, "select_server"):
                w.select_server(self.sid)
                break
            w = w.parent()
        super().mousePressEvent(e)


class VpnGate(QWidget):
    ACCEPTED = 1
    REJECTED = 0
    connected_ok = pyqtSignal(str)
    lab_relaunch = pyqtSignal(str)
    launch_lab = pyqtSignal(str)
    vpn_down = pyqtSignal()
    skipped_router = pyqtSignal()

    def __init__(self, parent=None, embedded: bool = False):
        super().__init__(parent)
        self.embedded = bool(embedded)
        self.setObjectName("VpnRoot")
        # Consistent dark DedSec look in every app theme (default/dark/light).
        # Exempt from the app-wide inline remap; the gate swaps its own colours.
        self.setProperty(THEME_EXEMPT_PROP, True)
        _gate_state["mode"] = None
        self._gate_mode = _gate_mode()
        self._gate_light = self._gate_mode == "light"
        self.setPalette(_dedsec_palette(self._gate_mode))
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet(gate_style(self._gate_mode))
        _gate_instances.add(self)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self._wallpaper = QPixmap()
        here = Path(__file__).resolve()
        roots = [
            Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else here.parents[1],
            Path.cwd(),
            here.parent,
        ]
        for root in roots:
            for name in (
                "world_map_dark.png",
                "vpn_wallpaper.jpg",
                "site-wallpaper.png",
                "site-wallpaper.jpg",
            ):
                wp = root / "assets" / name
                if wp.is_file():
                    pm = QPixmap(str(wp))
                    if not pm.isNull():
                        self._wallpaper = pm
                        break
            if not self._wallpaper.isNull():
                break
        self.cfg = load_cfg()
        self.vpn = VpnProcess()
        self.current = self.cfg.get("last_server") or "eu"
        self.connected = False
        self._drag = QPoint()
        self._router = False
        self._router_lost_since = 0.0
        self._router_local = False
        self._router_notified = False
        self._probe_n = 0
        self._suppress_router_until = 0.0
        self._client_session = False
        self._phase = "idle"
        self._lab_shown = False
        self._protection_active = False
        self._reconnect_tries = 0

        self.setWindowTitle("DedSec")
        if not self.embedded:
            self.setFixedSize(380, 752)
            self.setWindowFlags(
                Qt.WindowType.Tool | Qt.WindowType.FramelessWindowHint
            )
            self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
            self.setWindowIcon(app_icon())
        else:
            # Fill the lab content pane; no chrome / fixed phone size.
            self.setMinimumSize(360, 520)
            self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        self.stack = QStackedWidget()
        root.addWidget(self.stack)
        self.stack.addWidget(self._build_home())
        self.stack.addWidget(self._build_settings())
        self.stack.addWidget(self._build_install())

        self.tray = None
        if not self.embedded:
            self.tray = QSystemTrayIcon(app_icon(), self)
            menu = styled_menu()
            a_show = QAction("Open DedSec VPN", self)
            a_show.triggered.connect(self._show_from_tray)
            a_lab = QAction("Start DedSec Lab", self)
            a_lab.triggered.connect(self._emit_lab)
            a_quit = QAction("Disconnect and quit", self)
            a_quit.triggered.connect(self.shutdown_app)
            self._a_quit = a_quit
            menu.addAction(a_show)
            menu.addAction(a_lab)
            menu.addAction(a_quit)
            self.tray.setContextMenu(menu)
            self.tray.activated.connect(self._show_from_tray)
            self.tray.setToolTip("DedSec VPN")
            self.tray.show()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        self.timer.start(1500)
        self._probe_timer = QTimer(self)
        self._probe_timer.timeout.connect(self._periodic_probe)
        self._probe_timer.start(6000)
        _kick_lab_probe(resolve_exit=True)
        self.refresh_labels()
        if self.embedded and already_on_lab_vpn():
            self._apply_router_mode()

    def _build_home(self) -> QWidget:
        page = QWidget()
        page.setObjectName("VpnRoot")
        lay = QVBoxLayout(page)
        lay.setContentsMargins(20, 16, 20, 16)
        lay.setSpacing(12)

        bar = QHBoxLayout()
        brand = QLabel("DEDSEC VPN")
        brand.setObjectName("brand")
        bar.addWidget(brand)
        bar.addStretch()
        gear = QPushButton("⚙")
        gear.setObjectName("iconBtn")
        gear.setToolTip("Settings")
        gear.clicked.connect(self._open_settings)
        bar.addWidget(gear)
        if not self.embedded:
            minb = QPushButton("-")
            minb.setObjectName("iconBtn")
            xb = QPushButton("×")
            xb.setObjectName("iconBtn")
            minb.clicked.connect(self._hide_to_tray)
            xb.clicked.connect(self._close_and_disconnect)
            bar.addWidget(minb)
            bar.addWidget(xb)
        lay.addLayout(bar)

        hero = QFrame()
        hero.setObjectName("hero")
        hero.setMinimumHeight(168)
        grid = QGridLayout(hero)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(0)
        self.map_bg = QLabel()
        self.map_bg.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.map_bg.setStyleSheet("background:transparent;border:none;")
        self.map_bg.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        grid.addWidget(self.map_bg, 0, 0)

        inner = QWidget()
        inner.setStyleSheet("background:transparent;")
        hl = QVBoxLayout(inner)
        hl.setContentsMargins(16, 14, 16, 16)
        top = QHBoxLayout()
        top.setSpacing(10)
        top.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        left = QVBoxLayout()
        left.setSpacing(3)
        left.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        k = QLabel("STATUS")
        k.setObjectName("kicker")
        self.status = QLabel("OFF")
        self.status.setObjectName("on")
        self.status.setMinimumHeight(24)
        self.proto = QLabel("OpenVPN")
        self.proto.setObjectName("proto")
        self.proto.setMinimumHeight(18)
        left.addWidget(k)
        left.addWidget(self.status)
        left.addWidget(self.proto)
        self.power = QPushButton("⏻")
        self.power.setObjectName("power")
        self.power.setFixedSize(84, 84)
        self.power.setFlat(True)
        self.power.clicked.connect(self.toggle)
        top.addLayout(left, 1)
        top.addWidget(self.power)
        hl.addLayout(top)
        self.city = QLabel("France")
        self.city.setObjectName("city")
        self.city.setWordWrap(False)
        self.city.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        self.zone = QLabel("OVH France")
        self.zone.setObjectName("zone")
        self.pub_ip = QLabel("")
        self.pub_ip.setObjectName("ip")
        hl.addSpacing(6)
        city_row = QHBoxLayout()
        city_row.setSpacing(10)
        city_row.setContentsMargins(0, 0, 0, 0)
        self.hero_flag = QLabel()
        self.hero_flag.setFixedSize(28, 28)
        self.hero_flag.setStyleSheet("background:transparent;border:none;")
        self.hero_flag.setPixmap(_flag_pixmap(self.current if hasattr(self, "current") else "eu", 28))
        city_row.addWidget(self.hero_flag, 0, Qt.AlignmentFlag.AlignVCenter)
        city_row.addWidget(self.city, 1)
        hl.addLayout(city_row)
        hl.addWidget(self.zone)
        hl.addWidget(self.pub_ip)
        grid.addWidget(inner, 0, 0)
        lay.addWidget(hero)

        fw = QFrame()
        fw.setObjectName("fw")
        fl = QHBoxLayout(fw)
        fl.setContentsMargins(14, 12, 14, 12)
        shield = QLabel("🛡")
        self.fw_title = QLabel("Firewall")
        self.fw_title.setStyleSheet("font-weight:800;background:transparent;border:none;")
        self.fw_sub = QLabel("Disabled")
        self.fw_sub.setObjectName("zone")
        col = QVBoxLayout()
        col.setSpacing(0)
        col.addWidget(self.fw_title)
        col.addWidget(self.fw_sub)
        self.fw_toggle = QPushButton("○")
        self.fw_toggle.setObjectName("iconBtn")
        self.fw_toggle.setFixedWidth(40)
        self.fw_toggle.clicked.connect(self._on_tog_kill)
        fl.addWidget(shield)
        fl.addLayout(col, 1)
        fl.addWidget(self.fw_toggle)
        lay.addWidget(fw)

        loc_h = QLabel("LOCATIONS")
        loc_h.setObjectName("kicker")
        lay.addWidget(loc_h)
        self.loc_scroll = QScrollArea()
        self.loc_scroll.setObjectName("VpnSettingsScroll")
        self.loc_scroll.setWidgetResizable(True)
        self.loc_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.loc_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        loc_host = QWidget()
        loc_host.setObjectName("VpnLocHost")
        self.loc_box = QVBoxLayout(loc_host)
        self.loc_box.setContentsMargins(0, 0, 0, 0)
        self.loc_box.setSpacing(8)
        self.loc_scroll.setWidget(loc_host)
        self.loc_scroll.viewport().setAutoFillBackground(False)
        self.loc_scroll.viewport().setStyleSheet("background: transparent;")
        lay.addWidget(self.loc_scroll)

        self.lab_btn = QPushButton("Start DedSec Lab")
        self.lab_btn.setObjectName("lab")
        self.lab_btn.setEnabled(False)
        self.lab_btn.clicked.connect(self._emit_lab)
        if self.embedded:
            self.lab_btn.hide()
        lay.addWidget(self.lab_btn)

        foot = QFrame()
        foot.setObjectName("foot")
        fol = QHBoxLayout(foot)
        fol.setContentsMargins(12, 10, 12, 10)
        self.secure = QLabel("Connect a location first")
        self.secure.setStyleSheet(_tc(
            f"color:{MUTED};font-size:11px;background:transparent;border:none;"
        ))
        self.auto_lbl = QLabel("Auto-connect  off")
        self.auto_lbl.setStyleSheet(_tc(
            f"color:{MUTED};font-size:11px;background:transparent;border:none;"
        ))
        self.auto_lbl.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.auto_lbl.mousePressEvent = lambda e: self._toggle_auto()  # type: ignore
        fol.addWidget(self.secure, 1)
        fol.addWidget(self.auto_lbl)
        lay.addWidget(foot)
        lay.addStretch()
        return page

    def _open_settings(self):
        self.stack.setCurrentIndex(1)

    def _build_settings(self) -> QWidget:
        page = QWidget()
        page.setObjectName("VpnRoot")
        outer = QVBoxLayout(page)
        outer.setContentsMargins(16, 12, 16, 12)
        outer.setSpacing(8)

        bar = QHBoxLayout()
        back = QPushButton("←")
        back.setObjectName("iconBtn")
        back.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        title = QLabel("SETTINGS")
        title.setObjectName("kicker")
        bar.addWidget(back)
        bar.addWidget(title)
        bar.addStretch()
        outer.addLayout(bar)

        scroll = QScrollArea()
        scroll.setObjectName("VpnSettingsScroll")
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        body = QWidget()
        body.setObjectName("VpnSettingsBody")
        body.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        lay = QVBoxLayout(body)
        lay.setContentsMargins(2, 2, 8, 2)
        lay.setSpacing(10)

        # ---- GENERAL ----
        gen = self._settings_section("GENERAL")
        gl = gen.layout()
        self.name_edit = QLineEdit(self.cfg.get("display_name", ""))
        self.name_edit.setPlaceholderText("Display name")
        self.name_edit.setFixedHeight(34)
        gl.addWidget(self.name_edit)
        self.tog_boot = self._add_toggle_row(
            gl, "Run at Windows startup",
            "Launch DedSec when you sign in (Windows only).",
            bool(self.cfg.get("run_at_boot")),
            self._on_tog_boot,
        )
        self.tog_minimized = self._add_toggle_row(
            gl, "Start minimized to tray",
            "Hide the gate window on launch (standalone gate only).",
            bool(self.cfg.get("start_minimized")),
            self._on_tog_minimized,
        )
        lay.addWidget(gen)

        # ---- CONNECTION ----
        conn = self._settings_section("CONNECTION")
        cl = conn.layout()
        proto = QLabel("Protocol  ·  OpenVPN   ·   Port 1194 UDP")
        proto.setObjectName("VpnProtoBadge")
        cl.addWidget(proto)
        self.tog_autoconnect = self._add_toggle_row(
            cl, "Connect on launch",
            "Auto-connect to the last used server when DedSec starts.",
            bool(self.cfg.get("auto_connect")),
            self._on_tog_autoconnect,
        )
        self.tog_reconnect = self._add_toggle_row(
            cl, "Reconnect if dropped",
            "Retry automatically after an unexpected drop (when kill switch is off).",
            bool(self.cfg.get("auto_reconnect")),
            self._on_tog_reconnect,
        )
        last = self.cfg.get("servers", {}).get(self.cfg.get("last_server", "eu"), {})
        last_lbl = QLabel(f"Last server  ·  {last.get('name', 'France')}")
        last_lbl.setObjectName("VpnSettingsRowHint")
        self._last_server_lbl = last_lbl
        cl.addWidget(last_lbl)
        lay.addWidget(conn)

        # ---- SECURITY ----
        sec = self._settings_section("SECURITY")
        sl = sec.layout()
        self.tog_kill = self._add_toggle_row(
            sl, "Kill switch / block-outside-DNS",
            "Pass --block-outside-dns while connected. On unexpected drop, show Protection active.",
            bool(self.cfg.get("kill_switch", True)),
            self._on_tog_kill,
        )
        lay.addWidget(sec)

        # ---- NOTIFICATIONS ----
        note = self._settings_section("NOTIFICATIONS")
        nl = note.layout()
        self.tog_notify = self._add_toggle_row(
            nl, "Desktop notifications",
            "Tray balloons on connect and disconnect.",
            bool(self.cfg.get("notifications", True)),
            self._on_tog_notify,
        )
        lay.addWidget(note)

        # ---- LOCATIONS / CONFIGS (auto country detection) ----
        cfgs = self._settings_section("LOCATIONS & CONFIGS")
        cfl = cfgs.layout()
        hint = QLabel(
            "Pick an .ovpn and DedSec reads its 'remote' host, resolves the IP "
            "and detects the country flag automatically."
        )
        hint.setObjectName("VpnSettingsRowHint")
        hint.setWordWrap(True)
        cfl.addWidget(hint)
        cfg_host = QWidget()
        cfg_host.setObjectName("VpnCfgHost")
        self._cfg_list_lay = QVBoxLayout(cfg_host)
        self._cfg_list_lay.setContentsMargins(0, 0, 0, 0)
        self._cfg_list_lay.setSpacing(8)
        cfl.addWidget(cfg_host)
        add_btn = QPushButton("+  Add location (.ovpn)")
        add_btn.setObjectName("lab")
        add_btn.setFixedHeight(36)
        add_btn.clicked.connect(self._add_location)
        cfl.addWidget(add_btn)
        self._rebuild_cfg_list()
        lay.addWidget(cfgs)

        # ---- OPENVPN ----
        ov = self._settings_section("OPENVPN")
        ol = ov.layout()
        self.settings_ovpn = QLabel("")
        self.settings_ovpn.setWordWrap(True)
        self.settings_ovpn.setObjectName("zone")
        ol.addWidget(self.settings_ovpn)
        self.install_btn = QPushButton("Install OpenVPN")
        self.install_btn.setObjectName("lab")
        self.install_btn.clicked.connect(self._open_openvpn_download)
        self.install_btn.setFixedHeight(36)
        ol.addWidget(self.install_btn)
        chk = QPushButton("Check again")
        chk.setObjectName("ghost")
        chk.clicked.connect(self._recheck_openvpn)
        chk.setFixedHeight(34)
        ol.addWidget(chk)
        lay.addWidget(ov)

        reset = QPushButton("Reset to defaults")
        reset.setObjectName("ghost")
        reset.clicked.connect(self._reset_settings)
        reset.setFixedHeight(34)
        lay.addWidget(reset)

        save = QPushButton("Save settings")
        save.setObjectName("lab")
        save.clicked.connect(self._save_settings)
        save.setFixedHeight(38)
        lay.addWidget(save)
        lay.addStretch(1)

        scroll.setWidget(body)
        scroll.viewport().setAutoFillBackground(False)
        scroll.viewport().setStyleSheet("background: transparent;")
        outer.addWidget(scroll, 1)
        self._sync_ovpn_btn()
        # Sync boot toggle to registry truth on Windows
        if sys.platform == "win32":
            live = get_run_at_boot()
            self.cfg["run_at_boot"] = live
            self._set_toggle(self.tog_boot, live)
        return page

    def _settings_section(self, title: str) -> QFrame:
        box = QFrame()
        box.setObjectName("VpnSettingsSection")
        lay = QVBoxLayout(box)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(8)
        k = QLabel(title)
        k.setObjectName("VpnSettingsSectionTitle")
        lay.addWidget(k)
        return box

    def _add_toggle_row(self, lay, title: str, hint: str, on: bool, slot):
        row = QHBoxLayout()
        row.setSpacing(8)
        col = QVBoxLayout()
        col.setSpacing(1)
        t = QLabel(title)
        t.setObjectName("VpnSettingsRowTitle")
        h = QLabel(hint)
        h.setObjectName("VpnSettingsRowHint")
        h.setWordWrap(True)
        col.addWidget(t)
        col.addWidget(h)
        btn = QPushButton("ON" if on else "OFF")
        btn.setObjectName("VpnToggle")
        btn.setProperty("on", "true" if on else "false")
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.clicked.connect(slot)
        self._polish_toggle(btn)
        row.addLayout(col, 1)
        row.addWidget(btn, 0, Qt.AlignmentFlag.AlignVCenter)
        lay.addLayout(row)
        return btn

    def _polish_toggle(self, btn: QPushButton):
        btn.style().unpolish(btn)
        btn.style().polish(btn)
        btn.update()

    def _set_toggle(self, btn: QPushButton, on: bool):
        btn.setText("ON" if on else "OFF")
        btn.setProperty("on", "true" if on else "false")
        self._polish_toggle(btn)

    def _on_tog_boot(self):
        want = not bool(self.cfg.get("run_at_boot"))
        err = set_run_at_boot(want)
        if err:
            QMessageBox.warning(self, "DedSec", err)
            want = get_run_at_boot() if sys.platform == "win32" else False
        self.cfg["run_at_boot"] = want
        self._set_toggle(self.tog_boot, want)
        save_cfg(self.cfg)

    def _on_tog_minimized(self):
        self.cfg["start_minimized"] = not bool(self.cfg.get("start_minimized"))
        self._set_toggle(self.tog_minimized, self.cfg["start_minimized"])
        save_cfg(self.cfg)

    def _on_tog_autoconnect(self):
        self.cfg["auto_connect"] = not bool(self.cfg.get("auto_connect"))
        self._set_toggle(self.tog_autoconnect, self.cfg["auto_connect"])
        save_cfg(self.cfg)
        self.refresh_labels()

    def _on_tog_reconnect(self):
        self.cfg["auto_reconnect"] = not bool(self.cfg.get("auto_reconnect"))
        self._set_toggle(self.tog_reconnect, self.cfg["auto_reconnect"])
        save_cfg(self.cfg)

    def _on_tog_kill(self):
        self.cfg["kill_switch"] = not bool(self.cfg.get("kill_switch", True))
        if hasattr(self, "tog_kill"):
            self._set_toggle(self.tog_kill, self.cfg["kill_switch"])
        # Turning kill switch off clears the protection latch.
        if not self.cfg["kill_switch"]:
            self._protection_active = False
        save_cfg(self.cfg)
        self.refresh_labels()

    def _on_tog_notify(self):
        self.cfg["notifications"] = not bool(self.cfg.get("notifications", True))
        self._set_toggle(self.tog_notify, self.cfg["notifications"])
        save_cfg(self.cfg)

    def _reset_settings(self):
        reply = QMessageBox.question(
            self,
            "DedSec",
            "Reset VPN settings to defaults?\nServer .ovpn paths are kept.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        servers = self.cfg.get("servers", {})
        self.cfg.update({k: v for k, v in CFG_DEFAULTS.items()})
        self.cfg["servers"] = servers
        set_run_at_boot(False)
        self.cfg["run_at_boot"] = False
        self.name_edit.setText("")
        for btn, key in (
            (self.tog_boot, "run_at_boot"),
            (self.tog_minimized, "start_minimized"),
            (self.tog_autoconnect, "auto_connect"),
            (self.tog_reconnect, "auto_reconnect"),
            (self.tog_kill, "kill_switch"),
            (self.tog_notify, "notifications"),
        ):
            self._set_toggle(btn, bool(self.cfg.get(key)))
        save_cfg(self.cfg)
        self.refresh_labels()

    def _notify(self, title: str, body: str):
        if not self.cfg.get("notifications", True):
            return
        try:
            tray = self.tray
            if tray is None:
                # Embedded page has no permanent tray - use a short-lived one.
                if not hasattr(self, "_notify_tray") or self._notify_tray is None:
                    self._notify_tray = QSystemTrayIcon(app_icon(), self)
                    self._notify_tray.setVisible(True)
                tray = self._notify_tray
            if tray is not None:
                icon = app_icon()
                tray.setIcon(icon)
                # QIcon overload -> balloon shows the DedSec logo, not the blank "i".
                tray.showMessage(title, body, icon, 4000)
                return
        except Exception:
            pass
        if sys.platform == "win32":
            try:
                from win10toast import ToastNotifier  # type: ignore
                ico = None
                for cand in _logo_paths():
                    if cand.suffix.lower() == ".ico" and cand.is_file():
                        ico = str(cand)
                        break
                ToastNotifier().show_toast(
                    title, body, icon_path=ico, duration=4, threaded=True
                )
            except Exception:
                pass

    def _build_install(self) -> QWidget:
        page = QWidget()
        page.setObjectName("VpnRoot")
        lay = QVBoxLayout(page)
        lay.setContentsMargins(20, 24, 20, 20)
        brand = QLabel("DEDSEC")
        brand.setObjectName("brand")
        lay.addWidget(brand)
        title = QLabel("Install OpenVPN")
        title.setObjectName("city")
        lay.addWidget(title)
        body = QLabel(
            "New PCs need the official OpenVPN client before EU / USA will connect.\n\n"
            "Install it, then press Check again."
        )
        body.setWordWrap(True)
        body.setObjectName("zone")
        lay.addWidget(body)
        go = QPushButton("Download OpenVPN")
        go.setObjectName("lab")
        go.clicked.connect(self._open_openvpn_download)
        again = QPushButton("Check again")
        again.setObjectName("ghost")
        again.clicked.connect(self._recheck_openvpn)
        skip = QPushButton("Back")
        skip.setObjectName("ghost")
        skip.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        lay.addWidget(go)
        lay.addWidget(again)
        lay.addWidget(skip)
        lay.addStretch()
        return page

    OPENVPN_MSI = (
        "https://swupdate.openvpn.org/community/releases/"
        "OpenVPN-2.6.14-I001-amd64.msi"
    )

    def _open_openvpn_download(self):
        self._install_openvpn_silent()

    def _install_openvpn_silent(self):
        import tempfile
        import urllib.request

        if find_openvpn():
            QMessageBox.information(
                self,
                "DedSec",
                "OpenVPN is already installed:\n" + find_openvpn(),
            )
            return

        ask = QMessageBox(self)
        ask.setWindowTitle("DedSec")
        ask.setText(
            "OpenVPN needs Administrator permission.\n\n"
            "Click Yes on the Windows UAC prompt when it appears."
        )
        ask.setStandardButtons(
            QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel
        )
        if ask.exec() != QMessageBox.StandardButton.Ok:
            return

        dest = Path(tempfile.gettempdir()) / "DedSec-OpenVPN.msi"
        dlg = QWidget(self, Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint)
        dlg.setFixedSize(320, 110)
        dlg.setStyleSheet(
            "background:#0a1624;color:#eef6ff;border:2px solid #2ee6ff;border-radius:12px;"
        )
        vl = QVBoxLayout(dlg)
        status = QLabel("Downloading OpenVPN...")
        bar = QProgressBar()
        bar.setRange(0, 100)
        bar.setValue(0)
        bar.setStyleSheet(
            "QProgressBar{border:1px solid #2ee6ff;border-radius:6px;height:16px;text-align:center;}"
            "QProgressBar::chunk{background:#2ee6ff;}"
        )
        vl.addWidget(status)
        vl.addWidget(bar)
        dlg.show()
        QApplication.processEvents()

        def hook(blocks, block_size, total):
            if total > 0:
                bar.setValue(min(100, int(blocks * block_size * 100 / total)))
            QApplication.processEvents()

        try:
            opener = urllib.request.build_opener()
            opener.addheaders = [("User-Agent", "DedSecLab/1.0")]
            urllib.request.install_opener(opener)
            urllib.request.urlretrieve(self.OPENVPN_MSI, dest, hook)
        except Exception as e:
            dlg.close()
            QMessageBox.warning(self, "DedSec", f"Download failed:\n{e}")
            return

        if dest.stat().st_size < 1_000_000:
            dlg.close()
            QMessageBox.warning(self, "DedSec", "Download was too small. Try again.")
            return

        # M4: refuse to elevate-install an unsigned / unexpected MSI.
        try:
            from core.winutil import verify_authenticode
            ok, detail = verify_authenticode(dest, "OpenVPN")
        except Exception as e:
            ok, detail = False, str(e)
        if not ok:
            dlg.close()
            QMessageBox.warning(
                self, "DedSec",
                "OpenVPN installer failed the signature check and was NOT installed.\n\n"
                f"{detail}",
            )
            try:
                dest.unlink(missing_ok=True)
            except Exception:
                pass
            return

        status.setText("Installing... accept the admin prompt")
        bar.setRange(0, 0)
        QApplication.processEvents()

        try:
            import ctypes
            rc = ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                "msiexec.exe",
                f'/i "{dest}" /passive /norestart',
                None,
                1,
            )
            if rc <= 32:
                dlg.close()
                QMessageBox.warning(
                    self,
                    "DedSec",
                    "Windows blocked the admin prompt "
                    f"(code {rc}). Run DedSec as Administrator and try again.",
                )
                return
        except Exception as e:
            dlg.close()
            QMessageBox.warning(self, "DedSec", f"Install failed:\n{e}")
            return

        status.setText("Waiting for OpenVPN to finish installing...")
        for _ in range(180):
            QApplication.processEvents()
            if find_openvpn():
                break
            import time
            time.sleep(1)

        dlg.close()
        if find_openvpn():
            QMessageBox.information(self, "DedSec", "OpenVPN installed. DedSec will restart.")
            self._restart_app()
        else:
            QMessageBox.warning(
                self,
                "DedSec",
                "No admin approval, or install did not finish.\n"
                "Look for the dimmed desktop / UAC Yes-No box.",
            )

    def _restart_app(self):
        try:
            from core.updater import restart_command
            from PyQt6.QtCore import QProcess
            cmd = restart_command()
            if not QProcess.startDetached(cmd[0], cmd[1:]):
                subprocess.Popen(cmd)
        except Exception:
            subprocess.Popen([sys.executable, *sys.argv])
        self.shutdown_app()

    def _sync_ovpn_btn(self):
        found = find_openvpn()
        if hasattr(self, "settings_ovpn"):
            if found:
                self.settings_ovpn.setText("Installed  ·  " + found.replace("\\\\", "\\"))
            else:
                self.settings_ovpn.setText("Not installed")
        if not hasattr(self, "install_btn"):
            return
        if found:
            self.install_btn.hide()
        else:
            self.install_btn.setText("Install OpenVPN")
            self.install_btn.setEnabled(True)
            self.install_btn.setObjectName("lab")
            self.install_btn.show()

    def _recheck_openvpn(self):
        found = find_openvpn()
        self._sync_ovpn_btn()
        if hasattr(self, "settings_ovpn"):
            self.settings_ovpn.setText("OpenVPN: " + (found or "not installed"))
        if found:
            self.stack.setCurrentIndex(0)
            self.refresh_labels()
        else:
            QMessageBox.information(
                self,
                "DedSec",
                "OpenVPN is still not installed.\nDefault path:\nC:\\Program Files\\OpenVPN\\bin\\openvpn.exe",
            )

    def _set_cfg_status(self, box: QLineEdit, label: QLabel):
        raw = box.text().strip()
        if raw and Path(raw).is_file():
            label.setText("Loaded")
        elif raw:
            label.setText("Missing file")
        else:
            label.setText("No config selected")

    # ------------------------------------------------------------ locations
    def _rebuild_cfg_list(self):
        lay = getattr(self, "_cfg_list_lay", None)
        if lay is None:
            return
        while lay.count():
            item = lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._cfg_boxes = {}
        attr = {"eu": "eu", "canada": "canada", "usa": "usa", "uk": "uk"}
        for sid in ordered_server_ids(self.cfg["servers"]):
            srv = self.cfg["servers"][sid]
            row = QFrame()
            row.setObjectName("loc")
            rl = QVBoxLayout(row)
            rl.setContentsMargins(12, 8, 12, 8)
            rl.setSpacing(4)
            hr = QHBoxLayout()
            hr.setSpacing(8)
            fl = QLabel()
            fl.setFixedSize(22, 22)
            fl.setPixmap(_flag_pixmap(sid, 22, server_cc(sid, srv)))
            tl = QLabel(srv.get("name", sid))
            tl.setObjectName("VpnSettingsRowTitle")
            browse = QPushButton("Browse")
            browse.setObjectName("ghost")
            browse.clicked.connect(lambda _=False, s=sid: self._pick_for(s))
            hr.addWidget(fl)
            hr.addWidget(tl, 1)
            hr.addWidget(browse)
            if srv.get("custom"):
                rm = QPushButton("Remove")
                rm.setObjectName("ghost")
                rm.clicked.connect(lambda _=False, s=sid: self._remove_location(s))
                hr.addWidget(rm)
            rl.addLayout(hr)

            path_edit = QLineEdit(str(srv.get("ovpn") or ""))
            path_edit.hide()
            status = QLabel("")
            status.setObjectName("zone")
            status.setWordWrap(True)
            self._set_cfg_status(path_edit, status)
            if srv.get("detecting"):
                status.setText("Detecting country...")
            elif srv.get("detect_error"):
                status.setText(f"{status.text()}  ·  {srv['detect_error']} - pick country below")
            elif srv.get("cc_source") in ("auto", "manual"):
                via = "auto" if srv.get("cc_source") == "auto" else "manual"
                status.setText(f"{status.text()}  ·  {srv.get('city', '')}  ({via})")
            rl.addWidget(status)

            combo = QComboBox()
            combo.addItem("Country: auto-detect", "")
            for cc, nm in sorted(_flags.COUNTRY_NAMES.items(), key=lambda kv: kv[1]):
                combo.addItem(nm, cc)
            if srv.get("cc_source") == "manual" and srv.get("cc"):
                idx = combo.findData(srv["cc"])
                if idx >= 0:
                    combo.setCurrentIndex(idx)
            combo.currentIndexChanged.connect(
                lambda _i, s=sid, c=combo: self._on_country_override(s, c.currentData())
            )
            rl.addWidget(combo)

            self._cfg_boxes[sid] = (path_edit, status)
            if sid in attr:
                setattr(self, f"{attr[sid]}_path", path_edit)
                setattr(self, f"{attr[sid]}_status", status)
            lay.addWidget(row)

    def _schedule_cfg_rebuild(self):
        QTimer.singleShot(0, self._rebuild_cfg_list)

    def _pick(self, box: QLineEdit):
        """Back-compat: map a path box to its server id."""
        for sid, (edit, _status) in getattr(self, "_cfg_boxes", {}).items():
            if edit is box:
                self._pick_for(sid)
                return

    def _ask_ovpn(self, start: str = "") -> str:
        start_dir = str(Path(start).parent) if start and Path(start).parent.is_dir() else str(Path.home())
        path, _ = QFileDialog.getOpenFileName(
            self, "OpenVPN profile", start_dir, "OpenVPN (*.ovpn);;All (*)"
        )
        return path or ""

    def _pick_for(self, sid: str):
        srv = self.cfg["servers"].get(sid)
        if srv is None:
            return
        path = self._ask_ovpn(str(srv.get("ovpn") or ""))
        if not path:
            return
        srv["ovpn"] = path
        save_cfg(self.cfg)
        self._start_detect(sid)

    def _add_location(self):
        path = self._ask_ovpn()
        if not path:
            return
        import time as _time
        sid = f"custom_{int(_time.time() * 1000) % 10_000_000}"
        while sid in self.cfg["servers"]:
            sid += "x"
        rem = _flags.parse_ovpn_remote(path)
        self.cfg["servers"][sid] = {
            "id": sid,
            "name": Path(path).stem,
            "city": rem[0] if rem else "",
            "host": rem[0] if rem else "",
            "ovpn": path,
            "custom": True,
            "load": 0,
        }
        save_cfg(self.cfg)
        self._start_detect(sid)

    def _remove_location(self, sid: str):
        srv = self.cfg["servers"].get(sid)
        if not srv or not srv.get("custom"):
            return
        if sid == self.current and (self.connected or self._phase != "idle"):
            QMessageBox.information(self, "DedSec", "Disconnect from this location first.")
            return
        del self.cfg["servers"][sid]
        if self.current == sid:
            self.current = "eu"
            self.cfg["last_server"] = "eu"
        save_cfg(self.cfg)
        self.refresh_labels()
        self._schedule_cfg_rebuild()

    def _start_detect(self, sid: str):
        srv = self.cfg["servers"].get(sid)
        if not srv or not srv.get("ovpn"):
            return
        srv["detecting"] = True
        srv.pop("detect_error", None)
        self.refresh_labels()
        self._schedule_cfg_rebuild()
        th = _GeoThread(sid, str(srv["ovpn"]), self)
        th.done.connect(self._on_detect_done)
        if not hasattr(self, "_geo_threads"):
            self._geo_threads = []
        self._geo_threads.append(th)
        th.finished.connect(lambda t=th: self._geo_threads.remove(t) if t in self._geo_threads else None)
        th.finished.connect(th.deleteLater)
        th.start()

    def _on_detect_done(self, sid: str, res: dict):
        srv = self.cfg["servers"].get(sid)
        if srv is None:
            return
        srv.pop("detecting", None)
        ip = res.get("ip") or ""
        if res.get("host"):
            srv["remote_host"] = res["host"]
        if res.get("port"):
            srv["port"] = res["port"]
        if res.get("proto"):
            srv["proto"] = res["proto"]
        if ip:
            srv["ip"] = ip
            srv["host"] = ip
        if res.get("ok"):
            srv.pop("detect_error", None)
            if srv.get("cc_source") != "manual":
                srv["cc"] = res["cc"]
                srv["country"] = res.get("country") or _flags.code_to_name(res["cc"])
                srv["geo_city"] = res.get("city") or ""
                srv["cc_source"] = "auto"
        else:
            srv["detect_error"] = res.get("error") or "Detection failed"
            if srv.get("custom") and ip:
                srv["city"] = ip
        if srv.get("cc_source") in ("auto", "manual") and srv.get("cc"):
            self._apply_country_labels(sid, srv)
        save_cfg(self.cfg)
        self.refresh_labels()
        self._schedule_cfg_rebuild()

    def _apply_country_labels(self, sid: str, srv: dict):
        if sid in BUILTIN_LABELS:
            _apply_builtin_labels(sid, srv)
            return
        srv["name"] = srv.get("country") or _flags.code_to_name(srv.get("cc"))
        ip = srv.get("ip") or ""
        city = srv.get("geo_city") or ""
        srv["city"] = f"{city} · {ip}" if city and ip else (city or ip)

    def _on_country_override(self, sid: str, cc):
        srv = self.cfg["servers"].get(sid)
        if srv is None:
            return
        if cc:
            srv["cc"] = str(cc).lower()
            srv["country"] = _flags.code_to_name(srv["cc"])
            srv["cc_source"] = "manual"
            srv.pop("detect_error", None)
            self._apply_country_labels(sid, srv)
            save_cfg(self.cfg)
            self.refresh_labels()
            self._schedule_cfg_rebuild()
            return
        # Back to auto: drop manual pick and re-detect from the .ovpn.
        if srv.get("cc_source") == "manual":
            srv.pop("cc_source", None)
            srv.pop("cc", None)
            srv.pop("country", None)
            if sid in BUILTIN_LABELS:
                _apply_builtin_labels(sid, srv)
            save_cfg(self.cfg)
            self.refresh_labels()
            if srv.get("ovpn") and (srv.get("custom") or srv.get("ip")):
                self._start_detect(sid)
            else:
                self._schedule_cfg_rebuild()

    def _save_settings(self):
        self.cfg["display_name"] = self.name_edit.text().strip()
        self.cfg["servers"]["eu"]["ovpn"] = self.eu_path.text().strip()
        self.cfg.setdefault("servers", {}).setdefault("canada", DEFAULT_SERVERS["canada"])
        self.cfg["servers"]["canada"]["ovpn"] = self.canada_path.text().strip()
        self.cfg["servers"]["usa"]["ovpn"] = self.usa_path.text().strip()
        self.cfg.setdefault("servers", {}).setdefault("uk", DEFAULT_SERVERS["uk"])
        self.cfg["servers"]["uk"]["ovpn"] = self.uk_path.text().strip()
        # Toggles already persist on click; re-assert registry for boot.
        if sys.platform == "win32":
            set_run_at_boot(bool(self.cfg.get("run_at_boot")))
        save_cfg(self.cfg)
        self.stack.setCurrentIndex(0)
        self.refresh_labels()

    def _toggle_auto(self):
        self.cfg["auto_connect"] = not self.cfg.get("auto_connect")
        if hasattr(self, "tog_autoconnect"):
            self._set_toggle(self.tog_autoconnect, bool(self.cfg["auto_connect"]))
        save_cfg(self.cfg)
        self.refresh_labels()

    def _rebuild_rows(self):
        while self.loc_box.count():
            item = self.loc_box.takeAt(0)
            if item.widget():
                item.widget().hide()
                item.widget().deleteLater()
        ids = ordered_server_ids(self.cfg["servers"])
        for sid in ids:
            s = self.cfg["servers"][sid]
            selected = sid == self.current
            live = bool((self.connected or self._router) and selected and not self._router_sid_unknown())
            self.loc_box.addWidget(
                LocationRow(
                    sid, s.get("name", sid), s.get("city", ""), selected, live,
                    cc=server_cc(sid, s), detecting=bool(s.get("detecting")),
                )
            )
        if hasattr(self, "loc_scroll"):
            shown = max(1, min(len(ids), 4))
            self.loc_scroll.setFixedHeight(shown * 64 + (shown - 1) * 8 + 2)

    def on_theme_changed(self):
        """Swap theme colours in place (no widget rebuild)."""
        _gate_state["mode"] = None
        mode = _gate_mode()
        prev = getattr(self, "_gate_mode", "dark")
        if mode == prev:
            return
        self._gate_mode = mode
        self._gate_light = mode == "light"
        self.setUpdatesEnabled(False)
        try:
            self.setPalette(_dedsec_palette(mode))
            self.setStyleSheet(gate_style(mode))
            for wdg in self.findChildren(QWidget):
                sh = wdg.styleSheet()
                if not sh or "#" not in sh and "rgba" not in sh:
                    continue
                src = _GATE_SRC.get(sh)
                if src is None:
                    src = _to_dark(sh) if prev == "light" else sh
                out = _tc(src)
                if out != sh:
                    wdg.setStyleSheet(out)
        finally:
            self.setUpdatesEnabled(True)
            self.update()

    def paintEvent(self, event):
        if getattr(self, "_gate_light", False):
            _chrome = {"bg": "#f3f7fa", "border": "#00707f", "gate_tint": (243, 247, 250, 238)}
        else:
            try:
                from ui.styles import chrome_colors
                mode = getattr(self, "_gate_mode", "dark")
                # dark look for default/dark; palette themes use their own chrome
                _chrome = chrome_colors(mode if mode not in ("dark", "light") else "default")
            except Exception:
                _chrome = {"bg": BG, "border": CYAN, "gate_tint": (6, 12, 20, 155)}
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        r = QRectF(self.rect()).adjusted(1, 1, -1, -1)
        path = QPainterPath()
        path.addRoundedRect(r, 16, 16)
        p.setClipPath(path)
        if not self._wallpaper.isNull():
            wall = self._wallpaper
            if _chrome.get("wall_color"):
                try:
                    from ui.styles import themed_wallpaper
                    wall = themed_wallpaper(wall, getattr(self, "_gate_mode", None))
                except Exception:
                    pass
            scaled = wall.scaled(
                self.size(),
                Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                Qt.TransformationMode.SmoothTransformation,
            )
            x = max(0, (scaled.width() - self.width()) // 2)
            y = max(0, (scaled.height() - self.height()) // 2)
            p.drawPixmap(0, 0, scaled, x, y, self.width(), self.height())
            p.fillRect(self.rect(), QColor(*_chrome["gate_tint"]))
        else:
            p.fillPath(path, QColor(_chrome["bg"]))
        p.setClipping(False)
        p.setPen(QColor(_chrome["border"]))
        p.drawPath(path)
        p.end()

    def mousePressEvent(self, e):
        if self.embedded:
            return super().mousePressEvent(e)
        if e.button() == Qt.MouseButton.LeftButton:
            self._drag = e.globalPosition().toPoint() - self.frameGeometry().topLeft()

    def mouseMoveEvent(self, e):
        if self.embedded:
            return super().mouseMoveEvent(e)
        if e.buttons() & Qt.MouseButton.LeftButton:
            self.move(e.globalPosition().toPoint() - self._drag)

    def closeEvent(self, e):
        if self.embedded:
            e.ignore()
            return
        e.ignore()
        self._hide_to_tray()

    def _hide_to_tray(self):
        self.hide()

    def _hide_taskbar_button(self):
        if sys.platform != "win32":
            return
        try:
            import ctypes
            hwnd = int(self.winId())
            GWL_EXSTYLE = -20
            WS_EX_APPWINDOW = 0x00040000
            WS_EX_TOOLWINDOW = 0x00000080
            user32 = ctypes.windll.user32
            style = user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
            style = (style & ~WS_EX_APPWINDOW) | WS_EX_TOOLWINDOW
            user32.SetWindowLongW(hwnd, GWL_EXSTYLE, style)
        except Exception:
            pass

    def _show_from_tray(self, reason=None):
        if reason == QSystemTrayIcon.ActivationReason.Context:
            return
        self.show()
        self.showNormal()
        self._hide_taskbar_button()
        self.raise_()
        self.activateWindow()

    def refresh_labels(self):
        if self.current not in self.cfg.get("servers", {}):
            self.current = "eu"
        srv = self.cfg["servers"][self.current]
        self.city.setText(srv.get("name", self.current))
        self.zone.setText("Detecting country..." if srv.get("detecting") else srv.get("city", ""))
        self.pub_ip.setText(str(srv.get("host") or srv.get("ip") or ""))
        cc = server_cc(self.current, srv)
        if hasattr(self, "hero_flag"):
            self.hero_flag.setPixmap(_flag_pixmap(self.current, 28, cc))
        if hasattr(self, "map_bg"):
            # Only show the slot map when the slot still points at its own country.
            native = _flags.SLOT_CODES.get(self.current)
            pm = _map_pixmap(self.current, 210, 120) if native and cc == native else QPixmap()
            self.map_bg.setPixmap(pm)
            self.map_bg.setVisible(not pm.isNull())
        on = self.connected or self._router
        # Hard-locked to the router: disconnecting here can't work, so lock it.
        locked = self._router_locked()
        self.power.setEnabled(not locked)
        self.power.setToolTip(
            "Connected via router - disconnect from the router" if locked else ""
        )
        self.fw_toggle.setEnabled(not self._router)
        if getattr(self, "_a_quit", None) is not None:
            self._a_quit.setText("Quit" if locked else "Disconnect and quit")
        self.power.setProperty("connected", "true" if on and self._phase == "idle" else "false")
        self.power.style().unpolish(self.power)
        self.power.style().polish(self.power)
        if self._phase == "connecting":
            self.status.setText("CONNECTING")
            self.proto.setText("OpenVPN")
            self.secure.setText("Accept UAC if it appears. Waiting for 10.8.0.x")
        elif self._phase == "disconnecting":
            self.status.setText("DISCONNECTING")
            self.proto.setText("OpenVPN")
            self.secure.setText("Stopping OpenVPN")
        elif self._router and self._router_local:
            # Leftover local OpenVPN (not the router) - normal ON, can disconnect.
            self.status.setText("ON")
            self.proto.setText("OpenVPN")
            self.secure.setText("Your connection is secure")
        elif self._router:
            self.status.setText("ON")
            self.proto.setText("Router")
            if self._router_sid_unknown():
                self.city.setText("Router VPN")
                self.zone.setText("Detecting server...")
                self.pub_ip.setText("")
                if hasattr(self, "hero_flag"):
                    self.hero_flag.setPixmap(QPixmap())
                if hasattr(self, "map_bg"):
                    self.map_bg.setVisible(False)
                self.secure.setText("VPN connected via router · detecting server")
            else:
                self.secure.setText("VPN connected via router · disconnect from the router")
        elif on:
            self.status.setText("ON")
            self.proto.setText("OpenVPN 1194")
            self.secure.setText("Your connection is secure")
        else:
            self.status.setText("OFF")
            self.proto.setText("OpenVPN")
            self.secure.setText("Connect a location first")
        ks = bool(self.cfg.get("kill_switch", True))
        if getattr(self, "_protection_active", False):
            self.fw_title.setText("Firewall")
            self.fw_sub.setText("Protection active")
            self.fw_toggle.setText("●")
        elif on and ks:
            self.fw_sub.setText("Kill switch on")
            self.fw_toggle.setText("●")
        elif on:
            self.fw_sub.setText("DNS open")
            self.fw_toggle.setText("○")
        elif ks:
            self.fw_sub.setText("Kill switch armed")
            self.fw_toggle.setText("●")
        else:
            self.fw_sub.setText("Disabled")
            self.fw_toggle.setText("○")
        if hasattr(self, "tog_kill"):
            self._set_toggle(self.tog_kill, ks)
        if hasattr(self, "tog_autoconnect"):
            self._set_toggle(self.tog_autoconnect, bool(self.cfg.get("auto_connect")))
        if hasattr(self, "_last_server_lbl"):
            last = self.cfg.get("servers", {}).get(self.current, {})
            self._last_server_lbl.setText(
                f"Last server  ·  {last.get('name', self.current)}"
            )
        self.lab_btn.setEnabled(on and self._phase == "idle")
        self.auto_lbl.setText(
            "Auto-connect  on" if self.cfg.get("auto_connect") else "Auto-connect  off"
        )
        self._rebuild_rows()

    def select_server(self, sid: str):
        if self._router:
            return
        switching = self.connected and sid != self.current
        self.current = sid
        self.cfg["last_server"] = sid
        push_recent(self.cfg, sid)
        save_cfg(self.cfg)
        self.refresh_labels()
        if switching:
            self._phase = "disconnecting"
            self.refresh_labels()
            self.vpn.stop(kill_all=True)
            self.connected = False
            QTimer.singleShot(400, self._start_connect)

    def toggle(self):
        if self._phase in ("connecting", "disconnecting"):
            return
        # Hard-locked to the router: the app can't drop the router's tunnel.
        if self._router_locked():
            self.secure.setText("Connected via router - disconnect from the router")
            return
        if self._router:
            # Tunnel from a leftover local openvpn.exe - that one we can stop.
            self._start_disconnect()
            return
        if not find_openvpn():
            QMessageBox.warning(self, "DedSec", "Install OpenVPN In Settings.")
            return
        if self.connected:
            self._start_disconnect()
            return
        self._start_connect()

    def _start_connect(self) -> None:
        srv = self.cfg["servers"][self.current]
        ovpn = str(srv.get("ovpn") or "").strip()
        if ovpn and not Path(ovpn).is_file():
            ovpn = ""
        if not ovpn:
            box = {
                "eu": getattr(self, "eu_path", None),
                "canada": getattr(self, "canada_path", None),
                "usa": getattr(self, "usa_path", None),
                "uk": getattr(self, "uk_path", None),
            }.get(self.current)
            if box is not None:
                ovpn = box.text().strip()
            if ovpn and not Path(ovpn).is_file():
                ovpn = ""
        if not ovpn:
            if self.current in BUILTIN_ORDER:
                ovpn = bundled_ovpn({"eu": "eu.ovpn", "canada": "canada.ovpn", "usa": "usa.ovpn", "uk": "uk.ovpn"}[self.current])
            else:
                self.secure.setText("No .ovpn for this location - add one in Settings")
                return
        srv["ovpn"] = ovpn
        self._client_session = True
        self._phase = "connecting"
        self.connected = False
        self._protection_active = False
        self.refresh_labels()
        err = self.vpn.start(ovpn, kill_switch=bool(self.cfg.get("kill_switch", True)))
        if err:
            self._phase = "idle"
            self.refresh_labels()
            self.secure.setText(err)
            return
        self._tries = 0
        _kick_lab_probe(resolve_exit=False)
        QTimer.singleShot(250, self._poll_connect)

    def _poll_connect(self) -> None:
        if self._phase != "connecting":
            return
        self._tries += 1
        if self._tries % 2 == 1:
            _kick_lab_probe(resolve_exit=False)
        up = vpn_tunnel_up()
        if up:
            self._phase = "idle"
            self.connected = True
            self._protection_active = False
            self._reconnect_tries = 0
            _kick_lab_probe(resolve_exit=True)  # background: figure out exit country
            self.refresh_labels()
            self.connected_ok.emit(self.current)
            srv = self.cfg["servers"].get(self.current, {})
            self._notify("DedSec VPN", f"Connected to {srv.get('name', self.current)}")
            return
        if self._tries >= 60:  # ~15s at 250ms
            self._phase = "idle"
            self.connected = False
            self.refresh_labels()
            log = _appdata() / "openvpn.log"
            tail = ""
            if log.exists():
                try:
                    tail = "\n".join(log.read_text(errors="ignore").splitlines()[-6:])
                except Exception:
                    tail = ""
            self.secure.setText(tail or "VPN did not get 10.8.0.x")
            return
        self.refresh_labels()
        QTimer.singleShot(250, self._poll_connect)

    def _start_disconnect(self) -> None:
        self._phase = "disconnecting"
        self._router = False
        self.connected = False
        clear_lab_cache()
        # Stop probes from re-latching "router" mode for a short window.
        import time as _time
        self._suppress_router_until = _time.time() + 45.0
        self.refresh_labels()
        self.vpn.stop(kill_all=True)
        self._dtries = 0
        _kick_lab_probe(resolve_exit=False)
        QTimer.singleShot(400, self._poll_disconnect)

    def _poll_disconnect(self) -> None:
        if self._phase != "disconnecting":
            return
        self._dtries += 1
        clear_lab_cache()
        if self._dtries % 2 == 1:
            _kick_lab_probe(resolve_exit=False)
        still = False
        try:
            still = vpn_tunnel_up() or _openvpn_running()
        except Exception:
            still = False
        if still and self._dtries < 15:
            self.refresh_labels()
            QTimer.singleShot(400, self._poll_disconnect)
            return
        clear_lab_cache()
        self._phase = "idle"
        self.connected = False
        self._router = False
        self._client_session = False
        self._lab_shown = False
        # Intentional disconnect clears kill-switch "protection" latch.
        self._protection_active = False
        self.vpn_down.emit()
        self.refresh_labels()
        self._notify("DedSec VPN", "Disconnected")

    def _emit_lab(self):
        if not (self.connected or self._router):
            return
        # First open builds the lab. Later clicks only raise it.
        # Creating a second login window while OpenVPN is still up
        # is the crash after Terminal / VPN Puller + close + reopen.
        if self._lab_shown:
            self.lab_relaunch.emit(self.current)
        else:
            self._lab_shown = True
            self.launch_lab.emit(self.current)
        if not self.embedded:
            self._hide_to_tray()

    def _sync_from_disk(self):
        """Pick up last_server / custom locations saved by another view
        (e.g. the in-app VPN dashboard). Only while idle & disconnected,
        and only on the home screen so settings edits are never clobbered."""
        m = cfg_mtime()
        if not m or m == getattr(self, "_cfg_seen", None):
            return
        if self.connected or self._router or self._phase != "idle":
            return
        if self.stack.currentIndex() != 0:
            return
        self._cfg_seen = m
        try:
            fresh = load_cfg()
        except Exception:
            return
        self.cfg = fresh
        last = fresh.get("last_server") or "eu"
        if last in fresh.get("servers", {}):
            self.current = last
        self.refresh_labels()
        if hasattr(self, "_cfg_list_lay"):
            self._schedule_cfg_rebuild()

    def _tick(self):
        if self._phase != "idle":
            return
        self._sync_from_disk()
        import time as _time
        live = already_on_lab_vpn() or self.vpn.running()
        if self.tray is not None and not getattr(self, "_tray_icon_set", False):
            self.tray.setIcon(app_icon())
            self._tray_icon_set = True
        if (
            live
            and not self._client_session
            and not self._router
            and _time.time() >= float(getattr(self, "_suppress_router_until", 0) or 0)
        ):
            self._apply_router_mode()
            return
        if self._router:
            self._sync_router_server()
            # Cache probes can briefly flicker false while the router is fine
            # (busy probe, slow ping). Prefer a fresh local check too, and only
            # leave router mode after a long quiet stretch - never notify.
            still = live or vpn_tunnel_up()
            if still:
                self._router_lost_since = 0.0
            elif not self._router_lost_since:
                self._router_lost_since = _time.time()
            elif _time.time() - self._router_lost_since > 60.0:
                self._router_lost_since = 0.0
                self._router = False
                self._router_notified = False
                self.connected = False
                self._lab_shown = False
                self.vpn_down.emit()
                self.refresh_labels()
            return
        if self.connected and not live and not self._router:
            self.connected = False
            self._lab_shown = False
            self.vpn_down.emit()
            self._notify("DedSec VPN", "Disconnected")
            if self.cfg.get("kill_switch", True):
                # Latch protection UI; do not auto-restore / reconnect.
                self._protection_active = True
                self.refresh_labels()
            elif self.cfg.get("auto_reconnect") and self._client_session:
                self.refresh_labels()
                self._reconnect_tries = getattr(self, "_reconnect_tries", 0) + 1
                if self._reconnect_tries <= 5:
                    self.secure.setText("Connection dropped - reconnecting...")
                    QTimer.singleShot(1500, self._start_connect)
                else:
                    self.secure.setText("Reconnect failed")
            else:
                self.refresh_labels()

    def exec_gate(self) -> int:
        # Prefer last_server for connect-on-launch.
        last = self.cfg.get("last_server") or "eu"
        if last in self.cfg.get("servers", {}):
            self.current = last
        self.show()
        self._hide_taskbar_button()
        if self.cfg.get("start_minimized") and not self.embedded:
            QTimer.singleShot(50, self._hide_to_tray)
        import time as _time
        if already_on_lab_vpn() and _time.time() >= float(getattr(self, "_suppress_router_until", 0) or 0):
            self._apply_router_mode()
        else:
            QTimer.singleShot(900, self._router_recheck)
            if self.cfg.get("auto_connect") and find_openvpn():
                QTimer.singleShot(300, self.toggle)
        return self.ACCEPTED

    def _apply_router_mode(self):
        self._router = True
        self.connected = True
        self._client_session = False
        self._router_lost_since = 0.0
        self._router_notified = False
        self._router_local = self._local_vpn_running()
        if not self._sync_router_server():
            self.refresh_labels()
        if self._router_sid_unknown():
            # Router tunnel is up but we don't know which server yet: ask the
            # public exit IP (ipify) instead of falling back to France.
            _kick_lab_probe(resolve_exit=True)
        else:
            self._notify_router_once()

    def _local_vpn_running(self) -> bool:
        try:
            return bool(self.vpn.running() or _openvpn_running())
        except Exception:
            return False

    def _router_locked(self) -> bool:
        """Tunnel is the router's (no local OpenVPN) - the app can't disconnect it."""
        return bool(self._router) and not self._router_local

    def _router_sid_unknown(self) -> bool:
        """Router-locked but the exit server hasn't been identified yet."""
        return bool(self._router) and _router_server_id() not in self.cfg.get("servers", {})

    def _sync_router_server(self) -> bool:
        """Point the UI at the server the router is really using. True if changed."""
        sid = _router_server_id()
        if not self._router or sid not in self.cfg.get("servers", {}):
            return False
        if sid == self.current and self.cfg.get("last_server") == sid and getattr(self, "_router_shown", None) == sid:
            return False
        self.current = sid
        self._router_shown = sid
        self.cfg["last_server"] = sid
        try:
            save_cfg(self.cfg)
        except Exception:
            pass
        self.refresh_labels()
        self._notify_router_once()
        return True

    def _notify_router_once(self) -> None:
        """Single toast when the app opens onto a router VPN: connected + server."""
        if not self._router or getattr(self, "_router_notified", False):
            return
        sid = str(self.current or "")
        if sid not in self.cfg.get("servers", {}):
            return
        name = str((self.cfg["servers"][sid] or {}).get("name") or sid)
        self._router_notified = True
        self._notify("DedSec VPN", f"Router connected · {name}")

    def _periodic_probe(self):
        """Tunnel probe; while router-locked also re-check the exit IP so a slow
        first lookup (or a server switch on the router) still corrects the UI."""
        self._probe_n += 1
        if self._router:
            local = self._local_vpn_running()
            if local != self._router_local:
                self._router_local = local
                self.refresh_labels()
        want_exit = bool(self._router) and (
            self._router_sid_unknown() or self._probe_n % 5 == 0
        )
        _kick_lab_probe(resolve_exit=want_exit)

    def _router_recheck(self):
        import time as _time
        if self._router or self.connected or self._phase != "idle":
            return
        if _time.time() < float(getattr(self, "_suppress_router_until", 0) or 0):
            return
        if already_on_lab_vpn():
            self._apply_router_mode()

    def _close_and_disconnect(self):
        """Window × - stop the VPN so closing never leaves a locked 'ON' state."""
        if self._phase == "disconnecting" or self._router_locked():
            self._hide_to_tray()
            return
        if self.connected or _openvpn_running() or vpn_tunnel_up() or already_on_lab_vpn():
            self._start_disconnect()
            QTimer.singleShot(600, self._hide_to_tray)
        else:
            self._hide_to_tray()

    def shutdown_app(self):
        self.vpn.stop()
        if self.tray is not None:
            self.tray.hide()
        app = QApplication.instance()
        if app:
            app.quit()
