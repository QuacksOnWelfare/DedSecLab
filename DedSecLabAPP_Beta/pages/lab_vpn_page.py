"""In-app NordVPN-style VPN dashboard (DedSec colours).

Read-only overview: real connection status + the locations the user has
added. No connecting, switching or selecting here - the mini DedSec VPN
window does all of that.
"""

from __future__ import annotations

from pathlib import Path

import threading

from PyQt6.QtCore import QObject, Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QColor, QPainter, QPainterPath, QPixmap
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from core import flags as _flags
from core.dedsec_vpn_gate import already_on_lab_vpn

try:
    from core.dedsec_vpn_gate import vpn_tunnel_up
except ImportError:
    vpn_tunnel_up = already_on_lab_vpn  # type: ignore

try:
    from core.dedsec_vpn_gate import THEME_EXEMPT_PROP
except ImportError:
    THEME_EXEMPT_PROP = "dslThemeExempt"

try:
    from core.dedsec_vpn_gate import load_cfg, save_cfg, ordered_server_ids, server_cc
except ImportError:
    load_cfg = save_cfg = ordered_server_ids = server_cc = None  # type: ignore

try:
    from core.dedsec_vpn_gate import push_recent
except ImportError:
    def push_recent(cfg, sid):
        rec = [s for s in (cfg.get("recent_servers") or []) if s != sid]
        cfg["recent_servers"] = ([sid] + rec)[:8]


_DARK_PAL = dict(
    CYAN="#2ee6ff", BG="#0a1624", CARD="#102033", PANEL="#0d1c2c", MUTED="#7d93a8",
    TEXT="#eef6ff", DANGER="#ff5c7a", OK="#50ff85", ACC_RGB="46,230,255",
    SEL_BG="#13283a", CONN_BG="#0f2a22", SEL_FG="#04212a", BADGE_BG="rgba(80,255,133,0.18)",
)
_LIGHT_PAL = dict(
    CYAN="#00707f", BG="#f3f7fa", CARD="#ffffff", PANEL="#e9f1f6", MUTED="#4a6178",
    TEXT="#0d1b2a", DANGER="#b42334", OK="#11733a", ACC_RGB="0,112,127",
    SEL_BG="#e2f5fa", CONN_BG="#e7f7ee", SEL_FG="#ffffff", BADGE_BG="rgba(18,161,80,0.12)",
)

CYAN = BG = CARD = PANEL = MUTED = TEXT = DANGER = OK = ""


def _is_light_theme() -> bool:
    try:
        from ui.styles import current_theme
        return current_theme() == "light"
    except Exception:
        return False


def _theme_key() -> str:
    """'dark' (Default/Dark), 'light' or a ui.styles palette-theme key."""
    try:
        from ui.styles import current_theme, THEME_SPECS
        eff = current_theme()
        if eff == "light" or eff in THEME_SPECS:
            return eff
    except Exception:
        pass
    return "dark"


_PAL_CACHE: dict = {}


def _pal_for(key) -> dict:
    if key is True or key == "light":
        return _LIGHT_PAL
    if key is False or key in (None, "dark"):
        return _DARK_PAL
    pal = _PAL_CACHE.get(key)
    if pal is None:
        from ui.styles import theme_remap, theme_color
        pal = {k: theme_remap(v, key) for k, v in _DARK_PAL.items()}
        c = theme_color(_DARK_PAL["CYAN"], key).lstrip("#")
        pal["ACC_RGB"] = f"{int(c[0:2], 16)},{int(c[2:4], 16)},{int(c[4:6], 16)}"
        _PAL_CACHE[key] = pal
    return pal


def _use_palette(light) -> str:
    """Set module colour globals for the active theme and return the page QSS."""
    pal = _pal_for(light)
    g = globals()
    for k in ("CYAN", "BG", "CARD", "PANEL", "MUTED", "TEXT", "DANGER", "OK"):
        g[k] = pal[k]
    return _STYLE_TMPL.format(**pal)


_STYLE_TMPL = """
QWidget#LabVpnPage {{
    background: {BG};
    color: {TEXT};
    font-family: "Segoe UI";
}}
QWidget#LabVpnPage QLabel {{
    background: transparent;
    border: none;
    color: {TEXT};
}}
QFrame#SearchBar {{
    background: {PANEL};
    border: 1px solid rgba({ACC_RGB},0.18);
    border-radius: 18px;
}}
QLineEdit#VpnSearch {{
    background: transparent;
    border: none;
    color: {TEXT};
    font-size: 13px;
    padding: 4px 2px;
    selection-background-color: {CYAN};
    selection-color: {SEL_FG};
}}
QLineEdit#VpnSearch::placeholder {{
    color: {MUTED};
}}
QFrame#MapHero {{
    background: {CARD};
    border: 1px solid rgba({ACC_RGB},0.16);
    border-radius: 18px;
}}
QWidget#LabVpnPage QLabel#HeroCountry {{
    color: {TEXT};
    font-size: 28px;
    font-weight: 800;
}}
QWidget#LabVpnPage QLabel#HeroStatusOk {{
    color: {OK};
    font-size: 13px;
    font-weight: 700;
}}
QWidget#LabVpnPage QLabel#HeroStatusOff {{
    color: {DANGER};
    font-size: 13px;
    font-weight: 700;
}}
QWidget#LabVpnPage QLabel#HeroSub {{
    color: {MUTED};
    font-size: 12px;
}}
QWidget#LabVpnPage QLabel#SectionTitle {{
    color: {TEXT};
    font-size: 15px;
    font-weight: 800;
}}
QWidget#LabVpnPage QLabel#SectionLink {{
    color: {CYAN};
    font-size: 12px;
    font-weight: 600;
}}
QFrame#LocCard {{
    background: {CARD};
    border: 1px solid rgba({ACC_RGB},0.12);
    border-radius: 14px;
}}
QFrame#LocCard[connected="true"] {{
    border: 1px solid {OK};
    background: {CONN_BG};
}}
QFrame#ListRow {{
    background: {CARD};
    border: 1px solid rgba({ACC_RGB},0.10);
    border-radius: 12px;
}}
QFrame#ListRow[connected="true"] {{
    border: 1px solid {OK};
    background: {CONN_BG};
}}
QWidget#LabVpnPage QLabel#LocName {{
    color: {TEXT};
    font-size: 13px;
    font-weight: 700;
}}
QWidget#LabVpnPage QLabel#LocSub {{
    color: {MUTED};
    font-size: 11px;
}}
QWidget#LabVpnPage QLabel#ConnectedBadge {{
    background: {BADGE_BG};
    border: 1px solid {OK};
    color: {OK};
    border-radius: 9px;
    font-size: 10px;
    font-weight: 800;
    padding: 2px 8px;
}}
QFrame#StatsStrip {{
    background: {PANEL};
    border: 1px solid rgba({ACC_RGB},0.14);
    border-radius: 12px;
}}
QWidget#LabVpnPage QLabel#StatKey {{
    color: {MUTED};
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.6px;
}}
QWidget#LabVpnPage QLabel#StatVal {{
    color: {TEXT};
    font-size: 12px;
    font-weight: 700;
}}
QScrollArea#VpnScroll {{
    background: transparent;
    border: none;
}}
QScrollArea#VpnScroll > QWidget {{
    background: transparent;
}}
QScrollBar:vertical {{
    background: transparent;
    width: 8px;
    margin: 4px 0;
}}
QScrollBar::handle:vertical {{
    background: rgba({ACC_RGB},0.28);
    border-radius: 4px;
    min-height: 24px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
QScrollBar:horizontal {{
    background: transparent;
    height: 8px;
}}
QScrollBar::handle:horizontal {{
    background: rgba({ACC_RGB},0.28);
    border-radius: 4px;
    min-width: 24px;
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0;
}}
QFrame#MapHero QLabel#HeroCountry {{ color: #ffffff; }}
QFrame#MapHero QLabel#HeroSub {{ color: #b9cad8; }}
QFrame#MapHero QLabel {{ color: #eef6ff; }}
QFrame#MapHero QLabel#HeroStatusOk {{ color: #50ff85; }}
QFrame#MapHero QLabel#HeroStatusOff {{ color: #ff8a9e; }}
QFrame#MapHero QLabel#ConnectedBadge {{
    color: #50ff85; border: 1px solid #50ff85; background: rgba(80,255,133,0.18);
}}
"""

PAGE_STYLE = _use_palette(False)



def _assets_root() -> Path:
    return Path(__file__).resolve().parents[1] / "assets"


def _flag_pix(cc: str | None, size: int = 36) -> QPixmap:
    path = _flags.flag_path(cc)
    if not path:
        pm = QPixmap(size, size)
        pm.fill(QColor(PANEL))
        return pm
    src = QPixmap(str(path))
    if src.isNull():
        pm = QPixmap(size, size)
        pm.fill(QColor(PANEL))
        return pm
    scaled = src.scaled(
        size, size,
        Qt.AspectRatioMode.KeepAspectRatioByExpanding,
        Qt.TransformationMode.SmoothTransformation,
    )
    out = QPixmap(size, size)
    out.fill(Qt.GlobalColor.transparent)
    p = QPainter(out)
    p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    clip = QPainterPath()
    clip.addEllipse(0, 0, size, size)
    p.setClipPath(clip)
    p.drawPixmap((size - scaled.width()) // 2, (size - scaled.height()) // 2, scaled)
    p.end()
    return out


def _loc_line(srv: dict) -> str:
    """'City · IP' without repeating the IP when the city text already has it."""
    city = str(srv.get("city") or "").strip()
    host = str(srv.get("host") or srv.get("ip") or "").strip()
    if host and host in city:
        return city
    return " · ".join(b for b in (city, host) if b)


_PROTO_CACHE: dict = {}


def _ovpn_proto(path: str) -> str:
    """'OpenVPN · 1194 UDP' read from the server's .ovpn (cached; worker thread)."""
    path = str(path or "")
    if not path:
        return ""
    if path in _PROTO_CACHE:
        return _PROTO_CACHE[path]
    proto, port = "", ""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                bits = line.strip().split()
                if not bits or bits[0].startswith(("#", ";")):
                    continue
                if bits[0] == "proto" and len(bits) > 1 and not proto:
                    proto = bits[1].replace("-client", "").upper()
                elif bits[0] == "port" and len(bits) > 1 and not port:
                    port = bits[1]
                elif bits[0] == "remote" and len(bits) > 2 and not port:
                    port = bits[2]
                    if len(bits) > 3 and not proto:
                        proto = bits[3].upper()
                if bits[0] == "<ca>":
                    break
    except OSError:
        pass
    out = "OpenVPN · " + " ".join(b for b in (port, proto) if b) if (port or proto) else ""
    _PROTO_CACHE[path] = out
    return out


class _StateRelay(QObject):
    done = pyqtSignal(object)


class LabVpnPage(QWidget):
    """Read-only VPN overview. Nothing here connects, switches or selects."""

    def __init__(self, app_window):
        super().__init__()
        self.app_window = app_window
        self.setObjectName("LabVpnPage")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setProperty(THEME_EXEMPT_PROP, True)
        self._light = _theme_key()
        self.setStyleSheet(_use_palette(self._light))

        self.cfg = load_cfg() if load_cfg else {"servers": {}, "last_server": "eu"}
        self._rows: dict[str, dict] = {}
        self._rows_sig = None
        self._state = {"cfg": self.cfg, "tunnel": False, "tunnel_ip": "", "protos": {}}
        self._busy = False
        self._relay = _StateRelay(self)
        self._relay.done.connect(self._on_state)

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 14, 18, 14)
        root.setSpacing(14)
        root.addWidget(self._build_map_hero(), 2)
        root.addLayout(self._build_all_header())
        root.addWidget(self._build_all_list(), 3)
        root.addWidget(self._build_stats_strip(), 0)

        self._sync_rows()
        self._apply_state()
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._kick_refresh)
        self._refresh_timer.start(3000)
        QTimer.singleShot(0, self._kick_refresh)

    # ---------------- real state (no clicks involved) ----------------
    @staticmethod
    def _gate():
        app = QApplication.instance()
        return getattr(app, "_gate", None) if app is not None else None

    def _connected_sid(self) -> str | None:
        """Server that is actually live, or None. Never derived from clicks here."""
        servers = (self._state.get("cfg") or {}).get("servers") or {}
        gate = self._gate()
        if gate is not None:
            try:
                live = bool(getattr(gate, "connected", False) or getattr(gate, "_router", False))
                phase = getattr(gate, "_phase", "idle")
                sid = str(getattr(gate, "current", "") or "")
                if self._router_pending(gate):
                    return None  # router server not identified yet - never guess
                if live and phase == "idle" and sid in servers:
                    return sid
                return None
            except RuntimeError:
                pass
        # No in-process gate (e.g. standalone): tunnel up + the server the gate last used.
        if self._state.get("tunnel"):
            sid = str((self._state.get("cfg") or {}).get("last_server") or "")
            return sid if sid in servers else None
        return None

    @staticmethod
    def _router_pending(gate) -> bool:
        """Router-locked tunnel whose exit server is still being detected."""
        try:
            fn = getattr(gate, "_router_sid_unknown", None)
            return bool(getattr(gate, "_router", False) and fn and fn())
        except RuntimeError:
            return False

    @staticmethod
    def _via_router(gate) -> bool:
        try:
            fn = getattr(gate, "_router_locked", None)
            return bool(fn()) if fn else bool(getattr(gate, "_router", False))
        except RuntimeError:
            return False

    def _kick_refresh(self):
        """Read config + tunnel off the GUI thread; apply results via a signal."""
        if self._busy or not self.isVisible():
            return
        self._busy = True
        relay = self._relay

        def _run():
            st = {"cfg": None, "tunnel": False, "tunnel_ip": "", "protos": {}}
            try:
                st["cfg"] = load_cfg() if load_cfg else None
            except Exception:
                st["cfg"] = None
            try:
                from core.dedsec_vpn_gate import local_ipv4s
                ips = [str(i) for i in local_ipv4s() if str(i).startswith("10.8.0.")]
                st["tunnel"] = bool(ips)
                st["tunnel_ip"] = ips[0] if ips else ""
            except Exception:
                try:
                    st["tunnel"] = bool(vpn_tunnel_up())
                except Exception:
                    pass
            try:
                for sid, srv in ((st["cfg"] or {}).get("servers") or {}).items():
                    st["protos"][sid] = _ovpn_proto(srv.get("ovpn") or "")
            except Exception:
                pass
            try:
                relay.done.emit(st)
            except RuntimeError:
                pass

        threading.Thread(target=_run, daemon=True).start()

    def _on_state(self, st):
        self._busy = False
        if st.get("cfg") is None:
            st["cfg"] = self._state.get("cfg") or self.cfg
        self._state = st
        self.cfg = st["cfg"]
        self._sync_rows()
        self._apply_state()

    def refresh_live(self):
        self._kick_refresh()

    def load_config(self):
        if load_cfg:
            try:
                self.cfg = load_cfg()
                self._state["cfg"] = self.cfg
            except Exception:
                pass
        self._sync_rows()
        self._apply_state()
        self._kick_refresh()

    def showEvent(self, event):
        super().showEvent(event)
        QTimer.singleShot(0, self._kick_refresh)

    # ---------------- layout ----------------
    def _build_map_hero(self) -> QFrame:
        hero = QFrame()
        hero.setObjectName("MapHero")
        hero.setMinimumHeight(190)
        hero.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        self._map_bg = QLabel(hero)
        self._map_bg.setScaledContents(False)
        self._map_bg.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self._map_bg.lower()
        self._load_map()

        wrap = QHBoxLayout(hero)
        wrap.setContentsMargins(22, 18, 22, 18)
        wrap.setSpacing(16)

        left = QVBoxLayout()
        left.setSpacing(6)
        left.addStretch(1)
        flag_row = QHBoxLayout()
        flag_row.setSpacing(10)
        self.hero_flag = QLabel()
        self.hero_flag.setFixedSize(44, 44)
        self.hero_country = QLabel("Not connected")
        self.hero_country.setObjectName("HeroCountry")
        self.hero_badge = QLabel("● CONNECTED")
        self.hero_badge.setObjectName("ConnectedBadge")
        self.hero_badge.hide()
        flag_row.addWidget(self.hero_flag)
        flag_row.addWidget(self.hero_country)
        flag_row.addWidget(self.hero_badge)
        flag_row.addStretch(1)
        left.addLayout(flag_row)

        self.hero_status = QLabel("Not secured")
        self.hero_status.setObjectName("HeroStatusOff")
        left.addWidget(self.hero_status)

        self.hero_sub = QLabel("Use DedSec VPN to connect.")
        self.hero_sub.setObjectName("HeroSub")
        self.hero_sub.setWordWrap(True)
        left.addWidget(self.hero_sub)
        left.addStretch(1)

        wrap.addLayout(left, 1)
        wrap.addStretch(1)
        self._hero = hero
        return hero

    def _build_all_header(self) -> QHBoxLayout:
        row = QHBoxLayout()
        self._title_lbl = QLabel("Your locations")
        self._title_lbl.setObjectName("SectionTitle")
        note = QLabel("Connect or switch in DedSec VPN")
        note.setObjectName("LocSub")
        row.addWidget(self._title_lbl)
        row.addStretch(1)
        row.addWidget(note)
        return row

    def _build_all_list(self) -> QScrollArea:
        scroll = QScrollArea()
        scroll.setObjectName("VpnScroll")
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._list_host = QWidget()
        self._list_host.setStyleSheet("background: transparent;")
        self._list_layout = QVBoxLayout(self._list_host)
        self._list_layout.setContentsMargins(0, 0, 0, 0)
        self._list_layout.setSpacing(8)
        self._list_layout.addStretch(1)
        scroll.setWidget(self._list_host)
        return scroll

    def _build_stats_strip(self) -> QFrame:
        strip = QFrame()
        strip.setObjectName("StatsStrip")
        strip.setFixedHeight(64)
        lay = QHBoxLayout(strip)
        lay.setContentsMargins(16, 8, 16, 8)
        lay.setSpacing(18)
        self._stat_labels = {}
        for key in ("Protocol", "Server IP", "Tunnel IP", "Kill switch"):
            col = QVBoxLayout()
            col.setSpacing(2)
            k = QLabel(key.upper())
            k.setObjectName("StatKey")
            v = QLabel("-")
            v.setObjectName("StatVal")
            col.addWidget(k)
            col.addWidget(v)
            lay.addLayout(col, 1)
            self._stat_labels[key] = v
        return strip

    def on_theme_changed(self):
        key = _theme_key()
        prev = getattr(self, "_light", "dark")
        if key == prev:
            return
        self._light = key
        old = _pal_for(prev)
        new = _pal_for(key)
        self.setStyleSheet(_use_palette(key))
        try:
            self._apply_map()
        except Exception:
            pass
        # Swap colours in the few inline-styled labels instead of rebuilding.
        try:
            for wdg in self.findChildren(QWidget):
                sh = wdg.styleSheet()
                if not sh:
                    continue
                out = sh
                for k in ("MUTED", "OK", "TEXT", "CYAN", "PANEL"):
                    out = out.replace(old[k], new[k])
                if out != sh:
                    wdg.setStyleSheet(out)
        except Exception:
            pass

    # ---------------- rows (built only when the config changes) ----------------
    def _server_items(self) -> list[tuple[str, dict]]:
        servers = (self.cfg or {}).get("servers") or {}
        ids = ordered_server_ids(servers) if ordered_server_ids else list(servers)
        return [(sid, servers[sid]) for sid in ids if sid in servers]

    def _sync_rows(self):
        items = self._server_items()
        sig = tuple(
            (sid, str(srv.get("name") or ""), str(srv.get("city") or ""),
             str(srv.get("host") or srv.get("ip") or ""), str(server_cc(sid, srv) if server_cc else ""))
            for sid, srv in items
        )
        if sig == self._rows_sig:
            return
        self._rows_sig = sig
        while self._list_layout.count():
            item = self._list_layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.hide()
                w.setParent(None)
                w.deleteLater()
        self._rows.clear()
        for sid, srv in items:
            row, badge = self._make_row(sid, srv)
            self._rows[sid] = {"row": row, "badge": badge}
            self._list_layout.addWidget(row)
        self._list_layout.addStretch(1)
        self._title_lbl.setText(f"Your locations ({len(items)})")

    def _make_row(self, sid: str, srv: dict):
        row = QFrame()
        row.setObjectName("ListRow")
        row.setFixedHeight(56)
        row.setProperty("connected", False)
        lay = QHBoxLayout(row)
        lay.setContentsMargins(12, 8, 12, 8)
        lay.setSpacing(12)
        flag = QLabel()
        cc = server_cc(sid, srv) if server_cc else None
        flag.setPixmap(_flag_pix(cc, 32))
        flag.setFixedSize(32, 32)
        text = QVBoxLayout()
        text.setSpacing(1)
        name = QLabel(str(srv.get("name") or _flags.code_to_name(cc) or sid))
        name.setObjectName("LocName")
        sub = QLabel(_loc_line(srv) or "OpenVPN")
        sub.setObjectName("LocSub")
        text.addWidget(name)
        text.addWidget(sub)
        lay.addWidget(flag)
        lay.addLayout(text, 1)
        badge = QLabel("● CONNECTED")
        badge.setObjectName("ConnectedBadge")
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge.hide()
        lay.addWidget(badge)
        return row, badge

    # ---------------- apply live state in place ----------------
    def _apply_state(self):
        conn = self._connected_sid()
        for sid, parts in self._rows.items():
            on = sid == conn
            row = parts["row"]
            if bool(row.property("connected")) != on:
                row.setProperty("connected", on)
                row.style().unpolish(row)
                row.style().polish(row)
            parts["badge"].setVisible(on)
        self._update_hero(conn)
        self._update_stats(conn)

    def _update_hero(self, conn):
        servers = (self.cfg or {}).get("servers") or {}
        if conn and conn in servers:
            srv = servers[conn]
            cc = server_cc(conn, srv) if server_cc else None
            name = str(srv.get("name") or _flags.code_to_name(cc) or conn)
            city = str(srv.get("city") or "")
            host = str(srv.get("host") or srv.get("ip") or "")
            self.hero_flag.setPixmap(_flag_pix(cc, 44))
            self.hero_flag.show()
            self.hero_country.setText(name)
            self.hero_badge.show()
            gate = self._gate()
            via = "router" if gate is not None and self._via_router(gate) else "DedSec VPN"
            status, obj = f"Protected · connected via {via}", "HeroStatusOk"
            self.hero_sub.setText(_loc_line(srv))
        elif self._gate() is not None and self._router_pending(self._gate()):
            self.hero_flag.hide()
            self.hero_country.setText("Router VPN")
            self.hero_badge.show()
            status, obj = "Protected · connected via router", "HeroStatusOk"
            self.hero_sub.setText("Detecting which server the router is using...")
        else:
            self.hero_flag.hide()
            self.hero_country.setText("Not connected")
            self.hero_badge.hide()
            status, obj = "Not secured", "HeroStatusOff"
            self.hero_sub.setText("Use DedSec VPN to connect.")
        self.hero_status.setText(status)
        if self.hero_status.objectName() != obj:
            self.hero_status.setObjectName(obj)
            self.hero_status.style().unpolish(self.hero_status)
            self.hero_status.style().polish(self.hero_status)

    def _update_stats(self, conn):
        servers = (self.cfg or {}).get("servers") or {}
        srv = servers.get(conn) if conn else None
        if srv:
            proto = (self._state.get("protos") or {}).get(conn) or "OpenVPN"
            host = str(srv.get("host") or srv.get("ip") or "-")
            tip = self._state.get("tunnel_ip") or "-"
        else:
            proto, host, tip = "-", "-", "-"
        kill = "On" if (self.cfg or {}).get("kill_switch", True) else "Off"
        self._stat_labels["Protocol"].setText(proto)
        self._stat_labels["Server IP"].setText(host)
        self._stat_labels["Tunnel IP"].setText(tip)
        self._stat_labels["Kill switch"].setText(kill)

    def _load_map(self):
        root = _assets_root()
        for name in ("world_map_dark.png", "vpn_wallpaper.jpg", "vpn_wallpaper_src.jpg"):
            path = root / name
            if path.is_file():
                self._map_pix = QPixmap(str(path))
                if not self._map_pix.isNull():
                    break
        else:
            self._map_pix = QPixmap()
        self._apply_map()

    def _apply_map(self):
        if not hasattr(self, "_hero") or self._map_pix.isNull():
            return
        w = max(self._hero.width(), 1)
        h = max(self._hero.height(), 1)
        src = self._map_pix
        try:
            from ui.styles import themed_wallpaper
            src = themed_wallpaper(src)       # palette themes recolour the map
        except Exception:
            pass
        scaled = src.scaled(
            w, h,
            Qt.AspectRatioMode.KeepAspectRatioByExpanding,
            Qt.TransformationMode.SmoothTransformation,
        )
        self._map_bg.setPixmap(scaled)
        self._map_bg.setGeometry(0, 0, w, h)
        self._map_bg.lower()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._apply_map()
