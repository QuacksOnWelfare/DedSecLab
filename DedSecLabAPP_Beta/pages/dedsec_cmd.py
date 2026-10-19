"""
DedSec CMD - popup command window.

Same security as the Terminal page:
  POST /api/terminal-token  ->  WSS /ws/terminal  (Authorization: Bearer)
"""
from __future__ import annotations

import json
import re
import ssl
from core.tls import LabTLSError, ssl_context_for, qt_ssl_configuration_for, qt_accept_lab_ssl_errors
import urllib.request

from pathlib import Path

from PyQt6.QtCore import Qt, QUrl, QTimer
from PyQt6.QtGui import QFont, QTextCursor, QColor, QPalette, QTextCharFormat, QPainter, QPixmap
from PyQt6.QtNetwork import QAbstractSocket
from PyQt6.QtWebSockets import QWebSocket
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPlainTextEdit, QMessageBox, QSizePolicy, QFrame,
    QStackedWidget,
)

# TLS via core.tls (pinned lab CA).

# Fresh wrapper keys. First screen: [1] Enter Lab.
# Then 5 Browse Tool Categories -> 2 Ip Tools -> puller item.
PATH_ENTER_LAB = ["1"]
PATH_IP_TOOLS = ["5", "2"]
PATH_VPN_PULLER = PATH_ENTER_LAB + PATH_IP_TOOLS + ["7"]
PATH_VPN_PULLER_V2 = PATH_ENTER_LAB + PATH_IP_TOOLS + ["8"]

_FG = {
    30: "#9ca3af",
    31: "#ff5555",
    32: "#50ff85",
    33: "#f0c14b",
    34: "#55c7ff",
    35: "#c084fc",
    36: "#22d3ee",
    37: "#e5e7eb",
    90: "#6b7280",
    91: "#ff8080",
    92: "#86efac",
    93: "#fde68a",
    94: "#93c5fd",
    95: "#e9d5ff",
    96: "#67e8f9",
    97: "#ffffff",
}

_ANSI_RE = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"
    r"|\x1b[()][0-9A-B]"
    r"|\x1b\[[0-9;?]*[A-Za-z]"
    r"|\x1b[78NM=>]"
)


class AnsiStream:
    def __init__(self):
        self.fg = "#50ff85"
        self.bold = False

    def reset_style(self):
        self.fg = "#50ff85"
        self.bold = False

    def feed(self, raw: str) -> tuple[bool, list[tuple[str, str, bool]]]:
        if not raw:
            return False, []
        clear = ("\x1b[2J" in raw) or ("\x1b[3J" in raw) or ("\x1b[H" in raw)
        chunks: list[tuple[str, str, bool]] = []
        i = 0
        buf: list[str] = []

        def flush():
            if buf:
                chunks.append(("".join(buf), self.fg, self.bold))
                buf.clear()

        while i < len(raw):
            ch = raw[i]
            if ch == "\x1b":
                flush()
                m = _ANSI_RE.match(raw, i)
                if m:
                    self._apply_seq(m.group(0))
                    i = m.end()
                    continue
                i += 1
                continue
            if ch == "\x08":
                if buf:
                    buf.pop()
                i += 1
                continue
            if ch == "\r":
                i += 1
                continue
            buf.append(ch)
            i += 1
        flush()
        return clear, chunks

    def _apply_seq(self, seq: str):
        if not seq.startswith("\x1b["):
            return
        body, cmd = seq[2:-1], seq[-1]
        if cmd != "m":
            return
        if body in ("", "0"):
            self.reset_style()
            return
        for part in body.split(";"):
            if not part:
                continue
            try:
                n = int(part)
            except ValueError:
                continue
            if n == 0:
                self.reset_style()
            elif n == 1:
                self.bold = True
            elif n == 22:
                self.bold = False
            elif n == 39:
                self.fg = "#50ff85"
            elif n in _FG:
                self.fg = _FG[n]


def _terminal_palette():
    from PyQt6.QtGui import QPalette
    pal = QPalette()
    for role, col in (
        ("Window", "#0a1624"), ("Base", "#071422"), ("AlternateBase", "#0d1c2c"),
        ("Button", "#152433"), ("WindowText", "#eef6ff"), ("Text", "#50ff85"),
        ("ButtonText", "#eef6ff"), ("Highlight", "#264f78"), ("HighlightedText", "#ffffff"),
        ("PlaceholderText", "#7d93a8"), ("ToolTipBase", "#0d1c2c"), ("ToolTipText", "#eef6ff"),
    ):
        pal.setColor(getattr(QPalette.ColorRole, role), QColor(col))
    return pal


class DedSecCmdWindow(QMainWindow):
    def __init__(self, app_window, parent=None, path=None):
        super().__init__(parent)
        # Terminal keeps its dark look in every app theme: opt this window and
        # all children out of the light inline remap (set before any child
        # sheet is authored) and pin a dark palette below.
        self.setProperty("dslThemeExempt", True)
        self.setProperty("dslDarkMenus", True)  # right-click menus stay dark + readable
        self.app_window = app_window
        self._ws: QWebSocket | None = None
        self._ansi = AnsiStream()
        self._password = False
        self._started = False
        self._path = list(path or [])
        self._replay_i = 0
        self._owns_socket = True
        self._shared = False

        self.setWindowTitle("DedSec")
        self.setMinimumSize(720, 480)
        self.resize(860, 560)
        self.setWindowFlags(Qt.WindowType.Window)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        self.setWindowFlag(Qt.WindowType.Window, True)

        self._wallpaper = QPixmap()
        root = Path(__file__).resolve().parents[1]
        for wp in (
            root / "assets" / "site-wallpaper.png",
            Path.cwd() / "assets" / "site-wallpaper.png",
        ):
            if wp.exists():
                pm = QPixmap(str(wp))
                if not pm.isNull():
                    self._wallpaper = pm
                    break
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, False)
        self.setAutoFillBackground(False)

        root_w = QWidget(self)
        root_w.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, False)
        root_w.setAutoFillBackground(False)
        root_w.setStyleSheet("background: transparent;")
        self.setCentralWidget(root_w)
        lay = QVBoxLayout(root_w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        font = QFont("Consolas")
        if not font.exactMatch():
            font = QFont("Cascadia Mono")
        font.setStyleHint(QFont.StyleHint.Monospace)
        font.setFixedPitch(True)
        font.setPointSize(11)
        font.setStyleStrategy(QFont.StyleStrategy.NoFontMerging)

        self.view = QPlainTextEdit(self)
        self.view.setReadOnly(True)
        self.view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.view.setFont(font)
        self.view.setUndoRedoEnabled(False)
        self.view.document().setDocumentMargin(8)
        self.view.setStyleSheet(
            "QPlainTextEdit {"
            "  background: rgba(7, 20, 34, 0.38);"
            "  color:#50ff85;"
            "  border:none;"
            "  font-family: Consolas, 'Cascadia Mono', 'Courier New', monospace;"
            "}"
        )
        self.view.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        class WallpaperLoad(QFrame):
            def __init__(self, parent=None):
                super().__init__(parent)
                self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, False)
                self.setAutoFillBackground(False)
                root = Path(__file__).resolve().parents[1]
                self._wp = QPixmap()
                for wp in (
                    root / "assets" / "site-wallpaper.png",
                    Path.cwd() / "assets" / "site-wallpaper.png",
                ):
                    if wp.exists():
                        pm = QPixmap(str(wp))
                        if not pm.isNull():
                            self._wp = pm
                            break
                lay = QVBoxLayout(self)
                lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
                t = QLabel("LOADING SESSION")
                t.setAlignment(Qt.AlignmentFlag.AlignCenter)
                t.setStyleSheet("color:#50ff85; font-size:18px; font-weight:700; background:transparent;")
                s = QLabel("Opening the selected tool...")
                s.setAlignment(Qt.AlignmentFlag.AlignCenter)
                s.setStyleSheet("color:#d1d5db; font-size:12px; background:transparent;")
                lay.addWidget(t)
                lay.addWidget(s)

            def paintEvent(self, event):
                p = QPainter(self)
                p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
                r = self.rect()
                if not self._wp.isNull():
                    scaled = self._wp.scaled(
                        r.size(),
                        Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                        Qt.TransformationMode.SmoothTransformation,
                    )
                    x = max(0, (scaled.width() - r.width()) // 2)
                    y = max(0, (scaled.height() - r.height()) // 2)
                    p.drawPixmap(0, 0, scaled, x, y, r.width(), r.height())
                    p.fillRect(r, QColor(6, 12, 20, 150))
                else:
                    p.fillRect(r, QColor("#0a1624"))
                p.end()
                super().paintEvent(event)

        self.loading = WallpaperLoad(self)
        self.stack = QStackedWidget(self)
        self.stack.addWidget(self.view)
        self.stack.addWidget(self.loading)
        lay.addWidget(self.stack, 1)

        prompt_bar = QFrame(self)
        prompt_bar.setFixedHeight(34)
        prompt_bar.setStyleSheet(
            "background: rgba(7, 20, 34, 0.55); border-top:1px solid rgba(46,230,255,0.18);"
        )
        pb = QHBoxLayout(prompt_bar)
        pb.setContentsMargins(10, 0, 10, 4)
        pb.setSpacing(8)
        self.prompt = QLabel(">")
        self.prompt.setFont(font)
        self.prompt.setStyleSheet("color:#50ff85; font-weight:700;")
        self.input = QLineEdit(self)
        self.input.setFont(font)
        self.input.setPlaceholderText("type here and press Enter")
        self.input.returnPressed.connect(self._send_line)
        self.input.setEnabled(False)
        self.input.setStyleSheet(
            "QLineEdit {"
            "  background: transparent;"
            "  color:#f3f4f6;"
            "  border:none;"
            "  padding:0;"
            "  selection-background-color:#264f78;"
            "}"
        )
        pb.addWidget(self.prompt)
        pb.addWidget(self.input, 1)
        self.prompt_bar = prompt_bar
        lay.addWidget(prompt_bar)

        self.setStyleSheet(
            "QMainWindow { background: transparent; }"
            "QStackedWidget { background: transparent; }"
            "QScrollBar:vertical, QScrollBar:horizontal { background: rgba(7,20,34,0.6); border:none; width:8px; height:8px; }"
            "QScrollBar::handle { background:#24384c; border-radius:4px; min-height:24px; min-width:24px; }"
            "QScrollBar::handle:hover { background:#2ee6ff; }"
            "QScrollBar::add-line, QScrollBar::sub-line { width:0; height:0; border:none; }"
            "QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }"
        )
        self.setPalette(_terminal_palette())
        if self._path:
            self.stack.setCurrentWidget(self.loading)
            self.prompt_bar.hide()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        r = self.rect()
        if not self._wallpaper.isNull():
            scaled = self._wallpaper.scaled(
                r.size(),
                Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                Qt.TransformationMode.SmoothTransformation,
            )
            x = max(0, (scaled.width() - r.width()) // 2)
            y = max(0, (scaled.height() - r.height()) // 2)
            p.drawPixmap(0, 0, scaled, x, y, r.width(), r.height())
            p.fillRect(r, QColor(6, 12, 20, 140))
        else:
            p.fillRect(r, QColor("#0a1624"))
        p.end()
        super().paintEvent(event)

    def showEvent(self, event):
        super().showEvent(event)
        if not self._started:
            self._started = True
            QTimer.singleShot(150, self.connect_session)

    def _server_base(self) -> str:
        if self.app_window and hasattr(self.app_window, "config"):
            url = self.app_window.config.get("server_url", "https://YOUR_LAB_VPN_IP:8443")
        elif self.app_window and hasattr(self.app_window, "server"):
            url = getattr(self.app_window.server, "server_url", "") or "https://YOUR_LAB_VPN_IP:8443"
        else:
            url = "https://YOUR_LAB_VPN_IP:8443"
        return str(url).strip().rstrip("/")

    def _ws_url(self) -> str:
        """WSS URL. Auth is Authorization: Bearer - never a query-string token."""
        base = self._server_base()
        if base.startswith("https://"):
            ws = "wss://" + base[len("https://"):]
        elif base.startswith("http://"):
            ws = "wss://" + base[len("http://"):]
        else:
            ws = "wss://" + base
        return f"{ws}/ws/terminal"


    def _fetch_token(self) -> str | None:
        url = self._server_base() + "/api/terminal-token"
        try:
            req = urllib.request.Request(
                url,
                data=b"{}",
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=12, context=ssl_context_for(url)) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
            if data.get("ok") and data.get("token"):
                return data["token"]
            QMessageBox.warning(self, "DedSec", str(data.get("reason") or data)[:400])
            return None
        except Exception as e:
            QMessageBox.warning(self, "DedSec", f"Token request failed:\n{e}")
            return None

    def attach_session(self, socket, snapshot="", raw_ansi=""):
        """Use the Terminal tab's live websocket. Same page, same process."""
        self._owns_socket = False
        self._shared = True
        self._ws = socket
        self.view.clear()
        if raw_ansi:
            self._on_text(raw_ansi)
        elif snapshot:
            self.view.setPlainText(snapshot)
            cur = self.view.textCursor()
            cur.movePosition(QTextCursor.MoveOperation.End)
            self.view.setTextCursor(cur)
        self.stack.setCurrentWidget(self.view)
        self.prompt_bar.show()
        try:
            self._ws.textMessageReceived.connect(self._on_text)
            self._ws.disconnected.connect(self._on_ws_disconnected)
        except Exception:
            pass
        live = (
            self._ws is not None
            and self._ws.state() == QAbstractSocket.SocketState.ConnectedState
        )
        self.input.setEnabled(live)
        if live:
            self.input.setFocus()

    def connect_session(self):
        if self._ws is not None:
            return
        token = self._fetch_token()
        if not token:
            return
        self._owns_socket = True
        self._ws = QWebSocket()
        try:
            self._ws.setSslConfiguration(qt_ssl_configuration_for(self._ws_url()))
        except LabTLSError as e:
            self._append(f"[TLS ERROR] {e}")
            return
        self._ws.errorOccurred.connect(self._on_ws_error)
        self._ws.connected.connect(self._on_ws_connected)
        self._ws.disconnected.connect(self._on_ws_disconnected)
        self._ws.textMessageReceived.connect(self._on_text)
        self._ws.sslErrors.connect(self._on_ssl_errors)
        from PyQt6.QtNetwork import QNetworkRequest
        req = QNetworkRequest(QUrl(self._ws_url()))
        req.setRawHeader(b"Authorization", f"Bearer {token}".encode("ascii"))
        self._ws.open(req)

    def disconnect_session(self):
        if self._ws is not None:
            try:
                self._ws.textMessageReceived.disconnect(self._on_text)
            except Exception:
                pass
            try:
                self._ws.disconnected.disconnect(self._on_ws_disconnected)
            except Exception:
                pass
            if self._owns_socket:
                try:
                    self._ws.close()
                except Exception:
                    pass
            self._ws = None
        self.input.setEnabled(False)

    def _on_ssl_errors(self, errors):
        if qt_accept_lab_ssl_errors(errors):
            try:
                if self._ws:
                    self._ws.ignoreSslErrors()
            except Exception:
                pass
            return
        msgs = "; ".join(e.errorString() for e in (errors or [])) or "certificate error"
        self._append(
            f"[TLS ERROR] {msgs}. Connection refused "
            "(lab CA must match assets/lab_ca.pem)."
        )
        try:
            if self._ws:
                self._ws.abort()
        except Exception:
            pass

    def _show_loading(self, on: bool):
        if on:
            self.stack.setCurrentWidget(self.loading)
            self.prompt_bar.hide()
        else:
            self.stack.setCurrentWidget(self.view)
            self.prompt_bar.show()
            self.input.setEnabled(True)
            self.input.setFocus()

    def _on_ws_connected(self):
        if self._path:
            self._show_loading(True)
            self.input.setEnabled(False)
            QTimer.singleShot(500, self._replay_next)
        else:
            self._show_loading(False)

    def _replay_next(self):
        if self._ws is None or self._ws.state() != QAbstractSocket.SocketState.ConnectedState:
            self._show_loading(False)
            return
        if self._replay_i >= len(self._path):
            QTimer.singleShot(800, self._reveal_if_ready)
            return
        line = self._path[self._replay_i]
        self._replay_i += 1
        self._ws.sendTextMessage(str(line) + "\n")
        QTimer.singleShot(400, self._replay_next)

    def _reveal_if_ready(self):
        self._show_loading(False)

    def _on_ws_disconnected(self):
        self._ws = None
        self.input.setEnabled(False)
        QTimer.singleShot(250, self.close)

    def _on_ws_error(self, err):
        if err == QAbstractSocket.SocketError.RemoteHostClosedError:
            return

    def _on_text(self, data: str):
        clear, chunks = self._ansi.feed(data)
        if clear:
            self.view.clear()
        cur = self.view.textCursor()
        cur.movePosition(QTextCursor.MoveOperation.End)
        for text, color, bold in chunks:
            if not text:
                continue
            fmt = QTextCharFormat()
            fmt.setForeground(QColor(color))
            fmt.setFontWeight(700 if bold else 400)
            cur.insertText(text, fmt)
        self.view.setTextCursor(cur)
        self.view.ensureCursorVisible()

        low = data.lower()
        if "password" in low:
            self._password = True
            self.input.setEchoMode(QLineEdit.EchoMode.Password)
            self.prompt.setText("*")
        elif self._password and ("select" in low or "\n" in data):
            self._password = False
            self.input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.prompt.setText(">")
        if not self._shared and re.search(
            r"\bgoodbye\b|\bexiting\b|session closed", low
        ):
            QTimer.singleShot(400, self.close)

    def _send_line(self):
        if not self._ws or self._ws.state() != QAbstractSocket.SocketState.ConnectedState:
            return
        text = self.input.text()
        self._ws.sendTextMessage(text + "\n")
        owner = getattr(self, "_owner", None)
        if self._shared and owner is not None and hasattr(owner, "session_path"):
            owner.session_path.append(text)
        self.input.clear()
        if self._password:
            self._password = False
            self.input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.prompt.setText(">")

    def closeEvent(self, event):
        self.disconnect_session()
        owner = getattr(self, "_owner", None) or self.parent()
        if owner is not None and getattr(owner, "_dedsec_cmd_win", None) is self:
            owner._dedsec_cmd_win = None
        if owner is not None and hasattr(owner, "hide_cmd_view"):
            try:
                owner.hide_cmd_view()
            except Exception:
                pass
        super().closeEvent(event)


def open_dedsec_cmd(owner, app_window, path=None, attach=True):
    win = getattr(owner, "_dedsec_cmd_win", None)
    if win is not None:
        try:
            win.disconnect_session()
            win.close()
            win.deleteLater()
        except Exception:
            pass
        owner._dedsec_cmd_win = None
    win = DedSecCmdWindow(app_window, parent=None, path=path)
    win._owner = owner
    owner._dedsec_cmd_win = win
    socket = getattr(owner, "socket", None)
    connected = bool(getattr(owner, "connected", False))
    if attach and socket is not None and connected and not path:
        snap = ""
        try:
            snap = owner.output.toPlainText()
        except Exception:
            snap = ""
        raw = getattr(owner, "raw_screen", "") or ""
        win.attach_session(socket, snapshot=snap, raw_ansi=raw)
        win._started = True
    # else: own session; path replay happens behind LOADING SESSION
    win.show()
    win.raise_()
    win.activateWindow()
    return win
