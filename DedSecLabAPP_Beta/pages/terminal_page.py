import re
import json
import ssl
from core.tls import LabTLSError, ssl_context_for, qt_ssl_configuration_for, qt_accept_lab_ssl_errors
import urllib.request
import urllib.error
from pathlib import Path
from PyQt6.QtCore import QUrl, QTimer, Qt
from PyQt6.QtGui import QPainter, QPixmap, QColor
from PyQt6.QtWebSockets import QWebSocket
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTextEdit, QMessageBox, QFrame, QStackedWidget
)
from ui.widgets import (
    StatusRingWidget,
    MiniGraphWidget,
    TrafficBarsWidget,
    CyberDivider
)
from pages.dedsec_cmd import (
    open_dedsec_cmd,
    PATH_VPN_PULLER,
    PATH_VPN_PULLER_V2,
)

# TLS via core.tls (pinned lab CA). No unverified contexts.


def terminal_wants_clear(text):
    return "\x1b[H" in text or "\x1b[2J" in text or "\x1b[3J" in text


def strip_ansi(text):
    text = re.sub(r'\x1B[@-_][0-?]*[ -/]*[@-~]', '', text)
    text = text.replace('[H', '')
    text = text.replace('[2J', '')
    text = text.replace('[3J', '')
    return text


class TerminalPage(QWidget):
    def __init__(self, app_window):
        super().__init__()
        self.app_window = app_window
        self.socket = None
        self.connected = False
        self.auto_started = False
        self.password_mode = False
        self.session_path = []
        self.raw_screen = ""

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 8, 16, 8)
        root.setSpacing(6)

        header = QHBoxLayout()
        title_box = QVBoxLayout()
        title_box.setSpacing(2)
        title = QLabel("DedSec-Lab Terminal")
        title.setObjectName("PageTitle")
        subtitle = QLabel("Secure WebSocket shell routed through your VPN-restricted lab environment.")
        subtitle.setObjectName("StatusLine")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        self.status_label = QLabel("● Terminal: Disconnected")
        self.status_label.setObjectName("TerminalBadgeRed")
        header.addLayout(title_box)
        header.addStretch()
        header.addWidget(self.status_label)
        root.addLayout(header)

        top_row = QHBoxLayout()
        top_row.setSpacing(8)

        session_panel = QFrame()
        session_panel.setObjectName("TerminalHeroPanel")
        session_panel.setMaximumHeight(120)
        session_layout = QHBoxLayout(session_panel)
        session_layout.setContentsMargins(10, 6, 10, 6)
        session_layout.setSpacing(10)

        self.terminal_ring = StatusRingWidget("TTY", "#62ff00")
        self.terminal_ring.setMaximumSize(100, 100)
        self.terminal_ring.setMinimumSize(90, 90)

        session_text = QVBoxLayout()
        session_text.setSpacing(3)
        session_title = QLabel("SESSION STATUS")
        session_title.setObjectName("TerminalPanelTitle")
        self.session_state = QLabel("IDLE")
        self.session_state.setObjectName("TerminalHeroState")
        self.session_detail = QLabel("Waiting for secure shell session.")
        self.session_detail.setObjectName("TerminalHeroDetail")
        self.session_detail.setWordWrap(True)
        session_text.addWidget(session_title)
        session_text.addWidget(self.session_state)
        session_text.addWidget(CyberDivider())
        session_text.addWidget(self.session_detail)

        mini_info = QVBoxLayout()
        mini_info.setSpacing(3)
        self.user_label = QLabel("User: N/A")
        self.user_label.setObjectName("TerminalInfoPill")
        self.role_label = QLabel("Role: N/A")
        self.role_label.setObjectName("TerminalInfoPill")
        self.vpn_label = QLabel("VPN IP: N/A")
        self.vpn_label.setObjectName("TerminalInfoPill")
        self.session_label = QLabel("Session: Secure")
        self.session_label.setObjectName("TerminalInfoPillGreen")
        mini_info.addWidget(self.user_label)
        mini_info.addWidget(self.role_label)
        mini_info.addWidget(self.vpn_label)
        mini_info.addWidget(self.session_label)

        session_layout.addWidget(self.terminal_ring)
        session_layout.addLayout(session_text, 1)
        session_layout.addLayout(mini_info)

        telemetry_panel = QFrame()
        telemetry_panel.setObjectName("TerminalHeroPanel")
        telemetry_panel.setMaximumHeight(120)
        telemetry_layout = QVBoxLayout(telemetry_panel)
        telemetry_layout.setContentsMargins(10, 6, 10, 6)
        telemetry_layout.setSpacing(4)
        telemetry_title = QLabel("TERMINAL TELEMETRY")
        telemetry_title.setObjectName("TerminalPanelTitle")
        self.telemetry_graph = MiniGraphWidget("#55c7ff")
        self.telemetry_graph.setMinimumHeight(40)
        self.telemetry_graph.setMaximumHeight(44)
        self.telemetry_bars = TrafficBarsWidget("#50ff85")
        self.telemetry_bars.setMinimumHeight(24)
        self.telemetry_bars.setMaximumHeight(28)
        telemetry_layout.addWidget(telemetry_title)
        telemetry_layout.addWidget(self.telemetry_graph)
        telemetry_layout.addWidget(self.telemetry_bars)

        top_row.addWidget(session_panel, 1)
        top_row.addWidget(telemetry_panel, 1)
        root.addLayout(top_row)

        main = QHBoxLayout()
        main.setSpacing(8)

        terminal_panel = QFrame()
        terminal_panel.setObjectName("TerminalPanel")
        terminal_layout = QVBoxLayout(terminal_panel)
        terminal_layout.setContentsMargins(10, 6, 10, 6)
        terminal_layout.setSpacing(6)

        toolbar = QHBoxLayout()
        terminal_title = QLabel("LIVE TERMINAL SESSION")
        terminal_title.setObjectName("TerminalPanelTitle")
        self.connect_btn = QPushButton("Launch Terminal")
        self.connect_btn.setObjectName("TerminalConnectButton")
        self.connect_btn.clicked.connect(self.connect_terminal)
        self.disconnect_btn = QPushButton("Disconnect")
        self.disconnect_btn.setObjectName("DangerButton")
        self.disconnect_btn.clicked.connect(self.disconnect_terminal)
        self.disconnect_btn.setEnabled(False)
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.setObjectName("TerminalToolButton")
        self.clear_btn.clicked.connect(self.clear_terminal)
        self.cmd_btn = QPushButton("Open DedSec CMD")
        self.cmd_btn.clicked.connect(self.open_dedsec_cmd)
        self.puller_btn = QPushButton("VPN Puller")
        self.puller_btn.clicked.connect(self.open_vpn_puller)
        self.puller_v2_btn = QPushButton("VPN Puller v2")
        self.puller_v2_btn.clicked.connect(self.open_vpn_puller_v2)
        self._paint_btn(self.cmd_btn, "#22d3ee", "#061018")
        self._paint_btn(self.connect_btn, "#50ff85", "#06110a")
        self._paint_btn(self.disconnect_btn, "#3a151c", "#f07178")
        self._paint_btn(self.clear_btn, "#2a2f38", "#d1d5db")
        self._paint_btn(self.puller_btn, "#55c7ff", "#061018")
        self._paint_btn(self.puller_v2_btn, "#c084fc", "#14061a")
        terminal_layout.addWidget(terminal_title)
        toolbar.addWidget(self.cmd_btn)
        toolbar.addWidget(self.puller_btn)
        toolbar.addWidget(self.puller_v2_btn)
        toolbar.addWidget(self.connect_btn)
        toolbar.addWidget(self.disconnect_btn)
        toolbar.addWidget(self.clear_btn)
        toolbar.addStretch()

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setMinimumHeight(100)
        self.output.setObjectName("TerminalOutput")
        self.input = QLineEdit()
        self.input.setObjectName("TerminalInput")
        self.input.setPlaceholderText("Type menu option or command and press Enter")
        self.input.returnPressed.connect(self.send_command)
        self.input.setEnabled(False)

        class WallpaperFrame(QFrame):
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

        self.cmd_overlay = WallpaperFrame()
        self.cmd_overlay.setObjectName("CmdOverlay")
        self.cmd_overlay.setStyleSheet("QFrame#CmdOverlay { background: transparent; border: none; }")
        ov = QVBoxLayout(self.cmd_overlay)
        ov.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.cmd_overlay_title = QLabel("VIEWING IN DEDSEC CMD")
        self.cmd_overlay_title.setObjectName("PageTitle")
        self.cmd_overlay_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ov_body = QLabel("This session is open in the DedSec CMD window.\nClose that window to return here.")
        ov_body.setObjectName("StatusLine")
        ov_body.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ov_body.setWordWrap(True)
        ov.addWidget(self.cmd_overlay_title)
        ov.addWidget(ov_body)

        self.term_stack = QStackedWidget()
        self.term_stack.addWidget(self.output)
        self.term_stack.addWidget(self.cmd_overlay)

        terminal_layout.addLayout(toolbar)
        terminal_layout.addWidget(self.term_stack, 1)
        terminal_layout.addWidget(self.input)
        main.addWidget(terminal_panel, 3)

        side = QVBoxLayout()
        side.setSpacing(8)

        connection_panel = QFrame()
        connection_panel.setObjectName("TerminalSidePanel")
        connection_layout = QVBoxLayout(connection_panel)
        connection_layout.setContentsMargins(12, 8, 12, 8)
        connection_layout.setSpacing(5)
        connection_title = QLabel("CONNECTION")
        connection_title.setObjectName("TerminalSideTitle")
        self.ws_status = QLabel("WebSocket: Offline")
        self.api_status = QLabel("API Route: VPN only")
        self.auth_status = QLabel("Auth: Logged in required")
        self.shell_status = QLabel("Shell: Waiting")
        for label in [self.ws_status, self.api_status, self.auth_status, self.shell_status]:
            label.setObjectName("TerminalSideLine")
        connection_layout.addWidget(connection_title)
        connection_layout.addWidget(self.ws_status)
        connection_layout.addWidget(self.api_status)
        connection_layout.addWidget(self.auth_status)
        connection_layout.addWidget(self.shell_status)

        tools_panel = QFrame()
        tools_panel.setObjectName("TerminalSidePanel")
        tools_layout = QVBoxLayout(tools_panel)
        tools_layout.setContentsMargins(12, 8, 12, 8)
        tools_layout.setSpacing(5)
        tools_title = QLabel("OPERATOR NOTES")
        tools_title.setObjectName("TerminalSideTitle")
        tools_text = QLabel(
            "✓ Commands are sent over WebSocket\n"
            "✓ Password prompts are hidden\n"
            "✓ ANSI screen clear is supported\n"
            "✓ Session is VPN restricted"
        )
        tools_text.setObjectName("TerminalMonoText")
        tools_layout.addWidget(tools_title)
        tools_layout.addWidget(tools_text)

        activity_panel = QFrame()
        activity_panel.setObjectName("TerminalSidePanel")
        activity_layout = QVBoxLayout(activity_panel)
        activity_layout.setContentsMargins(12, 8, 12, 8)
        activity_layout.setSpacing(5)
        activity_title = QLabel("SESSION ACTIVITY")
        activity_title.setObjectName("TerminalSideTitle")
        self.activity_1 = QLabel("● Terminal page loaded")
        self.activity_2 = QLabel("● Waiting for session")
        self.activity_3 = QLabel("● Awaiting operator commands")
        for label in [self.activity_1, self.activity_2, self.activity_3]:
            label.setObjectName("TerminalActivityLine")
        activity_layout.addWidget(activity_title)
        activity_layout.addWidget(self.activity_1)
        activity_layout.addWidget(self.activity_2)
        activity_layout.addWidget(self.activity_3)
        activity_layout.addStretch()

        side.addWidget(connection_panel)
        side.addWidget(tools_panel)
        side.addWidget(activity_panel, 1)
        main.addLayout(side, 1)
        root.addLayout(main, 1)

        self.auto_connect_timer = QTimer(self)
        self.auto_connect_timer.setSingleShot(True)
        self.auto_connect_timer.timeout.connect(self.auto_connect_once)

    def set_activity(self, text):
        self.activity_3.setText(self.activity_2.text())
        self.activity_2.setText(self.activity_1.text())
        self.activity_1.setText(f"● {text}")

    def load_config(self):
        self.update_user_labels()
        if not self.auto_started:
            self.auto_started = True
            self.auto_connect_timer.start(400)

    def update_user_labels(self):
        user = self.app_window.server.user or {}
        display_name = user.get("display_name", "N/A")
        role = str(user.get("role", "N/A")).upper()
        vpn_ip = user.get("vpn_ip", "N/A")
        self.user_label.setText(f"User: {display_name}")
        self.role_label.setText(f"Role: {role}")
        self.vpn_label.setText(f"VPN IP: {vpn_ip}")

    def _server_http_base(self):
        return self.app_window.config.get(
            "server_url",
            "https://YOUR_LAB_VPN_IP:8443"
        ).strip().rstrip("/")

    def make_ws_url(self):
        """WSS URL for the terminal. Auth is the Authorization: Bearer header
        (see connect_terminal). Tokens are NEVER put in the URL query string.
        """
        server_url = self._server_http_base()
        if server_url.startswith("https://"):
            return "wss://" + server_url[len("https://"):] + "/ws/terminal"
        if server_url.startswith("http://"):
            return "wss://" + server_url[len("http://"):] + "/ws/terminal"
        return "wss://" + server_url + "/ws/terminal"


    def fetch_terminal_token(self):
        """
        Call POST /api/terminal-token over the same VPN path.
        Returns the token string on success, or None on failure.
        """
        url = self._server_http_base() + "/api/terminal-token"
        try:
            req = urllib.request.Request(
                url,
                data=b"{}",
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=8, context=ssl_context_for(url)) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
                data = json.loads(body)
                if data.get("ok") and data.get("token"):
                    return data["token"]
                reason = data.get("reason", "unknown")
                self.output.append(f"[TOKEN ERROR] {reason}")
                return None
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode("utf-8", errors="ignore")
                data = json.loads(body)
                reason = data.get("reason", str(e))
            except Exception:
                reason = str(e)
            self.output.append(f"[TOKEN ERROR] {reason}")
            return None
        except LabTLSError as e:
            self.output.append(f"[TOKEN ERROR] {e}")
            return None
        except Exception as e:
            self.output.append(f"[TOKEN ERROR] {e}")
            return None

    def auto_connect_once(self):
        if self.connected:
            return
        if not self.app_window.server.user:
            self.output.append("[ERROR] You must login first.")
            return
        self.connect_terminal()

    def connect_terminal(self):
        if self.connected:
            return
        if not self.app_window.server.user:
            QMessageBox.warning(self, "Not Logged In", "Login first before opening the terminal.")
            return

        self.disconnect_terminal(silent=True)
        self.output.clear()
        self.update_user_labels()

        self.status_label.setText("● Terminal: Connecting")
        self.status_label.setObjectName("TerminalBadgeOrange")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

        self.ws_status.setText("WebSocket: Connecting")
        self.shell_status.setText("Shell: Starting")
        self.set_activity("Requesting terminal token")
        self.terminal_ring.set_status("LINK", "#ffcc33")
        self.session_state.setText("CONNECTING")
        self.session_detail.setText("Requesting short-lived terminal token.")

        self.connect_btn.setEnabled(False)
        self.disconnect_btn.setEnabled(False)
        self.input.setEnabled(False)

        token = self.fetch_terminal_token()
        if not token:
            self.status_label.setText("● Terminal: Failed")
            self.status_label.setObjectName("TerminalBadgeRed")
            self.status_label.style().unpolish(self.status_label)
            self.status_label.style().polish(self.status_label)
            self.ws_status.setText("WebSocket: Token failed")
            self.shell_status.setText("Shell: Failed")
            self.terminal_ring.set_status("FAIL", "#ff4d5f")
            self.session_state.setText("ERROR")
            self.session_detail.setText("Could not obtain terminal token.")
            self.connect_btn.setEnabled(True)
            self.set_activity("Terminal token failed")
            return

        ws_url = self.make_ws_url()
        self.output.append(f"[CONNECTING] {ws_url}")
        self.set_activity("WebSocket connecting")
        self.session_detail.setText("Establishing secure WebSocket shell.")

        self.socket = QWebSocket()
        try:
            self.socket.setSslConfiguration(qt_ssl_configuration_for(ws_url))
        except LabTLSError as e:
            self.output.append(f"[TLS ERROR] {e}")
            self.status_label.setText("● Terminal: Failed")
            self.status_label.setObjectName("TerminalBadgeRed")
            self.status_label.style().unpolish(self.status_label)
            self.status_label.style().polish(self.status_label)
            self.connect_btn.setEnabled(True)
            return
        self.socket.sslErrors.connect(self._on_ssl_errors)
        self.socket.connected.connect(self.on_connected)
        self.socket.disconnected.connect(self.on_disconnected)
        self.socket.textMessageReceived.connect(self.on_text_received)
        self.socket.errorOccurred.connect(self.on_error)
        # Auth in Authorization header - never in the URL (H4).
        from PyQt6.QtNetwork import QNetworkRequest
        req = QNetworkRequest(QUrl(ws_url))
        req.setRawHeader(b"Authorization", f"Bearer {token}".encode("ascii"))
        self.socket.open(req)

        try:
            self.app_window.add_log("Terminal WebSocket connecting (token auth).")
        except Exception:
            pass

    def on_connected(self):
        self.connected = True
        self.status_label.setText("● Terminal: Connected")
        self.status_label.setObjectName("TerminalBadgeGreen")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)
        self.ws_status.setText("WebSocket: Connected")
        self.shell_status.setText("Shell: Active")
        self.set_activity("Terminal connected")
        self.terminal_ring.set_status("LIVE", "#50ff85")
        self.session_state.setText("ACTIVE")
        self.session_detail.setText("Secure terminal session established.")
        self.output.append("[CONNECTED]\n")
        self.connect_btn.setEnabled(False)
        self.disconnect_btn.setEnabled(True)
        self.input.setEnabled(True)
        self.input.setFocus()
        try:
            self.app_window.add_log("Terminal WebSocket connected.")
        except Exception:
            pass

    def on_disconnected(self):
        was_connected = self.connected
        self.connected = False
        self.status_label.setText("● Terminal: Disconnected")
        self.status_label.setObjectName("TerminalBadgeRed")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)
        self.ws_status.setText("WebSocket: Offline")
        self.shell_status.setText("Shell: Waiting")
        self.set_activity("Terminal disconnected")
        self.terminal_ring.set_status("OFF", "#ff4d5f")
        self.session_state.setText("DISCONNECTED")
        self.session_detail.setText("Terminal session offline.")
        self.connect_btn.setEnabled(True)
        self.disconnect_btn.setEnabled(False)
        self.input.setEnabled(False)
        self.input.setEchoMode(QLineEdit.EchoMode.Normal)
        self.password_mode = False
        if was_connected:
            self.output.append("\n[DISCONNECTED]")
        try:
            self.app_window.add_log("Terminal WebSocket disconnected.")
        except Exception:
            pass

    def _on_ssl_errors(self, errors):
        # Lab certs often use CN=IP without SAN; accept only if pin matches.
        if qt_accept_lab_ssl_errors(errors):
            try:
                self.socket.ignoreSslErrors()
            except Exception:
                pass
            return
        msgs = "; ".join(e.errorString() for e in (errors or [])) or "certificate error"
        self.output.append(
            f"[TLS ERROR] {msgs}. Connection refused "
            "(lab CA must match assets/lab_ca.pem)."
        )
        try:
            self.socket.abort()
        except Exception:
            pass

    def on_error(self, error):
        message = "WebSocket error"
        try:
            message = self.socket.errorString()
        except Exception:
            pass
        self.status_label.setText("● Terminal: Failed")
        self.status_label.setObjectName("TerminalBadgeRed")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)
        self.ws_status.setText("WebSocket: Error")
        self.shell_status.setText("Shell: Failed")
        self.set_activity("WebSocket error")
        self.terminal_ring.set_status("FAIL", "#ff4d5f")
        self.session_state.setText("ERROR")
        self.session_detail.setText(message)
        self.output.append(f"\n[ERROR] {message}")
        self.connect_btn.setEnabled(True)
        self.disconnect_btn.setEnabled(False)
        self.input.setEnabled(False)
        try:
            self.app_window.add_log(f"Terminal WebSocket error: {message}")
        except Exception:
            pass

    def on_text_received(self, raw):
        if terminal_wants_clear(raw):
            self.output.clear()
            self.raw_screen = raw
        else:
            self.raw_screen += raw
        data = strip_ansi(raw)
        self.update_input_mode(data)
        self.telemetry_graph.set_value(82)
        self.output.moveCursor(self.output.textCursor().MoveOperation.End)
        self.output.insertPlainText(data)
        self.output.verticalScrollBar().setValue(
            self.output.verticalScrollBar().maximum()
        )

    def update_input_mode(self, text):
        if "password" in text.lower():
            self.password_mode = True
            self.input.setEchoMode(QLineEdit.EchoMode.Password)
            self.input.setPlaceholderText("Password input hidden")
            self.set_activity("Password input hidden")
        elif self.password_mode:
            self.password_mode = False
            self.input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.input.setPlaceholderText("Type menu option or command and press Enter")

    def send_command(self):
        command = self.input.text()
        if not self.connected or not self.socket:
            QMessageBox.warning(self, "Not Connected", "Terminal is not connected.")
            return
        try:
            self.socket.sendTextMessage(command + "\n")
            self.session_path.append(command)
            self.input.clear()
            self.set_activity(f"Command sent: {command[:32]}")
            if self.password_mode:
                self.input.setEchoMode(QLineEdit.EchoMode.Normal)
                self.input.setPlaceholderText("Type menu option or command and press Enter")
                self.password_mode = False
        except Exception as error:
            self.output.append(f"\n[SEND ERROR] {error}")
            self.disconnect_terminal(silent=True)

    def disconnect_terminal(self, silent=False):
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
        self.socket = None
        self.connected = False
        self.status_label.setText("● Terminal: Disconnected")
        self.status_label.setObjectName("TerminalBadgeRed")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)
        self.ws_status.setText("WebSocket: Offline")
        self.shell_status.setText("Shell: Waiting")
        self.terminal_ring.set_status("OFF", "#ff4d5f")
        self.session_state.setText("DISCONNECTED")
        self.session_detail.setText("Terminal session offline.")
        self.connect_btn.setEnabled(True)
        self.disconnect_btn.setEnabled(False)
        self.input.setEnabled(False)
        self.input.setEchoMode(QLineEdit.EchoMode.Normal)
        self.password_mode = False
        self.session_path = []
        self.raw_screen = ""
        if not silent:
            self.output.append("\n[DISCONNECTED]")
            self.set_activity("Manual disconnect")
        try:
            self.app_window.add_log("Terminal disconnected.")
        except Exception:
            pass

    def clear_terminal(self):
        self.output.clear()
        self.set_activity("Terminal cleared")

    _LIGHT_BTN = {
        "#22d3ee": ("#d9f7fc", "#00707f", "#8fdfeb"),
        "#50ff85": ("#dcfce7", "#11733a", "#93e6b0"),
        "#3a151c": ("#fde4e6", "#b42334", "#f3a9b1"),
        "#2a2f38": ("#eef1f5", "#334155", "#cbd5e1"),
        "#55c7ff": ("#e0f2ff", "#075985", "#9cccf5"),
        "#c084fc": ("#f3e8ff", "#6b21a8", "#d6b4fb"),
    }

    def on_theme_changed(self):
        for btn, bg, fg in getattr(self, "_painted_btns", []):
            self._paint_btn(btn, bg, fg, _record=False)

    def _paint_btn(self, btn, bg, fg, _record=True):
        if _record:
            if not hasattr(self, "_painted_btns"):
                self._painted_btns = []
            self._painted_btns.append((btn, bg, fg))
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setMinimumHeight(32)
        btn.setProperty("dslThemeExempt", True)
        light = False
        try:
            from ui.styles import current_theme
            light = current_theme() == "light"
        except Exception:
            pass
        if light and bg in self._LIGHT_BTN:
            lbg, lfg, lborder = self._LIGHT_BTN[bg]
            btn.setStyleSheet(
                "QPushButton {"
                f"  background:{lbg}; color:{lfg}; border:1px solid {lborder};"
                "  border-radius:8px; padding:6px 12px; font-weight:700;"
                "}"
                f"QPushButton:hover {{ border:1px solid {lfg}; }}"
                "QPushButton:disabled { background:#f1f3f5; color:#6b7c8c; border:1px solid #e2e6ea; }"
            )
            return
        sheet = (
            "QPushButton {"
            f"  background:{bg}; color:{fg}; border:none;"
            "  border-radius:8px; padding:6px 12px; font-weight:700;"
            "}"
            "QPushButton:disabled { background:#1a1a1a; color:#555; }"
        )
        try:
            from ui.styles import is_palette_theme, theme_remap
            if is_palette_theme():
                sheet = theme_remap(sheet)
        except Exception:
            pass
        btn.setStyleSheet(sheet)

    def show_cmd_view(self, title="VIEWING IN DEDSEC CMD"):
        self.cmd_overlay_title.setText(title)
        self.term_stack.setCurrentWidget(self.cmd_overlay)
        self.input.setEnabled(False)
        self.input.setPlaceholderText("Session is open in DedSec CMD")
        self.set_activity("Viewing in DedSec CMD")

    def hide_cmd_view(self):
        self.term_stack.setCurrentWidget(self.output)
        if self.connected:
            self.input.setEnabled(True)
            self.input.setPlaceholderText("Type menu option or command and press Enter")
            self.input.setFocus()
        self.set_activity("Returned from DedSec CMD")

    def open_dedsec_cmd(self):
        self.set_activity("Opened DedSec CMD window")
        open_dedsec_cmd(self, self.app_window, attach=True)
        self.show_cmd_view("VIEWING IN DEDSEC CMD")

    def open_vpn_puller(self):
        self.set_activity("Shortcut: VPN Puller")
        open_dedsec_cmd(
            self, self.app_window, path=list(PATH_VPN_PULLER), attach=False
        )
        self.show_cmd_view("VIEWING VPN PULLER IN DEDSEC CMD")

    def open_vpn_puller_v2(self):
        self.set_activity("Shortcut: VPN Puller v2")
        open_dedsec_cmd(
            self, self.app_window, path=list(PATH_VPN_PULLER_V2), attach=False
        )
        self.show_cmd_view("VIEWING VPN PULLER V2 IN DEDSEC CMD")