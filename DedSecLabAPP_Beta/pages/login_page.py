import sys
import os
import json
from pathlib import Path
from PyQt6.QtCore import Qt, QProcess, QTimer, QUrl, QObject, pyqtSignal
import threading
from PyQt6.QtGui import QPixmap, QDesktopServices
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QMessageBox, QCheckBox, QFileDialog, QApplication, QProgressBar,
    QFrame, QDialog, QTextEdit, QStackedWidget
)
from core.config import ConfigManager
from core import secure_store
from core.server import lab_probe
from ui.widgets import StatusRingWidget, MiniGraphWidget, TrafficBarsWidget, CyberDivider

DEFAULT_SERVER_URL = "https://YOUR_LAB_VPN_IP:8443"


# ============================================================
# FIRST-RUN SETUP WIZARD
# ============================================================
class FirstRunWizard(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Setup - DedSec Lab Client")
        self.setModal(True)
        self.setMinimumSize(580, 500)
        self.setMaximumSize(640, 560)
        self.accepted_terms = False
        self.setWindowFlags(
            Qt.WindowType.Dialog
            | Qt.WindowType.CustomizeWindowHint
            | Qt.WindowType.WindowTitleHint
            | Qt.WindowType.WindowCloseButtonHint
        )
        self.setStyleSheet("""
            QDialog {
                background: #0a0a0c;
                color: #e8f0ff;
            }
            QLabel#WizardTitle {
                font-size: 15px;
                font-weight: 800;
                color: #e8f0ff;
            }
            QLabel#WizardSubtitle {
                font-size: 12px;
                color: #9aa8bc;
            }
            QTextEdit {
                background: #12141a;
                color: #d0d8e8;
                border: 1px solid rgba(85, 199, 255, 0.18);
                border-radius: 6px;
                padding: 10px;
                font-size: 12px;
            }
            QCheckBox {
                color: #e8f0ff;
                font-size: 13px;
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
            }
            QPushButton {
                min-height: 30px;
                min-width: 88px;
                padding: 5px 14px;
                border-radius: 6px;
                font-weight: 700;
            }
            QPushButton#NextBtn {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #55c7ff, stop:1 #3aa8e0);
                border: none;
                color: #060606;
            }
            QPushButton#NextBtn:disabled {
                background: #1e222a;
                color: #5a6578;
            }
            QPushButton#BackBtn, QPushButton#CancelBtn {
                background: rgba(85, 199, 255, 0.06);
                border: 1px solid rgba(85, 199, 255, 0.22);
                color: #55c7ff;
            }
            QFrame#HeaderBar {
                background: #101218;
                border-bottom: 1px solid rgba(85, 199, 255, 0.10);
            }
            QFrame#FooterBar {
                background: #101218;
                border-top: 1px solid rgba(85, 199, 255, 0.10);
            }
        """)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        header = QFrame()
        header.setObjectName("HeaderBar")
        header.setFixedHeight(58)
        hl = QVBoxLayout(header)
        hl.setContentsMargins(18, 8, 18, 8)
        self.header_title = QLabel("Welcome")
        self.header_title.setObjectName("WizardTitle")
        self.header_sub = QLabel("Please complete setup before continuing.")
        self.header_sub.setObjectName("WizardSubtitle")
        hl.addWidget(self.header_title)
        hl.addWidget(self.header_sub)
        root.addWidget(header)

        self.stack = QStackedWidget()
        self.stack.addWidget(self._page_welcome())
        self.stack.addWidget(self._page_terms())
        self.stack.addWidget(self._page_ready())
        root.addWidget(self.stack, 1)

        footer = QFrame()
        footer.setObjectName("FooterBar")
        footer.setFixedHeight(58)
        fl = QHBoxLayout(footer)
        fl.setContentsMargins(16, 12, 16, 12)
        fl.setSpacing(10)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setObjectName("CancelBtn")
        self.cancel_btn.clicked.connect(self.reject)
        self.back_btn = QPushButton("Back")
        self.back_btn.setObjectName("BackBtn")
        self.back_btn.clicked.connect(self._back)
        self.back_btn.setEnabled(False)
        self.next_btn = QPushButton("Next")
        self.next_btn.setObjectName("NextBtn")
        self.next_btn.clicked.connect(self._next)
        fl.addWidget(self.cancel_btn)
        fl.addStretch()
        fl.addWidget(self.back_btn)
        fl.addWidget(self.next_btn)
        root.addWidget(footer)
        self._update_buttons()

    def _page_welcome(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(28, 22, 28, 18)
        layout.setSpacing(10)
        title = QLabel("Welcome to DedSec Lab Client")
        title.setStyleSheet("font-size: 18px; font-weight: 900; color: #55c7ff;")
        body = QLabel(
            "This setup will prepare your client for secure access.\n\n"
            "You will:\n"
            "  • Review and accept the terms of use\n"
            "  • Install OpenVPN (if needed)\n"
            "  • Select your VPN configuration\n"
            "  • Connect and log in to your account\n\n"
            "Click Next to continue."
        )
        body.setWordWrap(True)
        body.setStyleSheet("font-size: 13px; color: #b8c4d4;")
        layout.addWidget(title)
        layout.addWidget(body)
        layout.addStretch()
        return page

    def _page_terms(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(28, 14, 28, 16)
        layout.setSpacing(8)
        info = QLabel(
            "Please read the following Terms of Use. You must accept the terms "
            "before continuing with setup."
        )
        info.setWordWrap(True)
        info.setStyleSheet("font-size: 12px; color: #b8c4d4;")
        self.terms_box = QTextEdit()
        self.terms_box.setReadOnly(True)
        self.terms_box.setPlainText(
            "DEDSEC LAB CLIENT - TERMS OF USE\n"
            "================================\n\n"
            "IMPORTANT - PLEASE READ CAREFULLY\n\n"
            "This End-User Agreement is a legal agreement between you (either an "
            "individual or a single entity) and DedSec Lab for the DedSec Lab Client "
            "software product, which includes computer software and associated media "
            "and may include online or electronic documentation.\n\n"
            "By installing, copying, or otherwise using DedSec Lab Client, you agree "
            "to be bound by the terms of this agreement.\n\n"
            "1. LICENSE\n"
            "You are granted a limited, non-exclusive, non-transferable license to use "
            "the DedSec Lab Client for legitimate personal or authorised organisational use.\n\n"
            "2. RESTRICTIONS\n"
            "You may not reverse engineer, decompile, or attempt to extract source code "
            "from the client except as permitted by applicable law.\n\n"
            "3. PRIVACY & NO-LOGS\n"
            "DedSec Lab operates a strict no-logs policy for VPN traffic. Account data is "
            "used only for authentication and service delivery.\n\n"
            "4. VPN & NETWORK TOOLS\n"
            "Network tools and VPN features must be used in compliance with local laws "
            "and the terms of any networks you access.\n\n"
            "5. UPDATES\n"
            "The client may require updates. Unsupported versions may be blocked from "
            "connecting to the service.\n\n"
            "6. DISCLAIMER\n"
            "The software is provided \"as is\" without warranty of any kind. Use at your "
            "own risk.\n\n"
            "7. ACCEPTANCE\n"
            "By checking \"I accept the agreement\" and continuing, you confirm that you "
            "have read and agree to these terms."
        )
        self.accept_check = QCheckBox("I accept the agreement")
        self.accept_check.setChecked(False)
        self.accept_check.toggled.connect(self._update_buttons)
        layout.addWidget(info)
        layout.addWidget(self.terms_box, 1)
        layout.addSpacing(8)
        layout.addWidget(self.accept_check)
        return page

    def _page_ready(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(28, 22, 28, 18)
        layout.setSpacing(10)
        title = QLabel("You're almost ready")
        title.setStyleSheet("font-size: 18px; font-weight: 900; color: #50ff85;")
        body = QLabel(
            "Setup is complete.\n\n"
            "Next, the client will check for OpenVPN and guide you through "
            "selecting your VPN config if needed.\n\n"
            "Click Finish to continue to the secure access gateway."
        )
        body.setWordWrap(True)
        body.setStyleSheet("font-size: 13px; color: #b8c4d4;")
        layout.addWidget(title)
        layout.addWidget(body)
        layout.addStretch()
        return page

    def _update_buttons(self, *_):
        idx = self.stack.currentIndex()
        titles = [
            ("Welcome", "Welcome to DedSec Lab Client setup."),
            ("License Agreement", "Please read the following important information before continuing."),
            ("Setup Complete", "You can now continue to the client."),
        ]
        self.header_title.setText(titles[idx][0])
        self.header_sub.setText(titles[idx][1])
        self.back_btn.setEnabled(idx > 0)
        if idx == 0:
            self.next_btn.setText("Next")
            self.next_btn.setEnabled(True)
        elif idx == 1:
            self.next_btn.setText("Next")
            self.next_btn.setEnabled(self.accept_check.isChecked())
        else:
            self.next_btn.setText("Finish")
            self.next_btn.setEnabled(True)

    def _next(self):
        idx = self.stack.currentIndex()
        if idx == 1:
            if not self.accept_check.isChecked():
                return
            self.stack.setCurrentIndex(2)
            self._update_buttons()
            return
        if idx == 2:
            self.accepted_terms = True
            self.accept()
            return
        self.stack.setCurrentIndex(idx + 1)
        self._update_buttons()

    def _back(self):
        idx = self.stack.currentIndex()
        if idx > 0:
            self.stack.setCurrentIndex(idx - 1)
            self._update_buttons()


# ============================================================
# LOGIN PAGE
# ============================================================
class _ProbeRelay(QObject):
    done = pyqtSignal(bool, str)


class LoginPage(QWidget):
    def __init__(self, app_window):
        super().__init__()
        self.app_window = app_window
        self.vpn_process = None
        self.install_process = None
        self.vpn_connected = False
        self.openvpn_installed = False
        self.has_vpn_config = False
        self.detecting_vpn = True
        self._ui_ready = False
        self.locker_status = "approved"
        self.device_id = self.app_window.server.device_id
        if getattr(sys, "frozen", False):
            self.project_root = Path(sys.executable).resolve().parent
        else:
            self.project_root = Path(__file__).resolve().parents[1]
        self.logo_path = self.project_root / "assets" / "dedsec_logo.png"
        self.wallpaper_path = self._find_wallpaper()
        # Legacy login.key/login.dat live here; migrated once into the OS store.
        self.legacy_cred_dir = self.project_root
        self._last_probe_error = ""

        self.bg = QLabel(self)
        self.bg.setObjectName("LoginWallpaper")
        self.bg.setScaledContents(False)  # cover-cropped in resizeEvent (no stretching)
        self.bg.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self._bg_pix = QPixmap(str(self.wallpaper_path)) if self.wallpaper_path else QPixmap()
        if not self._bg_pix.isNull():
            self._apply_cover_wallpaper()
        self.bg.lower()
        self.setObjectName("LoginPage")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet("QWidget#LoginPage { background: transparent; } QWidget#LoginContent { background: transparent; }")

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 10, 18, 8)
        root.setSpacing(5)

        self.main_content = QWidget()
        self.main_content.setObjectName("LoginContent")
        self.main_content.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        content_root = QVBoxLayout(self.main_content)
        content_root.setContentsMargins(0, 0, 0, 0)
        content_root.setSpacing(5)

        content = QHBoxLayout()
        content.setSpacing(18)

        left_panel = QFrame()
        left_panel.setObjectName("LoginSideHud")
        left_panel.setMaximumWidth(245)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(16, 14, 16, 14)
        left_layout.setSpacing(10)
        left_title = QLabel("SECURE CHANNEL")
        left_title.setObjectName("LoginHudTitle")
        self.left_graph = MiniGraphWidget("#55c7ff")
        self.left_graph.setMinimumHeight(72)
        self.left_bars = TrafficBarsWidget("#50ff85")
        self.left_bars.setMinimumHeight(54)
        self.left_hint = QLabel("VPN route monitor\nEncrypted tunnel check\nBackend API heartbeat")
        self.left_hint.setObjectName("LoginHudText")
        self.left_hint.setWordWrap(True)
        left_layout.addWidget(left_title)
        left_layout.addWidget(CyberDivider())
        left_layout.addWidget(self.left_graph)
        left_layout.addWidget(self.left_bars)
        left_layout.addWidget(self.left_hint)
        left_layout.addStretch()
        content.addWidget(left_panel)
        left_panel.hide()

        panel = QFrame()
        panel.setObjectName("LoginMainPanel")
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(18, 8, 18, 10)
        panel_layout.setSpacing(3)

        self.logo = QLabel()
        self.logo.setObjectName("LoginLogo")
        self.logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.logo.setFixedHeight(42)
        if self.logo_path.exists():
            pixmap = QPixmap(str(self.logo_path))
            self.logo.setPixmap(
                pixmap.scaled(
                    42, 42,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                )
            )
        else:
            self.logo.setText("☠")
            self.logo.setObjectName("LoginLogoFallback")

        title = QLabel("DEDSEC-LAB ACCESS")
        title.setObjectName("LoginMainTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle = QLabel("Secure Infrastructure Access Platform")
        subtitle.setObjectName("LoginSubtitle")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.server_input = QLineEdit()
        self.server_input.hide()

        hero = QFrame()
        hero.setObjectName("LoginInnerPanel")
        hero.setMinimumHeight(110)
        hero.setMaximumHeight(120)
        hero_layout = QHBoxLayout(hero)
        hero_layout.setContentsMargins(16, 10, 16, 10)
        hero_layout.setSpacing(18)
        self.login_ring = StatusRingWidget("VPN", "#55c7ff")
        self.login_ring.setMinimumSize(100, 100)
        self.login_ring.setMaximumSize(100, 100)
        hero_text = QVBoxLayout()
        hero_text.setSpacing(5)
        self.stage_title = QLabel("SECURE ACCESS GATEWAY")
        self.stage_title.setObjectName("LoginHeroTitle")
        self.stage_title.setWordWrap(True)
        self.stage_title.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.stage_hint = QLabel("VPN verification is required before account login unlocks.")
        self.stage_hint.setObjectName("LoginPanelHint")
        self.stage_hint.setWordWrap(True)
        hero_text.addStretch()
        hero_text.addWidget(self.stage_title)
        hero_text.addWidget(CyberDivider())
        hero_text.addWidget(self.stage_hint)
        hero_text.addStretch()
        hero_layout.addStretch()
        hero_layout.addWidget(self.login_ring)
        hero_layout.addLayout(hero_text, 2)
        hero_layout.addStretch()

        self.traffic = TrafficBarsWidget("#55c7ff")
        self.traffic.setMinimumHeight(24)
        self.traffic.setMaximumHeight(28)

        self.locker_pending_frame = self._make_locker_frame(
            "DEVICE AWAITING APPROVAL",
            "This device is registered but not approved yet.\n"
            "Send your administrator the Device ID below.",
        )
        self.locker_revoked_frame = self._make_locker_frame(
            "⛔  DEVICE ACCESS REVOKED",
            "This device has been revoked by an administrator.\n"
            "Contact your administrator if you believe this is an error.",
        )
        self.locker_outdated_frame = self._make_locker_frame(
            "🔄  CLIENT UPDATE REQUIRED",
            "Your version of DedSec-Lab Client is no longer supported.\n"
            "Download and install the latest version to continue.",
        )
        self._update_btn = QPushButton("Download and install update")
        self._update_btn.setObjectName("LoginPrimaryButton")
        self._update_bar = QProgressBar()
        self._update_bar.setObjectName("LoginProgress")
        self._update_bar.setRange(0, 100)
        self._update_bar.hide()
        self.locker_outdated_frame.layout().addWidget(self._update_btn)
        self.locker_outdated_frame.layout().addWidget(self._update_bar)
        self._update_btn.clicked.connect(self._download_required_update)
        self.locker_error_frame = self._make_locker_frame(
            "⚠  AUTHORISATION SERVER UNREACHABLE",
            "Could not contact the authorisation server.\n"
            "Check your internet connection and try again.",
        )

        self.detect_title = QLabel("Checking VPN Status")
        self.detect_title.setObjectName("LoginStageTitle")
        self.detect_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.detect_hint = QLabel("Please wait while DEDSEC checks your secure connection...")
        self.detect_hint.setObjectName("Hint")
        self.detect_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.detect_hint.setWordWrap(True)
        self.detect_progress = QProgressBar()
        self.detect_progress.setRange(0, 0)
        self.detect_progress.setObjectName("LoginProgress")

        self.setup_title = QLabel("VPN Setup")
        self.setup_title.setObjectName("LoginStageTitle")
        self.setup_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setup_hint = QLabel("")
        self.setup_hint.setObjectName("Hint")
        self.setup_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setup_hint.setWordWrap(True)
        self.download_openvpn_button = QPushButton("1. Install OpenVPN GUI")
        self.download_openvpn_button.setObjectName("LoginPrimaryButton")
        self.download_openvpn_button.clicked.connect(self.download_openvpn)
        self.install_progress = QProgressBar()
        self.install_progress.setRange(0, 0)
        self.install_progress.setObjectName("LoginProgress")
        self.install_progress.hide()
        self.select_vpn_button = QPushButton("2. Select VPN Config (.ovpn)")
        self.select_vpn_button.setObjectName("LoginPrimaryButton")
        self.select_vpn_button.clicked.connect(self.select_vpn_config)
        self.vpn_config_label = QLabel("No .ovpn config selected")
        self.vpn_config_label.setObjectName("LoginConfigText")
        self.vpn_config_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.vpn_config_label.setWordWrap(True)

        self.vpn_title = QLabel("VPN Connection")
        self.vpn_title.setObjectName("LoginStageTitle")
        self.vpn_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.vpn_status = QLabel("VPN status: Not connected")
        self.vpn_status.setObjectName("LoginVPNStatus")
        self.vpn_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.connect_vpn_button = QPushButton("Connect VPN")
        self.connect_vpn_button.setObjectName("LoginPrimaryButton")
        self.connect_vpn_button.clicked.connect(self.connect_vpn)
        self.disconnect_vpn_button = QPushButton("Disconnect VPN")
        self.disconnect_vpn_button.setObjectName("LoginDangerButton")
        self.disconnect_vpn_button.clicked.connect(self.disconnect_vpn)
        self.disconnect_vpn_button.setEnabled(False)

        self.login_title = QLabel("Account Login")
        self.login_title.setObjectName("LoginStageTitle")
        self.login_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.username_input = QLineEdit()
        self.username_input.setObjectName("LoginInput")
        self.username_input.setPlaceholderText("Username")
        self.password_input = QLineEdit()
        self.password_input.setObjectName("LoginInput")
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.returnPressed.connect(self.login)
        self.save_username = QCheckBox("Remember username")
        self.save_password = QCheckBox("Remember password")
        self.login_button = QPushButton("Login  ->")
        self.login_button.setObjectName("LoginPrimaryButton")
        self.login_button.clicked.connect(self.login)
        self.login_hint = QLabel("VPN connected. Enter your account details.")
        self.login_hint.setObjectName("Hint")
        self.login_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.login_hint.setWordWrap(True)

        security_row = QHBoxLayout()
        security_row.setSpacing(10)
        self.vpn_protected = QLabel("🟢 VPN")
        self.vpn_protected.setObjectName("LoginMiniStatus")
        self.vpn_protected.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.api_secured = QLabel("🟢 API")
        self.api_secured.setObjectName("LoginMiniStatus")
        self.api_secured.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.terminal_ready = QLabel("🟢 Terminal")
        self.terminal_ready.setObjectName("LoginMiniStatus")
        self.terminal_ready.setAlignment(Qt.AlignmentFlag.AlignCenter)
        security_row.addWidget(self.vpn_protected, 1)
        security_row.addWidget(self.api_secured, 1)
        security_row.addWidget(self.terminal_ready, 1)

        panel_layout.addWidget(self.logo)
        panel_layout.addWidget(title)
        panel_layout.addWidget(subtitle)
        panel_layout.addSpacing(4)
        panel_layout.addWidget(hero)
        panel_layout.addWidget(self.traffic)
        panel_layout.addWidget(CyberDivider())
        panel_layout.addWidget(self.locker_pending_frame)
        panel_layout.addWidget(self.locker_revoked_frame)
        panel_layout.addWidget(self.locker_outdated_frame)
        panel_layout.addWidget(self.locker_error_frame)
        panel_layout.addWidget(self.detect_title)
        panel_layout.addWidget(self.detect_hint)
        panel_layout.addWidget(self.detect_progress)
        panel_layout.addWidget(self.setup_title)
        panel_layout.addWidget(self.setup_hint)
        panel_layout.addWidget(self.download_openvpn_button)
        panel_layout.addWidget(self.install_progress)
        panel_layout.addWidget(self.select_vpn_button)
        panel_layout.addWidget(self.vpn_config_label)
        panel_layout.addWidget(self.vpn_title)
        panel_layout.addWidget(self.vpn_status)
        panel_layout.addWidget(self.connect_vpn_button)
        panel_layout.addWidget(self.disconnect_vpn_button)
        panel_layout.addWidget(self.login_title)
        panel_layout.addWidget(self.username_input)
        panel_layout.addWidget(self.password_input)
        checkbox_row = QHBoxLayout()
        checkbox_row.addWidget(self.save_username)
        checkbox_row.addWidget(self.save_password)
        panel_layout.addLayout(checkbox_row)
        panel_layout.addWidget(self.login_button)
        panel_layout.addWidget(self.login_hint)
        panel_layout.addWidget(CyberDivider())
        panel_layout.addLayout(security_row)
        panel.setMaximumWidth(680)

        content.addStretch()
        content.addWidget(panel)
        content.addStretch()

        right_panel = QFrame()
        right_panel.setObjectName("LoginSideHud")
        right_panel.setMaximumWidth(245)
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(16, 14, 16, 14)
        right_layout.setSpacing(10)
        right_title = QLabel("ACCESS TELEMETRY")
        right_title.setObjectName("LoginHudTitle")
        self.right_graph = MiniGraphWidget("#55c7ff")
        self.right_graph.setMinimumHeight(72)
        self.right_bars = TrafficBarsWidget("#50ff85")
        self.right_bars.setMinimumHeight(54)
        self.right_hint = QLabel("Client status: Ready\nSession state: Locked\nAuthentication: Waiting")
        self.right_hint.setObjectName("LoginHudText")
        self.right_hint.setWordWrap(True)
        right_layout.addWidget(right_title)
        right_layout.addWidget(CyberDivider())
        right_layout.addWidget(self.right_graph)
        right_layout.addWidget(self.right_bars)
        right_layout.addWidget(self.right_hint)
        right_layout.addStretch()
        content.addWidget(right_panel)
        right_panel.hide()

        content_root.addLayout(content, 1)

        footer_box = QVBoxLayout()
        footer_box.setSpacing(4)
        footer = QLabel("DEDSEC-LAB CLIENT  •  Secure Infrastructure Access Platform")
        footer.setObjectName("Hint")
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.website_link = QLabel(
            '<a href="https://YOUR_WEBSITE_URL.example" style="color:#55c7ff; text-decoration:none;">Visit Website</a>'
        )
        self.website_link.setObjectName("Hint")
        self.website_link.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.website_link.setOpenExternalLinks(True)
        self.website_link.setCursor(Qt.CursorShape.PointingHandCursor)
        footer_box.addWidget(footer)
        footer_box.addWidget(self.website_link)
        content_root.addLayout(footer_box)

        root.addWidget(self.main_content, 1)
        self.main_content.hide()

        self.vpn_check_timer = QTimer(self)
        self.vpn_check_timer.timeout.connect(self.check_vpn_reachable)
        # While login is locked, keep re-probing the lab in the background so
        # a VPN connected from the mini DedSec VPN window unlocks automatically.
        self._lock_recheck = QTimer(self)
        self._lock_recheck.setInterval(4000)
        self._lock_recheck.timeout.connect(self._recheck_while_locked)
        self._lock_recheck.start()
        try:
            gate = getattr(QApplication.instance(), "_gate", None)
            if gate is not None and hasattr(gate, "connected_ok"):
                gate.connected_ok.connect(lambda *_: QTimer.singleShot(800, self._recheck_while_locked))
        except Exception:
            pass
        self.apply_login_theme()
        QTimer.singleShot(50, self.maybe_show_first_run)
        QTimer.singleShot(200, self._hide_updater)

    def _find_wallpaper(self):
        assets = self.project_root / "assets"
        names = (
            "site-wallpaper.jpg", "site-wallpaper.png", "site-wallpaper.jpeg",
            "login_wallpaper.png", "login_wallpaper.jpg", "login_wallpaper.jpeg",
            "wallpaper.png", "wallpaper.jpg", "wallpaper.jpeg",
            "background.png", "background.jpg", "background.jpeg",
            "login_bg.png", "login_bg.jpg", "bg.png", "bg.jpg",
            "dedsec_bg.png", "dedsec_wallpaper.png", "dedsec_wall.png",
            "wall.png", "wall.jpg",
        )
        for name in names:
            path = assets / name
            if path.is_file():
                return path
        if not assets.is_dir():
            return None
        skip = {"dedsec_logo.png", "dedsec_logo.ico", "us.png", "uk.png", "fr.png", "ca.png", "france.png", "canada.png"}
        images = [
            path for path in assets.iterdir()
            if path.is_file() and path.suffix.lower() in {".png", ".jpg", ".jpeg", ".webp"}
            and path.name.lower() not in skip and "logo" not in path.name.lower() and "icon" not in path.name.lower()
        ]
        if not images:
            return None
        return max(images, key=lambda path: path.stat().st_size)

    def _hide_updater(self):
        if os.name != "nt":
            return
        import ctypes
        hidden = 0x02 | 0x04  # Hidden | System
        for folder in (self.project_root, self.project_root / "DedSecLab"):
            for name in ("DedSecLabUpdater.exe", "updater.exe"):
                path = folder / name
                if path.is_file():
                    ctypes.windll.kernel32.SetFileAttributesW(str(path), hidden)
            blob = folder / "assets" / "dsl_upd.bin"
            if blob.is_file():
                ctypes.windll.kernel32.SetFileAttributesW(str(blob), hidden)

    def _apply_cover_wallpaper(self):
        """Scale the wallpaper to COVER the page (keep aspect, centre-crop)."""
        if self._bg_pix.isNull() or self.width() <= 0 or self.height() <= 0:
            return
        src = self._bg_pix
        try:
            from ui.styles import themed_wallpaper
            src = themed_wallpaper(src)
        except Exception:
            pass
        scaled = src.scaled(
            self.size(),
            Qt.AspectRatioMode.KeepAspectRatioByExpanding,
            Qt.TransformationMode.SmoothTransformation,
        )
        x = max(0, (scaled.width() - self.width()) // 2)
        y = max(0, (scaled.height() - self.height()) // 2)
        pix = scaled.copy(x, y, self.width(), self.height())
        try:
            from ui.styles import chrome_colors
            tint = chrome_colors().get("login_tint", (0, 0, 0, 0))
        except Exception:
            tint = (0, 0, 0, 0)
        if tint[3]:
            from PyQt6.QtGui import QPainter, QColor
            painter = QPainter(pix)
            painter.fillRect(pix.rect(), QColor(*tint))
            painter.end()
        self.bg.setPixmap(pix)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, "bg"):
            self.bg.setGeometry(0, 0, self.width(), self.height())
            self._apply_cover_wallpaper()
            self.bg.lower()

    def _server_url(self) -> str:
        """Always resolve a usable HTTPS API base URL."""
        url = self.server_input.text().strip().rstrip("/")
        if not url and hasattr(self.app_window, "config"):
            url = str(self.app_window.config.get("server_url", DEFAULT_SERVER_URL)).strip().rstrip("/")
        if not url:
            url = DEFAULT_SERVER_URL
        # Lab migration: old http defaults -> https
        if url.startswith("http://YOUR_LAB_VPN_IP"):
            url = "https://YOUR_LAB_VPN_IP:8443"
        return url

    def _make_locker_frame(self, title_text, hint_text):
        frame = QFrame()
        frame.setObjectName("LoginInnerPanel")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)
        title = QLabel(title_text)
        title.setObjectName("LoginStageTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setWordWrap(True)
        hint = QLabel(hint_text)
        hint.setObjectName("Hint")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hint.setWordWrap(True)
        device = QLabel(f"Device ID:  {self.device_id}")
        device.setObjectName("DeviceIdLabel")
        device.setAlignment(Qt.AlignmentFlag.AlignCenter)
        device.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(hint)
        layout.addWidget(device)
        return frame

    def _download_required_update(self):
        from core.updater import check_for_update, download_update, start_apply_and_exit, app_dir
        from PyQt6.QtCore import QThread, pyqtSignal

        if getattr(self, "_update_busy", False):
            return
        status, info = check_for_update(self._server_url())
        if status == "error":
            QMessageBox.warning(self, "Update", str(info))
            return
        if not isinstance(info, dict):
            QMessageBox.warning(self, "Update", "No update info from server.")
            return
        url = str(info.get("download_url") or "").strip()
        if not url:
            QMessageBox.warning(
                self, "Update",
                info.get("download_error") or "Update file is not on the server yet.",
            )
            return
        ver = str(info.get("latest") or info.get("version") or "").strip()
        sha = str(info.get("sha256") or "")
        sig = str(info.get("signature") or "")
        if not sha:
            QMessageBox.warning(
                self, "Update",
                "Update refused: the server did not provide a sha256 checksum.",
            )
            return
        dest_dir = self.project_root / "updates"
        dest_dir.mkdir(parents=True, exist_ok=True)
        self._update_btn.setEnabled(False)
        self._update_btn.setText("Downloading...")
        self._update_bar.setVisible(True)
        self._update_bar.setValue(0)
        self._update_busy = True

        self_ref = self

        class _Worker(QThread):
            prog = pyqtSignal(int)
            finished_ok = pyqtSignal(str, object)

            def run(self):
                code, result = download_update(
                    url, dest_dir=dest_dir, version=ver, progress_cb=self.prog.emit,
                    sha256=sha, signature=sig, server_url=self_ref._server_url(),
                )
                self.finished_ok.emit(code, result)

        def on_prog(n):
            self._update_bar.setValue(int(n))
            QApplication.processEvents()

        def on_done(code, result):
            self._update_busy = False
            self._update_btn.setEnabled(True)
            self._update_btn.setText("Download and install update")
            if code == "ok":
                st, msg = start_apply_and_exit(
                    Path(result), app_dir(), sha256=sha, signature=sig,
                )
                if st != "ok":
                    QMessageBox.warning(self, "Update", str(msg))
                    return
                QApplication.instance().quit()
            else:
                QMessageBox.warning(self, "Update", str(result))

        self._upd_worker = _Worker(self)
        self._upd_worker.prog.connect(on_prog)
        self._upd_worker.finished_ok.connect(on_done)
        self._upd_worker.start()

    def open_website(self):
        QDesktopServices.openUrl(QUrl("https://YOUR_WEBSITE_URL.example"))

    def _is_vpn_already_up(self):
        ok, err = lab_probe(self._server_url(), timeout=2)
        self._last_probe_error = err
        return ok

    def _unlock_login_after_vpn(self):
        self.login_button.setEnabled(True)
        self.login_hint.setText("VPN connected. Enter your account details.")

    def maybe_show_first_run(self):
        # Ensure server_input has a value before any VPN checks
        if not self.server_input.text().strip():
            cfg_url = DEFAULT_SERVER_URL
            if hasattr(self.app_window, "config"):
                cfg_url = str(self.app_window.config.get("server_url", DEFAULT_SERVER_URL)).strip()
            self.server_input.setText(cfg_url or DEFAULT_SERVER_URL)

        if self.find_openvpn_exe() is not None:
            # Probe runs async from _reveal_login_ui (never blocks the UI).
            self._reveal_login_ui()
            return
        if self._is_vpn_already_up():
            self.vpn_connected = True
            self.detecting_vpn = False
            self._reveal_login_ui()
            self.login_button.setEnabled(False)
            self.login_hint.setText("VPN connected. Preparing secure login...")
            QTimer.singleShot(3000, self._unlock_login_after_vpn)
            return
        if self.find_openvpn_exe() is not None:
            self._reveal_login_ui()
            return
        self.app_window.hide()
        wizard = FirstRunWizard(None)
        wizard.setWindowModality(Qt.WindowModality.ApplicationModal)
        screen = QApplication.primaryScreen()
        if screen:
            geo = screen.availableGeometry()
            wizard.adjustSize()
            wizard.move(
                geo.center().x() - wizard.width() // 2,
                geo.center().y() - wizard.height() // 2,
            )
        result = wizard.exec()
        if result == QDialog.DialogCode.Accepted and wizard.accepted_terms:
            self.app_window.add_log("[SETUP] First-run wizard completed")
            self.app_window.show()
            self.app_window.raise_()
            self.app_window.activateWindow()
            self._reveal_login_ui()
        else:
            QApplication.quit()

    def _reveal_login_ui(self):
        self.main_content.show()
        self._ui_ready = True
        self.update_stage_visibility()
        if self.detecting_vpn:
            QTimer.singleShot(400, self.check_initial_vpn_state)

    def save_secure_password(self, username, password):
        try:
            secure_store.save_login(username, password)
            warn = secure_store.backend_warning()
            if warn:
                self.app_window.add_log(warn)
        except Exception as e:
            self.app_window.add_log(f"[LOGIN] Failed saving password ({type(e).__name__}).")

    def load_secure_password(self):
        try:
            return secure_store.load_login(
                legacy_dir=self.legacy_cred_dir,
                log=self.app_window.add_log,
            )
        except Exception as e:
            self.app_window.add_log(f"[LOGIN] Failed loading password ({type(e).__name__}).")
            return None

    def clear_secure_password(self):
        try:
            secure_store.clear_login()
            # Also drop any leftover legacy files once the secure store is usable.
            if secure_store.is_secure():
                for name in ("login.key", "login.dat"):
                    (self.legacy_cred_dir / name).unlink(missing_ok=True)
        except Exception as e:
            self.app_window.add_log(f"[LOGIN] Failed clearing password ({type(e).__name__}).")

    def load_config(self):
        config = self.app_window.config
        self.server_input.setText(config.get("server_url", DEFAULT_SERVER_URL))
        self.save_username.setChecked(config.get("save_username", True))
        self.save_password.setChecked(config.get("save_password", False))
        ovpn = config.get("ovpn_config", "")
        self.has_vpn_config = bool(ovpn and Path(ovpn).exists())
        self.openvpn_installed = self.find_openvpn_exe() is not None
        self.install_progress.hide()
        self.vpn_config_label.setText(
            f"Config: {ovpn}" if self.has_vpn_config else "No .ovpn config selected"
        )
        if config.get("save_password", False):
            saved_login = self.load_secure_password()
            if saved_login:
                self.password_input.setText(saved_login.get("password", ""))
                if config.get("save_username", False):
                    self.username_input.setText(saved_login.get("username", ""))
        self.detecting_vpn = True
        if self._ui_ready:
            self.update_stage_visibility()

    def update_stage_visibility(self):
        if not self._ui_ready:
            return
        self.locker_pending_frame.setVisible(False)
        self.locker_revoked_frame.setVisible(False)
        self.locker_outdated_frame.setVisible(False)
        self.locker_error_frame.setVisible(False)

        if self.locker_status == "pending":
            self.login_ring.set_status("LOCKED", "#ffcc33")
            self.stage_title.setText("DEVICE NOT AUTHORISED")
            self.stage_hint.setText("This device is awaiting admin approval.")
            self.locker_pending_frame.setVisible(True)
            self._hide_all_flow_widgets()
            return
        if self.locker_status == "revoked":
            self.login_ring.set_status("FAIL", "#ff4d5f")
            self.stage_title.setText("DEVICE ACCESS REVOKED")
            self.stage_hint.setText("This device has been revoked by an administrator.")
            self.locker_revoked_frame.setVisible(True)
            self._hide_all_flow_widgets()
            return
        if self.locker_status == "outdated":
            self.login_ring.set_status("FAIL", "#ff9900")
            self.stage_title.setText("CLIENT UPDATE REQUIRED")
            self.stage_hint.setText("Your app version is no longer supported. Please update.")
            self.locker_outdated_frame.setVisible(True)
            self._hide_all_flow_widgets()
            return
        if self.locker_status == "error":
            self.login_ring.set_status("FAIL", "#ff4d5f")
            self.stage_title.setText("AUTHORISATION SERVER UNREACHABLE")
            self.stage_hint.setText("Could not verify this device. Check your connection.")
            self.locker_error_frame.setVisible(True)
            self._hide_all_flow_widgets()
            return

        if self.detecting_vpn:
            self.login_ring.set_status("SCAN", "#55c7ff")
            self.stage_title.setText("CHECKING SECURE CONNECTION")
            self.stage_hint.setText("Please wait while DEDSEC verifies your VPN route.")
            self.right_hint.setText(
                "Client status: Initializing\nSession state: Scanning\nAuthentication: Locked"
            )
            self.detect_title.setVisible(True)
            self.detect_hint.setVisible(True)
            self.detect_progress.setVisible(True)
            self._hide_non_detect_widgets()
            return

        self.detect_title.setVisible(False)
        self.detect_hint.setVisible(False)
        self.detect_progress.setVisible(False)

        if self.vpn_connected:
            self.login_ring.set_status("READY", "#50ff85")
            self.stage_title.setText("SECURE CONNECTION VERIFIED")
            self.stage_hint.setText("VPN tunnel is active. Account login is now unlocked.")
            self.right_hint.setText(
                "Client status: Ready\nSession state: Login unlocked\nAuthentication: Waiting"
            )
            for w in [
                self.setup_title, self.setup_hint, self.download_openvpn_button,
                self.install_progress, self.select_vpn_button, self.vpn_config_label,
                self.vpn_title, self.vpn_status, self.connect_vpn_button, self.disconnect_vpn_button,
            ]:
                w.setVisible(False)
            self.login_title.setVisible(True)
            self.username_input.setVisible(True)
            self.password_input.setVisible(True)
            self.save_username.setVisible(True)
            self.save_password.setVisible(True)
            self.login_button.setVisible(True)
            self.login_hint.setVisible(True)
            return

        self.login_ring.set_status("LOCKED", "#ffcc33")
        self.stage_title.setText("VPN REQUIRED")
        self.stage_hint.setText("Complete VPN setup or connect to unlock account login.")
        self.right_hint.setText(
            "Client status: Locked\nSession state: VPN required\nAuthentication: Blocked"
        )
        if not self.openvpn_installed:
            self.setup_hint.setText(
                "VPN setup:\n"
                "1. Install OpenVPN GUI\n"
                "2. Select your .ovpn config file\n"
                "3. Connect VPN, then log in"
            )
        elif not self.has_vpn_config:
            self.setup_hint.setText(
                "OpenVPN is installed.\n"
                "Select your .ovpn config file to continue."
            )
        setup_needed = not self.openvpn_installed or not self.has_vpn_config
        self.setup_title.setVisible(setup_needed)
        self.setup_hint.setVisible(setup_needed)
        self.download_openvpn_button.setVisible(not self.openvpn_installed)
        self.select_vpn_button.setVisible(self.openvpn_installed and not self.has_vpn_config)
        self.vpn_config_label.setVisible(setup_needed)
        vpn_ready = not setup_needed
        self.vpn_title.setVisible(vpn_ready)
        self.vpn_status.setVisible(vpn_ready)
        self.connect_vpn_button.setVisible(vpn_ready and not self.vpn_connected)
        self.disconnect_vpn_button.setVisible(vpn_ready and self.vpn_connected)
        self.login_title.setVisible(False)
        self.username_input.setVisible(False)
        self.password_input.setVisible(False)
        self.save_username.setVisible(False)
        self.save_password.setVisible(False)
        self.login_button.setVisible(False)
        self.login_hint.setVisible(False)

    def _hide_all_flow_widgets(self):
        for w in [
            self.detect_title, self.detect_hint, self.detect_progress,
            self.setup_title, self.setup_hint, self.download_openvpn_button,
            self.install_progress, self.select_vpn_button, self.vpn_config_label,
            self.vpn_title, self.vpn_status, self.connect_vpn_button,
            self.disconnect_vpn_button, self.login_title, self.username_input,
            self.password_input, self.save_username, self.save_password,
            self.login_button, self.login_hint,
        ]:
            w.setVisible(False)

    def _hide_non_detect_widgets(self):
        for w in [
            self.setup_title, self.setup_hint, self.download_openvpn_button,
            self.install_progress, self.select_vpn_button, self.vpn_config_label,
            self.vpn_title, self.vpn_status, self.connect_vpn_button,
            self.disconnect_vpn_button, self.login_title, self.username_input,
            self.password_input, self.save_username, self.save_password,
            self.login_button, self.login_hint,
        ]:
            w.setVisible(False)

    def _probe_async(self, callback):
        """Run lab_probe off the UI thread so the window never freezes."""
        if getattr(self, "_probe_busy", False):
            return
        self._probe_busy = True
        relay = _ProbeRelay(self)
        def _finish(ok, err, relay=relay):
            self._probe_busy = False
            relay.deleteLater()
            try:
                callback(ok, err)
            except RuntimeError:
                pass
        relay.done.connect(_finish)
        url = self._server_url()
        def _run():
            try:
                ok, err = lab_probe(url, timeout=2)
            except Exception:
                ok, err = False, ""
            try:
                relay.done.emit(bool(ok), str(err or ""))
            except RuntimeError:
                pass
        threading.Thread(target=_run, daemon=True).start()

    def check_initial_vpn_state(self):
        self._probe_async(self._on_initial_probe)

    def _on_initial_probe(self, ok, err):
        self._last_probe_error = err
        if ok:
            self.vpn_connected = True
            self.vpn_status.setText("VPN status: Connected")
            self.detecting_vpn = False
            self.update_stage_visibility()
            self.login_button.setEnabled(False)
            self.login_hint.setText("VPN connected. Preparing secure login...")
            QTimer.singleShot(3000, self._unlock_login_after_vpn)
            return
        if err:
            self.app_window.add_log(f"[VPN] Probe: {err.splitlines()[0]}")
        self.vpn_connected = False
        self.detecting_vpn = False
        self.update_stage_visibility()
        self._show_route_diagnosis()

    def _recheck_while_locked(self):
        """Background re-probe while the login is locked (non-blocking)."""
        if self.vpn_connected or self.detecting_vpn or not self._ui_ready:
            return
        if self.locker_status != "approved" or not self.isVisible():
            return
        self._probe_async(self._on_recheck_probe)

    def _on_recheck_probe(self, ok, err):
        self._last_probe_error = err
        if ok:
            if not self.vpn_connected:
                self.app_window.add_log("[VPN] Lab reachable - unlocking login.")
                self.mark_vpn_connected()
            return
        self._show_route_diagnosis()

    def _show_route_diagnosis(self):
        """Explain WHY it is locked when the DedSec tunnel is up but the lab is not reachable."""
        if self.vpn_connected or self.locker_status != "approved":
            return
        try:
            from core.dedsec_vpn_gate import vpn_tunnel_up
            tunnel = bool(vpn_tunnel_up())
        except Exception:
            tunnel = False
        if not tunnel:
            return
        other = ""
        try:
            import psutil
            names = list(psutil.net_if_stats().keys())
            ups = {n for n, st in psutil.net_if_stats().items() if st.isup}
            for n in names:
                low = n.lower()
                if n in ups and any(k in low for k in (
                    "nordlynx", "nordvpn", "proton", "mullvad", "expressvpn",
                    "surfshark", "windscribe", "cyberghost", "pia",
                )):
                    other = n
                    break
        except Exception:
            pass
        self.stage_title.setText("LAB NOT REACHABLE")
        if other:
            self.stage_hint.setText(
                f"Another VPN ({other}) is blocking the lab. "
                "Disconnect it and login unlocks automatically."
            )
        else:
            self.stage_hint.setText(
                "VPN is up but the lab is not answering yet. Retrying..."
            )

    def apply_login_theme(self):
        """Light/dark bits that the app stylesheet can't reach (link HTML, ring)."""
        try:
            from ui.styles import current_theme
            light = current_theme() == "light"
        except Exception:
            light = False
        col = "#00707f" if light else "#55c7ff"
        if not light:
            try:
                from ui.styles import theme_color
                col = theme_color(col)
            except Exception:
                pass
        self.website_link.setText(
            f'<a href="https://YOUR_WEBSITE_URL.example" style="color:{col}; text-decoration:none; font-weight:700;">Visit Website</a>'
        )
        if hasattr(self.login_ring, "set_light"):
            self.login_ring.set_light(light)

    def select_vpn_config(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select OpenVPN Config", str(Path.home()),
            "OpenVPN Config (*.ovpn);;All Files (*)",
        )
        if file_path:
            self.app_window.config["ovpn_config"] = file_path
            ConfigManager.save(self.app_window.config)
            self.has_vpn_config = True
            self.openvpn_installed = self.find_openvpn_exe() is not None
            self.vpn_config_label.setText(f"Config: {file_path}")
            self.update_stage_visibility()

    def download_openvpn(self):
        self.download_openvpn_button.setEnabled(False)
        self.install_progress.show()
        self.setup_hint.setText(
            "Installing OpenVPN GUI...\n"
            "Windows may ask for administrator permission.\n"
            "Please wait until installation finishes."
        )
        self.app_window.add_log("[SETUP] Installing OpenVPN GUI with winget...")
        self.install_process = QProcess(self)
        self.install_process.readyReadStandardOutput.connect(self.read_install_output)
        self.install_process.readyReadStandardError.connect(self.read_install_error)
        self.install_process.finished.connect(self.openvpn_install_finished)
        self.install_process.start("winget", [
            "install", "--id", "OpenVPNTechnologies.OpenVPN",
            "-e", "--silent", "--accept-package-agreements", "--accept-source-agreements",
        ])
        if not self.install_process.waitForStarted(3000):
            error = self.install_process.errorString()
            self.install_progress.hide()
            self.download_openvpn_button.setEnabled(True)
            QMessageBox.warning(self, "Install Failed", f"Could not start winget:\n{error}")

    def read_install_output(self):
        output = bytes(self.install_process.readAllStandardOutput()).decode(errors="ignore")
        for line in output.splitlines():
            self.app_window.add_log(f"[SETUP] {line}")
            if "Downloading" in line:
                self.setup_hint.setText("Downloading OpenVPN GUI...\nPlease wait.")
            elif "Starting package install" in line:
                self.setup_hint.setText("Installing OpenVPN GUI...\nPlease wait.")
            elif "Successfully installed" in line:
                self.setup_hint.setText("OpenVPN installed successfully.")

    def read_install_error(self):
        output = bytes(self.install_process.readAllStandardError()).decode(errors="ignore")
        for line in output.splitlines():
            self.app_window.add_log(f"[SETUP ERROR] {line}")

    def openvpn_install_finished(self, exit_code, exit_status):
        self.install_progress.hide()
        self.openvpn_installed = self.find_openvpn_exe() is not None
        self.app_window.add_log(f"[SETUP] winget finished with code: {exit_code}")
        if exit_code == 0 or self.openvpn_installed:
            answer = QMessageBox.question(
                self, "OpenVPN Installed",
                "OpenVPN GUI was installed successfully.\n\nRestart the app now so setup can continue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if answer == QMessageBox.StandardButton.Yes:
                self.restart_app()
            else:
                self.setup_hint.setText(
                    "OpenVPN installed successfully.\nPlease restart this app when ready."
                )
                self.download_openvpn_button.setEnabled(True)
                self.update_stage_visibility()
        else:
            QMessageBox.warning(
                self, "Install Failed",
                "OpenVPN installer finished but OpenVPN was not detected.\n\nCheck Logs for details.",
            )
            self.download_openvpn_button.setEnabled(True)
            self.update_stage_visibility()

    def restart_app(self):
        from core.updater import restart_command
        cmd = restart_command()
        if not QProcess.startDetached(cmd[0], cmd[1:]):
            QMessageBox.warning(self, "Restart Failed", "Could not relaunch DedSec Lab.")
            return
        QApplication.quit()

    def find_openvpn_exe(self):
        paths = [
            r"C:\Program Files\OpenVPN\bin\openvpn.exe",
            r"C:\Program Files (x86)\OpenVPN\bin\openvpn.exe",
        ]
        for path in paths:
            if Path(path).exists():
                return path
        return None

    def mark_vpn_connected(self):
        self.vpn_connected = True
        self.detecting_vpn = False
        self.login_ring.set_status("READY", "#50ff85")
        self.vpn_status.setText("VPN status: Connected")
        self.connect_vpn_button.setEnabled(False)
        self.disconnect_vpn_button.setEnabled(True)
        self.login_button.setEnabled(False)
        self.login_hint.setText("VPN connected. Preparing secure login...")
        self.update_stage_visibility()
        QTimer.singleShot(3000, self._unlock_login_after_vpn)

    def connect_vpn(self):
        ovpn_config = self.app_window.config.get("ovpn_config", "")
        if not ovpn_config or not Path(ovpn_config).exists():
            self.has_vpn_config = False
            self.update_stage_visibility()
            QMessageBox.warning(self, "Missing Config", "Please select a valid .ovpn config first.")
            return
        openvpn_exe = self.find_openvpn_exe()
        if not openvpn_exe:
            self.openvpn_installed = False
            self.update_stage_visibility()
            QMessageBox.warning(self, "OpenVPN Not Found", "OpenVPN was not found. Install OpenVPN first.")
            return
        self.openvpn_installed = True
        self.has_vpn_config = True
        self.vpn_connected = False
        self.vpn_process = QProcess(self)
        self.vpn_process.readyReadStandardOutput.connect(self.read_vpn_output)
        self.vpn_process.readyReadStandardError.connect(self.read_vpn_error)
        self.vpn_process.finished.connect(self.vpn_stopped)
        self.app_window.add_log(f"[VPN] Starting: {openvpn_exe}")
        self.app_window.add_log(f"[VPN] Config: {ovpn_config}")
        self.vpn_process.start(openvpn_exe, ["--config", ovpn_config])
        if not self.vpn_process.waitForStarted(3000):
            error = self.vpn_process.errorString()
            QMessageBox.warning(self, "VPN Failed", f"OpenVPN did not start:\n{error}")
            self.app_window.add_log(f"[VPN ERROR] Failed to start: {error}")
            self.connect_vpn_button.setEnabled(True)
            self.disconnect_vpn_button.setEnabled(False)
            self.update_stage_visibility()
            return
        self.login_ring.set_status("VPN", "#ffcc33")
        self.vpn_status.setText("VPN status: Starting...")
        self.connect_vpn_button.setEnabled(False)
        self.disconnect_vpn_button.setEnabled(True)
        self.update_stage_visibility()
        self.vpn_check_timer.start(2500)

    def disconnect_vpn(self):
        self.vpn_check_timer.stop()
        self.vpn_connected = False
        self.login_ring.set_status("LOCKED", "#ffcc33")
        if self.vpn_process:
            self.vpn_process.kill()
            self.vpn_process = None
        self.vpn_status.setText("VPN status: Disconnected")
        self.connect_vpn_button.setEnabled(True)
        self.disconnect_vpn_button.setEnabled(False)
        self.update_stage_visibility()

    def vpn_stopped(self):
        self.vpn_check_timer.stop()
        if not self.vpn_connected:
            self.vpn_status.setText("VPN status: Disconnected")
            self.connect_vpn_button.setEnabled(True)
            self.disconnect_vpn_button.setEnabled(False)
            self.update_stage_visibility()
        self.app_window.add_log("[VPN] Process stopped.")

    def check_vpn_reachable(self):
        self._probe_async(self._on_reachable_probe)

    def _on_reachable_probe(self, ok, err):
        self._last_probe_error = err
        if ok:
            self.mark_vpn_connected()
            self.vpn_check_timer.stop()
        elif not self.vpn_connected:
            self.vpn_status.setText("VPN status: Connecting...")

    def read_vpn_output(self):
        output = bytes(self.vpn_process.readAllStandardOutput()).decode(errors="ignore")
        for line in output.splitlines():
            self.app_window.add_log(f"[VPN] {line}")
            lower = line.lower()
            if any(k in lower for k in [
                "initialization sequence completed", "push_reply",
                "peer connection initiated", "ifconfig", "netsh",
                "route addition", "assigned peer",
            ]):
                self.mark_vpn_connected()
            elif "auth_failed" in lower:
                self.vpn_status.setText("VPN status: Auth failed")
                self.login_ring.set_status("FAIL", "#ff4d5f")

    def read_vpn_error(self):
        output = bytes(self.vpn_process.readAllStandardError()).decode(errors="ignore")
        for line in output.splitlines():
            self.app_window.add_log(f"[VPN ERROR] {line}")
            lower = line.lower()
            if any(k in lower for k in [
                "initialization sequence completed", "push_reply",
                "peer connection initiated", "ifconfig", "netsh", "route addition",
            ]):
                self.mark_vpn_connected()
            elif "auth_failed" in lower:
                self.vpn_status.setText("VPN status: Auth failed")
                self.login_ring.set_status("FAIL", "#ff4d5f")

    def login(self):
        username = self.username_input.text().strip()
        password = self.password_input.text()
        server_url = self._server_url()
        ok, message = self.app_window.server.login(username, password, server_url)
        if not ok:
            QMessageBox.warning(self, "Connection Failed", message)
            return
        self.app_window.config["server_url"] = server_url
        self.app_window.config["save_username"] = self.save_username.isChecked()
        self.app_window.config["username"] = username if self.save_username.isChecked() else ""
        self.app_window.config["save_password"] = self.save_password.isChecked()
        self.app_window.config.pop("password", None)
        if self.save_password.isChecked():
            self.save_secure_password(username, password)
        else:
            self.clear_secure_password()
        ConfigManager.save(self.app_window.config)
        self.password_input.clear()
        self.app_window.show_main_app()
