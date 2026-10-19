import webbrowser
from pathlib import Path

from PyQt6.QtCore import Qt, QUrl, QTimer
from PyQt6.QtGui import QDesktopServices, QIcon, QPixmap, QPainter, QColor
from PyQt6.QtWidgets import (
    QApplication,
    QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton,
    QMessageBox, QCheckBox, QFrame, QFormLayout, QHBoxLayout,
    QGridLayout, QScrollArea, QRadioButton, QButtonGroup
)

from core.config import ConfigManager, CONFIG_FILE, APP_DIR
from core.updater import (
    APP_VERSION,
    app_dir,
    check_for_update,
    download_update,
    start_apply_and_exit,
)
from ui.widgets import CyberDivider
from ui.styles import THEMES, THEME_LABELS, apply_theme, resolve_theme
try:
    from ui.styles import THEME_SWATCHES
except ImportError:  # older styles module
    THEME_SWATCHES = {}


def _swatch_icon(key) -> QIcon:
    """Small preview: theme background, a card and the accent colour."""
    bg, card, acc = THEME_SWATCHES.get(key, ("#060606", "#0d1c2c", "#2ee6ff"))
    pm = QPixmap(88, 56)
    pm.fill(QColor(0, 0, 0, 0))
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setPen(QColor("#5b6f80"))
    p.setBrush(QColor(bg))
    p.drawRoundedRect(1, 1, 86, 54, 9, 9)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(card))
    p.drawRoundedRect(10, 10, 68, 36, 6, 6)
    p.setBrush(QColor(acc))
    p.drawRoundedRect(16, 17, 34, 6, 3, 3)
    p.drawEllipse(60, 16, 10, 10)
    p.setBrush(QColor(acc).darker(160) if QColor(bg).lightness() > 128 else QColor(acc).lighter(100))
    p.setOpacity(0.45)
    p.drawRoundedRect(16, 30, 46, 5, 2, 2)
    p.end()
    return QIcon(pm)


_SWATCH_QSS = """
QPushButton#ThemeSwatch {
    background: rgba(13, 28, 44, 0.85);
    border: 1px solid rgba(46, 230, 255, 0.18);
    border-radius: 10px;
    padding: 6px 8px;
    color: #eef6ff;
    font-weight: 700;
    font-size: 12px;
    text-align: left;
}
QPushButton#ThemeSwatch:hover { border: 1px solid rgba(46, 230, 255, 0.55); }
QPushButton#ThemeSwatch:checked {
    background: rgba(46, 230, 255, 0.12);
    border: 2px solid #2ee6ff;
}
QPushButton#ThemeSwatch:disabled { color: #7d93a8; }
"""


def _card() -> QFrame:
    f = QFrame()
    f.setObjectName("SettingsPanel")
    return f


class SettingsPage(QWidget):
    def __init__(self, app_window):
        super().__init__()
        self.app_window = app_window

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        outer.addWidget(scroll)

        content = QWidget()
        scroll.setWidget(content)

        root = QVBoxLayout(content)
        root.setContentsMargins(24, 18, 24, 18)
        root.setSpacing(12)

        header = QHBoxLayout()
        title_box = QVBoxLayout()
        title_box.setSpacing(2)

        title = QLabel("Settings")
        title.setObjectName("PageTitle")

        subtitle = QLabel("Connection, preferences, updates, and local data.")
        subtitle.setObjectName("StatusLine")
        subtitle.setWordWrap(True)

        title_box.addWidget(title)
        title_box.addWidget(subtitle)

        self.status_badge = QLabel("● Ready")
        self.status_badge.setObjectName("SettingsLiveBadge")
        self.status_badge.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        header.addLayout(title_box, 1)
        header.addWidget(self.status_badge)
        root.addLayout(header)

        cols = QHBoxLayout()
        cols.setSpacing(12)

        left = QVBoxLayout()
        left.setSpacing(10)

        right = QVBoxLayout()
        right.setSpacing(10)

        # ---------------- APPEARANCE / THEMES ----------------
        theme_card = _card()
        tl = QVBoxLayout(theme_card)
        tl.setContentsMargins(16, 14, 16, 14)
        tl.setSpacing(8)

        tt = QLabel("APPEARANCE  ·  THEME")
        tt.setObjectName("SettingsPanelTitle")
        tl.addWidget(tt)

        th = QLabel(
            "Default is the original DedSec look, Dark is deeper black, Light is bright. "
            "Matrix, Crimson, Midnight, Amber and OLED Black recolour the whole app and the "
            "DedSec VPN window. Changes apply instantly and are saved."
        )
        th.setObjectName("StatusLine")
        th.setWordWrap(True)
        tl.addWidget(th)

        self.theme_group = QButtonGroup(self)
        self.theme_group.setExclusive(True)
        self.theme_buttons = {}
        trow = QGridLayout()
        trow.setHorizontalSpacing(8)
        trow.setVerticalSpacing(8)
        ncols = 4
        for i, key in enumerate(THEMES):
            rb = QPushButton(THEME_LABELS.get(key, key.title()))
            rb.setObjectName("ThemeSwatch")
            rb.setCheckable(True)
            rb.setIcon(_swatch_icon(key))
            rb.setIconSize(QPixmap(44, 28).size())
            rb.setMinimumHeight(44)
            rb.setToolTip(f"{THEME_LABELS.get(key, key.title())} theme")
            rb.setStyleSheet(_SWATCH_QSS)
            rb.setProperty("themeKey", key)
            rb.setCursor(Qt.CursorShape.PointingHandCursor)
            self.theme_group.addButton(rb)
            self.theme_buttons[key] = rb
            trow.addWidget(rb, i // ncols, i % ncols)
        for c in range(ncols):
            trow.setColumnStretch(c, 1)
        tl.addLayout(trow)

        self.theme_status = QLabel("")
        self.theme_status.setObjectName("SettingsConnectionState")
        tl.addWidget(self.theme_status)

        self.theme_group.buttonClicked.connect(self._on_theme_clicked)
        left.addWidget(theme_card)

        conn = _card()
        cl = QVBoxLayout(conn)
        cl.setContentsMargins(16, 14, 16, 14)
        cl.setSpacing(8)

        ct = QLabel("CONNECTION")
        ct.setObjectName("SettingsPanelTitle")
        cl.addWidget(ct)

        form = QFormLayout()
        form.setSpacing(8)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)

        self.server_input = QLineEdit()
        self.server_input.setPlaceholderText("https://YOUR_LAB_VPN_IP:8443")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Default username")

        form.addRow("Server URL", self.server_input)
        form.addRow("Username", self.username_input)
        cl.addLayout(form)

        row = QHBoxLayout()
        self.test_button = QPushButton("Test Connection")
        self.test_button.setObjectName("SettingsSecondaryButton")
        self.test_button.clicked.connect(self.test_connection)

        self.connection_state = QLabel("Status: -")
        self.connection_state.setObjectName("SettingsConnectionState")

        row.addWidget(self.test_button)
        row.addStretch()
        row.addWidget(self.connection_state)
        cl.addLayout(row)
        left.addWidget(conn)

        prefs = _card()
        pl = QVBoxLayout(prefs)
        pl.setContentsMargins(16, 14, 16, 14)
        pl.setSpacing(6)

        pt = QLabel("PREFERENCES")
        pt.setObjectName("SettingsPanelTitle")
        pl.addWidget(pt)

        self.auto_connect = QCheckBox("Auto-connect VPN on launch")
        self.save_username = QCheckBox("Remember username on login")
        self.notifications = QCheckBox("Desktop notifications")
        self.animations = QCheckBox("Interface animations")
        self.splash_enabled = QCheckBox("Show splash screen on launch")
        self.click_fx = QCheckBox("Click animation effect")
        self.click_fx.toggled.connect(self._apply_click_fx)
        for cb in (self.auto_connect, self.save_username, self.notifications, self.animations,
                   self.splash_enabled, self.click_fx):
            pl.addWidget(cb)
        left.addWidget(prefs)

        updates = _card()
        ul = QVBoxLayout(updates)
        ul.setContentsMargins(16, 14, 16, 14)
        ul.setSpacing(8)

        ut = QLabel("UPDATES")
        ut.setObjectName("SettingsPanelTitle")
        ul.addWidget(ut)

        self.version_label = QLabel(f"Installed version  ·  {APP_VERSION}")
        self.version_label.setObjectName("StatusLine")
        ul.addWidget(self.version_label)

        self.update_hint = QLabel(
            "Checks the lab API over VPN. If a file is published it downloads; otherwise it says the file is not on the server yet."
        )
        self.update_hint.setObjectName("StatusLine")
        self.update_hint.setWordWrap(True)
        ul.addWidget(self.update_hint)

        urow = QHBoxLayout()
        self.check_updates_button = QPushButton("Check for Updates")
        self.check_updates_button.setObjectName("SettingsPrimaryButton")
        self.check_updates_button.clicked.connect(self.check_for_updates)

        self.open_website_button = QPushButton("Open Website")
        self.open_website_button.setObjectName("SettingsSecondaryButton")
        self.open_website_button.clicked.connect(self.open_website)

        urow.addWidget(self.check_updates_button)
        urow.addWidget(self.open_website_button)
        urow.addStretch()
        ul.addLayout(urow)
        ul.addStretch()
        left.addWidget(updates, 1)

        # ---------------- INSTALL & DATA (fills the right column) ----------------
        data = _card()
        dl = QVBoxLayout(data)
        dl.setContentsMargins(16, 14, 16, 14)
        dl.setSpacing(8)

        dt = QLabel("INSTALL & DATA")
        dt.setObjectName("SettingsPanelTitle")
        dl.addWidget(dt)

        dh = QLabel("Where DedSecLab is installed and where it keeps your local settings.")
        dh.setObjectName("StatusLine")
        dh.setWordWrap(True)
        dl.addWidget(dh)

        self.install_path = self._path_block(dl, "INSTALL FOLDER", str(app_dir()))
        self.appdata_path = self._path_block(dl, "APP DATA", str(APP_DIR))
        self.config_path = self._path_block(dl, "CONFIG FILE", str(CONFIG_FILE))

        drow = QHBoxLayout()
        drow.setSpacing(8)
        self.open_install_button = QPushButton("Open Install Folder")
        self.open_install_button.setObjectName("SettingsSecondaryButton")
        self.open_install_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.open_install_button.clicked.connect(self.open_install_folder)

        self.open_folder_button = QPushButton("Open App Data")
        self.open_folder_button.setObjectName("SettingsSecondaryButton")
        self.open_folder_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.open_folder_button.clicked.connect(self.open_appdata)

        drow.addWidget(self.open_install_button, 1)
        drow.addWidget(self.open_folder_button, 1)
        dl.addLayout(drow)
        dl.addStretch()

        dl.addWidget(CyberDivider())
        rrow = QHBoxLayout()
        reset_hint = QLabel("Clears local preferences only. Your account is kept.")
        reset_hint.setObjectName("StatusLine")
        reset_hint.setWordWrap(True)
        self.reset_button = QPushButton("Reset Local Settings")
        self.reset_button.setObjectName("SettingsDangerButton")
        self.reset_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.reset_button.clicked.connect(self.reset_settings)
        rrow.addWidget(reset_hint, 1)
        rrow.addWidget(self.reset_button)
        dl.addLayout(rrow)

        about = _card()
        about.setObjectName("SettingsSidePanel")
        al = QVBoxLayout(about)
        al.setContentsMargins(16, 14, 16, 14)
        al.setSpacing(8)

        at = QLabel("ABOUT")
        at.setObjectName("SettingsPanelTitle")
        al.addWidget(at)

        app_name = QLabel("DedSec-Lab Client")
        app_name.setObjectName("SettingsAppName")
        app_name.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.about_version = QLabel(f"v{APP_VERSION}")
        self.about_version.setObjectName("SettingsVersion")
        self.about_version.setAlignment(Qt.AlignmentFlag.AlignCenter)

        tag = QLabel("Secure infrastructure access")
        tag.setObjectName("StatusLine")
        tag.setAlignment(Qt.AlignmentFlag.AlignCenter)

        al.addWidget(app_name)
        al.addWidget(self.about_version)
        al.addWidget(tag)
        al.addWidget(CyberDivider())

        st = QLabel("STATUS")
        st.setObjectName("SettingsPanelTitle")
        al.addWidget(st)

        grid = QGridLayout()
        grid.setSpacing(8)

        self.config_file_status = self._chip("Config file", "OK")
        self.vpn_status = self._chip("VPN config", "-")
        self.api_status = self._chip("API", "-")
        self.tls_status = self._chip("Lab TLS", "-")

        grid.addWidget(self.config_file_status, 0, 0)
        grid.addWidget(self.vpn_status, 0, 1)
        grid.addWidget(self.api_status, 1, 0)
        grid.addWidget(self.tls_status, 1, 1)
        al.addLayout(grid)

        self.save_button = QPushButton("Save Settings")
        self.save_button.setObjectName("SettingsPrimaryButton")
        self.save_button.setMinimumHeight(40)
        self.save_button.clicked.connect(self.save_settings)
        al.addWidget(self.save_button)

        right.addWidget(about)
        right.addWidget(data, 1)

        cols.addLayout(left, 1)
        cols.addLayout(right, 1)
        root.addLayout(cols, 1)

    def _path_block(self, layout, title: str, path: str) -> QLabel:
        """Small caption + selectable path line (theme styles via objectNames)."""
        cap = QLabel(title)
        cap.setObjectName("SettingsSmallTitle")
        val = QLabel(path)
        val.setObjectName("SettingsPathText")
        val.setWordWrap(True)
        val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        val.setToolTip(path)
        layout.addWidget(cap)
        layout.addWidget(val)
        return val

    def _chip(self, title: str, value: str) -> QFrame:
        f = QFrame()
        f.setObjectName("SettingsStatusCard")
        lay = QVBoxLayout(f)
        lay.setContentsMargins(10, 8, 10, 8)
        lay.setSpacing(2)
        t = QLabel(title)
        t.setObjectName("SettingsSmallTitle")
        v = QLabel(value)
        v.setObjectName("SettingsStatusValue")
        lay.addWidget(t)
        lay.addWidget(v)
        f._value = v
        return f

    def _set_chip(self, chip: QFrame, value: str):
        chip._value.setText(str(value))

    # ---------------- theme helpers ----------------
    def on_theme_changed(self):
        """Keep the picker highlight on the theme that is actually applied."""
        try:
            from ui.styles import requested_theme
            self._sync_theme_buttons(requested_theme())
        except Exception:
            pass

    def _sync_theme_buttons(self, theme):
        theme = str(theme or "default").lower()
        if theme not in THEMES:
            theme = "default"
        btn = self.theme_buttons.get(theme)
        if btn is not None and not btn.isChecked():
            self.theme_group.blockSignals(True)
            btn.setChecked(True)
            self.theme_group.blockSignals(False)
        self._update_theme_status(theme)

    def _update_theme_status(self, theme):
        theme = resolve_theme(theme)
        labels = dict(THEME_LABELS)
        labels["default"] = "Default (original look)"
        self.theme_status.setText(f"Active: {labels.get(theme, theme.title())}")

    def _on_theme_clicked(self, button):
        key = button.property("themeKey") or "default"
        if getattr(self, "_theme_busy", False):
            return
        self._theme_busy = True
        labels = dict(THEME_LABELS) if isinstance(THEME_LABELS, dict) else {}
        self.theme_status.setText(f"Switching to {labels.get(key, str(key).title())}...")
        for b in self.theme_buttons.values():
            b.setEnabled(False)
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        # Big centred "Applying..." banner so it's obvious the switch is happening.
        win = self.window()
        toast = QLabel(f"Applying {labels.get(key, str(key).title())} theme...", win)
        toast.setAlignment(Qt.AlignmentFlag.AlignCenter)
        toast.setStyleSheet(
            "background: rgba(5,12,18,235); color: #00e5ff; border: 1px solid #00b8d4;"
            "border-radius: 12px; padding: 18px 34px; font-size: 16px; font-weight: 800;"
        )
        toast.adjustSize()
        toast.move((win.width() - toast.width()) // 2, (win.height() - toast.height()) // 2)
        toast.show()
        toast.raise_()
        toast.repaint()
        self.theme_status.repaint()
        def _go():
            try:
                self._set_theme(key, persist=True)
            finally:
                try:
                    toast.deleteLater()
                except RuntimeError:
                    pass
                QApplication.restoreOverrideCursor()
                for b in self.theme_buttons.values():
                    b.setEnabled(True)
                self._theme_busy = False
        # Let the "Switching..." text paint before the heavy restyle runs.
        QTimer.singleShot(30, _go)

    def _set_theme(self, theme, persist=True):
        app = QApplication.instance()
        eff = apply_theme(app, theme)
        if persist:
            self.app_window.config["theme"] = theme
            ConfigManager.save(self.app_window.config)
        if hasattr(self.app_window, "refresh_theme"):
            self.app_window.refresh_theme()
        self._sync_theme_buttons(theme)
        self.status_badge.setText(f"● Theme: {eff.title()}")
        try:
            self.app_window.add_log(f"Theme set to {theme} ({eff}).")
        except Exception:
            pass

    def _apply_click_fx(self, on: bool):
        try:
            from ui.fx import set_click_fx_enabled
            set_click_fx_enabled(bool(on))
        except Exception:
            pass
        self.app_window.config["click_fx"] = bool(on)
        try:
            ConfigManager.save(self.app_window.config)
        except Exception:
            pass

    def load_config(self):
        config = self.app_window.config
        self.server_input.setText(config.get("server_url", "https://YOUR_LAB_VPN_IP:8443"))
        self.username_input.setText(config.get("username", ""))
        self.auto_connect.setChecked(config.get("auto_connect", False))
        self.save_username.setChecked(config.get("save_username", True))
        self.notifications.setChecked(config.get("notifications", True))
        self.animations.setChecked(config.get("animations", True))
        self.splash_enabled.setChecked(config.get("splash_enabled", True))
        self.click_fx.blockSignals(True)
        self.click_fx.setChecked(config.get("click_fx", True))
        self.click_fx.blockSignals(False)
        self._sync_theme_buttons(config.get("theme", "default"))
        self._set_chip(self.config_file_status, "OK")
        self._set_chip(self.vpn_status, "OK" if config.get("ovpn_config", "") else "Missing")
        try:
            from core.tls import lab_ca_status
            ok, msg = lab_ca_status()
            self._set_chip(self.tls_status, "OK" if ok else "Missing CA")
            self.tls_status.setToolTip(msg)
        except Exception:
            self._set_chip(self.tls_status, "?")
        self.config_path.setText(str(CONFIG_FILE))
        self.install_path.setText(str(app_dir()))
        self.appdata_path.setText(str(APP_DIR))
        self.version_label.setText(f"Installed version  ·  {APP_VERSION}")
        self.about_version.setText(f"v{APP_VERSION}")

    def test_connection(self):
        self.status_badge.setText("● Testing...")
        try:
            status = self.app_window.server.get_status()
            online = bool(status.get("online"))
            if online:
                self.connection_state.setText("Status: Connected")
                self._set_chip(self.api_status, "OK")
                self.status_badge.setText("● API Connected")
                self.app_window.add_log("Settings connection test successful.")
            else:
                self.connection_state.setText("Status: Offline")
                self._set_chip(self.api_status, "Offline")
                self.status_badge.setText("● API Offline")
                self.app_window.add_log("Settings connection test failed.")
        except Exception as error:
            self.connection_state.setText("Status: Error")
            self._set_chip(self.api_status, "Error")
            self.status_badge.setText("● Error")
            self.app_window.add_log(f"Settings connection test error: {error}")

    def check_for_updates(self):
        server_url = self.server_input.text().strip()
        if not server_url:
            server_url = self.app_window.config.get("server_url", "https://YOUR_LAB_VPN_IP:8443")
        self.status_badge.setText("● Checking updates...")
        status, payload = check_for_update(server_url)
        if status == "error":
            self.status_badge.setText("● Update check failed")
            QMessageBox.warning(self, "Updates", str(payload))
            self.app_window.add_log(f"Update check error: {payload}")
            return
        remote = payload.get("version", "?")
        notes = payload.get("notes") or ""
        website = payload.get("website_url") or "https://YOUR_WEBSITE_URL.example"
        download_url = payload.get("download_url") or ""
        sha = payload.get("sha256") or ""
        sig = payload.get("signature") or ""
        dl_err = payload.get("download_error") or ""
        if status == "up_to_date":
            self.status_badge.setText("● Up to date")
            QMessageBox.information(
                self, "Updates",
                f"You are up to date.\n\nInstalled: {APP_VERSION}\nLatest: {remote}",
            )
            self.app_window.add_log("Update check: up to date")
            return
        self.status_badge.setText("● Update available")
        extra = (notes + "\n\n") if notes else ""
        if download_url and sha:
            msg = (
                f"A newer version is available.\n\n"
                f"Installed: {APP_VERSION}\n"
                f"Latest: {remote}\n\n"
                f"{extra}"
                f"Download and verify it now? (sha256 required)"
            )
        elif download_url and not sha:
            msg = (
                f"A newer version is listed, but the server did not provide a "
                f"sha256 checksum so this client will refuse to install it.\n\n"
                f"Installed: {APP_VERSION}\n"
                f"Latest: {remote}\n\n"
                f"{extra}"
                f"Open the website instead?"
            )
            download_url = ""
        else:
            why = dl_err or "the file is not on the server yet"
            msg = (
                f"A newer version is listed, but {why}.\n\n"
                f"Installed: {APP_VERSION}\n"
                f"Latest: {remote}\n\n"
                f"{extra}"
                f"Open the website instead?"
            )
        ans = QMessageBox.question(
            self, "Update Available", msg,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        self.app_window.add_log(f"Update available: {remote}")
        if ans != QMessageBox.StandardButton.Yes:
            return
        if download_url:
            dest_dir = app_dir() / "updates"
            dest_dir.mkdir(parents=True, exist_ok=True)
            st, result = download_update(
                download_url, dest_dir=dest_dir, version=remote,
                sha256=sha, signature=sig, server_url=server_url,
            )
            if st != "ok":
                QMessageBox.warning(self, "Update", str(result))
                return
            apply_st, apply_msg = start_apply_and_exit(
                Path(result), app_dir(), sha256=sha, signature=sig,
            )
            if apply_st != "ok":
                QMessageBox.warning(self, "Update", str(apply_msg))
                return
            QApplication.instance().quit()
        else:
            QDesktopServices.openUrl(QUrl(website))

    def open_website(self):
        QDesktopServices.openUrl(QUrl("https://YOUR_WEBSITE_URL.example"))
        self.app_window.add_log("Opened website from settings")

    def save_settings(self):
        server_url = self.server_input.text().strip()
        if server_url and not server_url.startswith(("http://", "https://")):
            QMessageBox.warning(
                self, "Invalid Server URL",
                "Server URL must start with http:// or https://",
            )
            return
        self.app_window.config["server_url"] = server_url
        self.app_window.config["username"] = self.username_input.text().strip()
        self.app_window.config["auto_connect"] = self.auto_connect.isChecked()
        self.app_window.config["save_username"] = self.save_username.isChecked()
        self.app_window.config["notifications"] = self.notifications.isChecked()
        self.app_window.config["animations"] = self.animations.isChecked()
        self.app_window.config["splash_enabled"] = self.splash_enabled.isChecked()
        self.app_window.config["click_fx"] = self.click_fx.isChecked()
        ConfigManager.save(self.app_window.config)
        self._set_chip(self.config_file_status, "OK")
        self._set_chip(
            self.vpn_status,
            "OK" if self.app_window.config.get("ovpn_config", "") else "Missing",
        )
        self.status_badge.setText("● Saved")
        self.app_window.add_log("Settings saved.")
        QMessageBox.information(self, "Saved", "Settings saved successfully.")

    def open_appdata(self):
        APP_DIR.mkdir(parents=True, exist_ok=True)
        webbrowser.open(str(APP_DIR))
        self.status_badge.setText("● App data opened")
        self.app_window.add_log("Opened app data folder from settings.")

    def open_install_folder(self):
        folder = app_dir()
        if not folder.is_dir():
            QMessageBox.warning(self, "Install Folder", f"Folder not found:\n{folder}")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder)))
        self.status_badge.setText("● Install folder opened")
        self.app_window.add_log("Opened install folder from settings.")

    def reset_settings(self):
        confirm = QMessageBox.question(
            self, "Reset Local Settings",
            "Clear local settings (username, VPN path, preferences)?\n\n"
            "Your server account is not deleted.\n\nContinue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return
        self.app_window.config.clear()
        self.app_window.config.update(dict(ConfigManager.DEFAULTS))
        ConfigManager.save(self.app_window.config)
        self._set_theme("default", persist=False)
        self.load_config()
        self.status_badge.setText("● Reset complete")
        self.app_window.add_log("Local settings reset.")
        QMessageBox.information(self, "Reset Complete", "Local settings have been reset.")