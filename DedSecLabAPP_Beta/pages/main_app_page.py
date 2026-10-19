from pathlib import Path
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QIcon, QPixmap, QPainter, QColor, QImage
from PyQt6.QtWidgets import (
    QWidget,
    QHBoxLayout,
    QVBoxLayout,
    QLabel,
    QPushButton,
    QFrame,
    QStackedWidget,
)
from pages.dashboard_page import DashboardPage
from pages.account_page import AccountPage
from pages.vpn_page import VPNPage
from pages.lab_vpn_page import LabVpnPage
from pages.ip_database_page import IPDatabasePage
#from pages.ip_sniffer_page import IPSnifferPage
from pages.terminal_page import TerminalPage
from pages.actions_page import ActionsPage
from pages.logs_page import LogsPage
from pages.networking_page import NetworkingPage
from pages.settings_page import SettingsPage
from pages.about_page import AboutPage


class MainAppPage(QWidget):
    def __init__(self, app_window):
        super().__init__()
        self.app_window = app_window
        self.project_root = Path(__file__).resolve().parents[1]
        self.icons_dir = self.project_root / "assets" / "icons"
        self._wallpaper = QPixmap()
        for wp in (
            self.project_root / "assets" / "site-wallpaper.png",
            Path.cwd() / "assets" / "site-wallpaper.png",
        ):
            if wp.exists():
                pm = QPixmap(str(wp))
                if not pm.isNull():
                    self._wallpaper = pm
                    break
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, False)
        self.setAutoFillBackground(False)
        self.setObjectName("MainAppRoot")

        # =================================================
        # ROOT LAYOUT
        # =================================================
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # =================================================
        # SIDEBAR
        # =================================================
        sidebar = QFrame()
        sidebar.setFixedWidth(232)
        sidebar.setObjectName("Sidebar")
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(14, 18, 14, 18)
        sidebar_layout.setSpacing(10)

        # Logo (matches website white/blue DedSec logo)
        brand = QLabel()
        brand.setObjectName("Brand")
        brand.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.brand_label = brand
        self._brand_light = None
        self.apply_brand_theme(force=True)
        brand.setContentsMargins(0, 4, 0, 4)

        # =================================================
        # NAV BUTTONS
        # =================================================
        self.dashboard_button = self.make_nav_button("Dashboard", "dashboard.png")
        self.account_button = self.make_nav_button("My Account", "account.png")
        self.vpn_button = self.make_nav_button("Xbox", "shield.png")
        self.lab_vpn_button = self.make_nav_button("VPN", "vpn.png")
        self.ip_database_btn = self.make_nav_button("IP Database", "network.png")
        #self.ip_sniffer_btn = self.make_nav_button("IP Sniffer", "network.png")
        self.terminal_button = self.make_nav_button("Terminal", "terminal.png")
        self.actions_button = self.make_nav_button("Changelog", "flash.png")
        self.logs_button = self.make_nav_button("Logs", "logs.png")
        self.networking_button = self.make_nav_button("Networking", "network.png")
        self.settings_button = self.make_nav_button("Settings", "settings.png")
        self.about_button = self.make_nav_button("About", "info.png")

        # =================================================
        # DISCONNECT BUTTON
        # =================================================
        self.disconnect_button = QPushButton("Disconnect")
        self.disconnect_button.setObjectName("DangerButton")
        self.disconnect_button.setMinimumHeight(52)
        self.disconnect_button.setCursor(Qt.CursorShape.PointingHandCursor)
        power_icon = self.icons_dir / "power.png"
        if power_icon.exists():
            self.disconnect_button.setIcon(QIcon(str(power_icon)))
            self.disconnect_button.setIconSize(QSize(18, 18))

        # =================================================
        # SIDEBAR LAYOUT
        # =================================================
        sidebar_layout.addWidget(brand)
        sidebar_layout.addSpacing(15)
        sidebar_layout.addWidget(self.dashboard_button)
        sidebar_layout.addWidget(self.account_button)
        sidebar_layout.addWidget(self.vpn_button)
        sidebar_layout.addWidget(self.lab_vpn_button)
        sidebar_layout.addWidget(self.ip_database_btn)
        #sidebar_layout.addWidget(self.ip_sniffer_btn)
        sidebar_layout.addWidget(self.terminal_button)
        sidebar_layout.addWidget(self.actions_button)
        sidebar_layout.addWidget(self.logs_button)
        sidebar_layout.addWidget(self.networking_button)
        sidebar_layout.addWidget(self.settings_button)
        sidebar_layout.addWidget(self.about_button)
        sidebar_layout.addStretch()
        sidebar_layout.addWidget(self.disconnect_button)

        # =================================================
        # STACKED PAGES
        # =================================================
        self.pages = QStackedWidget()
        # Explicit minimum so one wide page can't squash the sidebar
        self.pages.setMinimumWidth(700)

        self.dashboard_page = DashboardPage(app_window)
        self.account_page = AccountPage(app_window)
        self.vpn_page = VPNPage(app_window)
        self.lab_vpn_page = LabVpnPage(app_window)
        self.ip_database_page = IPDatabasePage(app_window)
        self.terminal_page = TerminalPage(app_window)
        self.actions_page = ActionsPage(app_window)
        self.logs_page = LogsPage(app_window)
        self.networking_page = NetworkingPage(app_window)
        self.settings_page = SettingsPage(app_window)
        self.about_page = AboutPage()

        self.pages.addWidget(self.dashboard_page)
        self.pages.addWidget(self.account_page)
        self.pages.addWidget(self.vpn_page)
        self.pages.addWidget(self.lab_vpn_page)
        self.pages.addWidget(self.ip_database_page)
        #self.ip_sniffer_page = IPSnifferPage(app_window)
        self.pages.addWidget(self.terminal_page)
        self.pages.addWidget(self.actions_page)
        self.pages.addWidget(self.logs_page)
        self.pages.addWidget(self.networking_page)
        self.pages.addWidget(self.settings_page)
        self.pages.addWidget(self.about_page)

        # =================================================
        # NAVIGATION MAP
        # =================================================
        self.nav_items = [
            (self.dashboard_button, self.dashboard_page),
            (self.account_button, self.account_page),
            (self.vpn_button, self.vpn_page),
            (self.lab_vpn_button, self.lab_vpn_page),
            (self.ip_database_btn, self.ip_database_page),
            (self.terminal_button, self.terminal_page),
            (self.actions_button, self.actions_page),
            (self.logs_button, self.logs_page),
            (self.networking_button, self.networking_page),
            (self.settings_button, self.settings_page),
            (self.about_button, self.about_page),
        ]

        for button, page in self.nav_items:
            button.clicked.connect(
                lambda checked=False, p=page: self.show_page(p)
            )

        self.disconnect_button.clicked.connect(self.app_window.disconnect)

        # =================================================
        # ROOT ADD
        # =================================================
        root.addWidget(sidebar, 0)
        root.addWidget(self.pages, 1)
        self.show_page(self.dashboard_page)


    def _load_brand_pixmap(self, light: bool):
        name = "applogo_light.png" if light else "applogo.png"
        logo_path = self.project_root / "assets" / name
        if light and not logo_path.exists():
            logo_path = self.project_root / "assets" / "applogo.png"
        pixmap = QPixmap(str(logo_path)) if logo_path.exists() else QPixmap()
        if pixmap.isNull():
            return pixmap
        # Crop transparent padding so the skull/wordmark fills the slot,
        # then fit inside the ~175px sidebar column (was 220 and clipped).
        crop = getattr(self, "_brand_crop", None)
        if crop is None:
            img = pixmap.toImage()
            min_x, min_y, max_x, max_y = img.width(), img.height(), -1, -1
            step = 2
            for y in range(0, img.height(), step):
                for x in range(0, img.width(), step):
                    if (img.pixel(x, y) >> 24) & 0xFF > 16:
                        if x < min_x:
                            min_x = x
                        if x > max_x:
                            max_x = x
                        if y < min_y:
                            min_y = y
                        if y > max_y:
                            max_y = y
            crop = ()
            if max_x > min_x and max_y > min_y:
                pad = 6
                x0 = max(0, min_x - pad)
                y0 = max(0, min_y - pad)
                x1 = min(img.width(), max_x + pad + step)
                y1 = min(img.height(), max_y + pad + step)
                crop = (x0, y0, x1 - x0, y1 - y0)
            self._brand_crop = crop  # same for both variants (identical layout)
        if crop:
            pixmap = pixmap.copy(*crop)
        return pixmap.scaled(
            150, 120,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )

    def apply_brand_theme(self, force: bool = False):
        """Sidebar logo: white DEDSEC wordmark in dark themes, dark wordmark in light."""
        brand = getattr(self, "brand_label", None)
        if brand is None:
            return
        try:
            from ui.styles import current_theme
            light = current_theme() == "light"
        except Exception:
            light = False
        if not force and light == self._brand_light:
            return
        self._brand_light = light
        cache = self.__dict__.setdefault("_brand_cache", {})
        logo = cache.get(light)
        if logo is None:
            logo = self._load_brand_pixmap(light)
            cache[light] = logo
        if not logo.isNull():
            brand.setPixmap(logo)
            brand.setFixedHeight(logo.height() + 12)
            brand.setMinimumWidth(logo.width())
        else:
            brand.setText("DEDSEC\nLAB")
            brand.setFixedHeight(64)

    def paintEvent(self, event):
        from ui.styles import chrome_colors
        c = chrome_colors()
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(c["app_bg"]))
        if not self._wallpaper.isNull():
            wall = self._wallpaper
            if c.get("wall_color"):
                from ui.styles import themed_wallpaper
                wall = themed_wallpaper(wall)
            img = wall.scaled(
                self.size(),
                Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                Qt.TransformationMode.SmoothTransformation,
            )
            p.drawPixmap((self.width()-img.width())//2, (self.height()-img.height())//2, img)
            # Tint over the wallpaper; light theme uses a strong pale wash so text stays readable.
            p.fillRect(self.rect(), QColor(*c["wallpaper_tint"]))
        super().paintEvent(event)

    def make_nav_button(self, text, icon_name):
        button = QPushButton(text)
        button.setMinimumHeight(52)
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        button.setCheckable(True)
        icon_path = self.icons_dir / icon_name
        if icon_path.exists():
            button.setIcon(QIcon(str(icon_path)))
            button.setIconSize(QSize(30, 30))
        button.setStyleSheet("""
            QPushButton {
                text-align: left;
                padding-left: 18px;
                font-size: 15px;
                font-weight: 700;
                border-radius: 10px;
            }
        """)
        return button

    def show_page(self, page):
        self.pages.setCurrentWidget(page)
        for button, button_page in self.nav_items:
            button.setChecked(button_page == page)

    def refresh(self):
        self.dashboard_page.refresh()
        self.account_page.refresh()
        self.vpn_page.load_config()
        if hasattr(self, "lab_vpn_page"):
            self.lab_vpn_page.load_config()
        self.ip_database_page.refresh()
        self.terminal_page.load_config()
        self.settings_page.load_config()

    def refresh_live(self):
        """Cheap periodic refresh: only the page the user is looking at."""
        cur = self.pages.currentWidget()
        if cur is self.dashboard_page:
            self.dashboard_page.refresh()
        elif cur is self.account_page:
            self.account_page.refresh()

    def add_log(self, message):
        self.logs_page.add_log(message)