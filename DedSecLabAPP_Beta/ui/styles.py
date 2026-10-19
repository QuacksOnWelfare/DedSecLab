"""
DedSec Lab theme system.

The original stylesheet is kept verbatim as the DARK base (the app's native
identity). LIGHT is derived from it with a collision-safe colour remap, so every
widget rule stays in one place and both themes stay structurally identical.

Themes:
    "default" - the app's original DedSec look (the historic dark palette)
    "dark"    - a deeper / blacker distinct dark theme
    "light"   - readable light theme

Public API:
    THEMES, THEME_LABELS
    resolve_theme(name)          -> "dark" | "light"
    build_qss(name)              -> stylesheet string
    build_palette(name)          -> QPalette
    apply_theme(app, name)       -> applies palette + stylesheet, returns effective theme
    apply_styles(app)            -> startup entry point (reads saved preference)
    current_theme() / chrome_colors()
"""
import sys

from PyQt6.QtCore import QEvent, QObject
from PyQt6.QtGui import QColor, QPalette
from PyQt6.QtWidgets import QApplication, QMenu, QWidget

# ---------------------------------------------------------------------------
# Palette themes. Each one is just a dict: the stylesheet, inline widget sheets,
# QPalette, window chrome, menus and the mini VPN window are all generated from
# it by recolouring the Default (original DedSec) colours. To add a theme, add a
# dict here. Keys: label, accent, bg, panel, card (required); text, muted,
# surface_scale (optional; text/muted are otherwise derived from the Default
# colours with their contrast preserved).
# ---------------------------------------------------------------------------
THEME_SPECS = {
    "matrix": {"label": "Matrix", "accent": "#00ff88",
               "bg": "#010503", "panel": "#04120b", "card": "#061a10"},
    "crimson": {"label": "Crimson", "accent": "#ff3b4e",
                "bg": "#070203", "panel": "#160709", "card": "#1d0a0d"},
    "midnight": {"label": "Midnight", "accent": "#a78bfa",
                 "bg": "#04030c", "panel": "#0c0a1f", "card": "#120f2b"},
    "amber": {"label": "Amber", "accent": "#ffb020",
              "bg": "#060402", "panel": "#150e04", "card": "#1c1306"},
    "oled": {"label": "OLED Black", "accent": "#2ee6ff",
             "bg": "#000000", "panel": "#000000", "card": "#0a0a0a",
             "text": "#ffffff", "surface_scale": 0.35, "tint_sat": 0.0},
}

THEMES = ("default", "dark", "light") + tuple(THEME_SPECS)
THEME_LABELS = {
    "default": "Default",
    "dark": "Dark",
    "light": "Light",
}
THEME_LABELS.update({k: v["label"] for k, v in THEME_SPECS.items()})
# Swatch colours for the Settings picker: (background, panel, accent).
THEME_SWATCHES = {
    "default": ("#060606", "#0d1c2c", "#2ee6ff"),
    "dark": ("#010102", "#080c12", "#00e5ff"),
    "light": ("#f3f7fa", "#ffffff", "#00707f"),
}
THEME_SWATCHES.update({k: (v["bg"], v["card"], v["accent"]) for k, v in THEME_SPECS.items()})

_current = {"requested": "default", "effective": "default"}

_BASE_QSS = """
        QMainWindow {
            background-color: transparent;
        }
        QStackedWidget {
            background-color: transparent;
        }
        QWidget {
            background-color: transparent;
            color: #eef6ff;
            font-family: Segoe UI;
            font-size: 14px;
        }
        QWidget#MainAppRoot,
        QStackedWidget#AppPages {
            background-color: transparent;
        }
        QWidget#LoginRoot {
            background-color: transparent;
            background-image: none;
        }
        QWidget#LoginRoot QWidget {
            background-image: none;
        }
        QWidget#LoginRoot QFrame#LoginMainPanel,
        QWidget#LoginRoot QFrame#LoginInnerPanel,
        QWidget#LoginRoot QFrame#LoginSideHud {
            background: rgba(10, 22, 36, 0.82);
            border: 1px solid rgba(46, 230, 255, 0.16);
            border-radius: 16px;
        }
        QFrame#Sidebar QPushButton {
            background: #0d1c2c;
            border: 1px solid rgba(46, 230, 255, 0.16);
            color: #eef6ff;
        }
        QFrame#Sidebar QPushButton:hover,
        QFrame#Sidebar QPushButton:checked,
        QFrame#Sidebar QPushButton[active="true"] {
            background: #102033;
            border: 1px solid #2ee6ff;
            color: #2ee6ff;
        }
        QFrame#Sidebar QPushButton:pressed {
            background: rgba(46, 230, 255, 0.22);
            border: 1px solid #2ee6ff;
            color: #2ee6ff;
            padding-top: 13px;
            padding-bottom: 9px;
        }
        QFrame#Sidebar QPushButton#DangerButton {
            background: #d92b3a;
            border: none;
            color: #ffffff;
            border-radius: 8px;
            font-weight: 800;
        }
        QFrame#Sidebar QPushButton#DangerButton:hover {
            background: #ff3b4e;
            border: none;
            color: #ffffff;
        }
        QFrame#Sidebar QPushButton#DangerButton:pressed {
            background: #a81e2b;
            border: none;
            color: #ffffff;
            padding-top: 13px;
            padding-bottom: 9px;
        }
        QFrame#Sidebar {
            background: #0a1624;
        }
        QFrame#Brand {
            background: transparent;
            min-height: 72px;
            max-height: 140px;
            padding: 10px 8px 2px 8px;
            margin: 0px;
            border: none;
        }
        QFrame#Brand QLabel {
            background: transparent;
            padding: 0px;
            margin: 0px;
        }

        QLabel#Title {
            font-size: 26px;
            font-weight: 900;
            color: #2ee6ff;
        }

        QLabel#Subtitle {
            font-size: 15px;
            color: #7d93a8;
        }

        QLabel#Hint {
            color: #7d93a8;
            font-size: 12px;
        }

        QLabel#PageTitle {
            font-size: 24px;
            font-weight: 800;
            color: #eef6ff;
        }

        QLabel#StatusLine {
            color: #7d93a8;
            font-size: 15px;
        }

        QLabel#Brand {
            font-size: 22px;
            font-weight: 900;
            color: #eef6ff;
            letter-spacing: 2px;
            background: transparent;
            border: none;
            padding: 0px;
            margin: 0px;
            max-width: 160px;
        }

        QLabel#CardTitle {
            color: #7d93a8;
            font-size: 13px;
        }

        QLabel#CardValue {
            color: #ffffff;
            font-size: 25px;
            font-weight: 900;
        }

        QLabel#AboutText {
            font-size: 15px;
            color: #eef6ff;
        }

        QFrame#Sidebar {
            background: #0a1624;
            border-right: 1px solid rgba(46, 230, 255, 0.14);
            padding: 4px 10px 12px 10px;
        }

        QFrame#Card {
            background: rgba(13, 28, 44, 0.96);
            border: 1px solid rgba(46, 230, 255, 0.12);
            border-radius: 14px;
        }

        QPushButton {
            background: rgba(46, 230, 255, 0.06);
            border: 1px solid rgba(46, 230, 255, 0.18);
            padding: 11px;
            border-radius: 10px;
            font-weight: 800;
            text-align: center;
            color: #eef6ff;
        }

        QPushButton:hover {
            background: rgba(46, 230, 255, 0.12);
            border: 1px solid rgba(46, 230, 255, 0.35);
            color: #2ee6ff;
        }

        QPushButton:pressed {
            background: rgba(46, 230, 255, 0.22);
            border: 1px solid rgba(46, 230, 255, 0.45);
            padding-top: 13px;
            padding-bottom: 9px;
        }

        QPushButton:disabled {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.06);
            color: #6a7588;
        }

        QPushButton#DangerButton {
            background: rgba(255, 90, 90, 0.08);
            border: 1px solid rgba(255, 90, 90, 0.22);
            color: #ff8d8d;
            text-align: center;
        }

        QPushButton#DangerButton:hover {
            background: rgba(255, 90, 90, 0.16);
            border: 1px solid rgba(255, 90, 90, 0.40);
        }

        QPushButton#DangerButton:pressed {
            background: rgba(255, 90, 90, 0.28);
            border: 1px solid rgba(255, 90, 90, 0.55);
            padding-top: 13px;
            padding-bottom: 9px;
        }

        QLineEdit {
            background: #0d1c2c;
            border: 1px solid rgba(46, 230, 255, 0.12);
            padding: 9px;
            border-radius: 8px;
            color: #eef6ff;
        }

        QLineEdit:focus {
            border: 1px solid rgba(46, 230, 255, 0.45);
        }

        QCheckBox {
            color: #7d93a8;
        }

        QRadioButton {
            color: #eef6ff;
            spacing: 8px;
            font-weight: 700;
        }
        QRadioButton:hover {
            color: #2ee6ff;
        }
        QRadioButton:checked {
            color: #2ee6ff;
        }
        QRadioButton::indicator {
            width: 14px;
            height: 14px;
            border-radius: 9px;
            border: 2px solid rgba(46, 230, 255, 0.45);
            background: #0d1c2c;
        }
        QRadioButton::indicator:checked {
            border: 2px solid #2ee6ff;
            background: qradialgradient(cx:0.5, cy:0.5, radius:0.5, fx:0.5, fy:0.5,
                stop:0 #2ee6ff, stop:0.5 #2ee6ff, stop:0.6 #0d1c2c, stop:1 #0d1c2c);
        }

        QTextEdit {
            background: rgba(7, 20, 34, 0.42);
            border: 1px solid rgba(46, 230, 255, 0.12);
            border-radius: 10px;
            color: #50ff85;
            font-family: Consolas;
            padding: 8px;
        }

        QTableWidget, QTableView {
            background: rgba(7, 20, 34, 0.38);
            alternate-background-color: rgba(7, 20, 34, 0.22);
            color: #eef6ff;
            gridline-color: rgba(46, 230, 255, 0.10);
            border: 1px solid rgba(46, 230, 255, 0.12);
        }
        QTableWidget::item, QTableView::item {
            background: transparent;
        }
        QHeaderView::section {
            background: rgba(10, 22, 36, 0.88);
            color: #eef6ff;
            border: none;
            padding: 6px;
        }
        QTabWidget::pane {
            background: rgba(13, 28, 44, 0.50);
            border: 1px solid rgba(46, 230, 255, 0.12);
        }

        QScrollBar:vertical {
            background: #0a1624;
            width: 10px;
            margin: 0px;
        }

        QScrollBar::handle:vertical {
            background: rgba(46, 230, 255, 0.20);
            border-radius: 5px;
            min-height: 20px;
        }

        QStatusBar {
            background: rgba(13, 28, 44, 0.95);
            color: #7d93a8;
        }

        /* DASH */
        QLabel#DashCardTitle {
            color: #7d93a8;
            font-size: 12px;
            font-weight: 700;
        }

        QLabel#DashCardValue {
            color: #ffffff;
            font-size: 26px;
            font-weight: 900;
        }

        QLabel#DashCardSub {
            color: #7d93a8;
            font-size: 12px;
        }

        QFrame#HeroPanel,
        QFrame#DashPanel,
        QFrame#DashGraphCard,
        QFrame#StatCard_blue,
        QFrame#StatCard_purple,
        QFrame#StatCard_orange,
        QFrame#StatCard_cyan,
        QFrame#StatCard_green {
            background: rgba(13, 28, 44, 0.96);
            border: 1px solid rgba(46, 230, 255, 0.12);
            border-radius: 12px;
        }

        QLabel#HeroSmall {
            color: #2ee6ff;
            font-size: 13px;
            font-weight: 800;
        }

        QLabel#HeroValue {
            color: #eef6ff;
            font-size: 34px;
            font-weight: 900;
        }

        QLabel#HeroValueGreen {
            color: #50ff85;
            font-size: 34px;
            font-weight: 900;
        }

        QLabel#HeroValueRed {
            color: #ff4d5f;
            font-size: 34px;
            font-weight: 900;
        }

        QLabel#HeroDetail {
            color: #eef6ff;
            font-size: 13px;
        }

        QLabel#StatusPill {
            background: rgba(13, 28, 44, 0.96);
            border: 1px solid rgba(46, 230, 255, 0.12);
            border-radius: 8px;
            padding: 8px 14px;
            color: #eef6ff;
            font-weight: 800;
        }

        QLabel#DashPanelTitle {
            color: #eef6ff;
            font-size: 14px;
            font-weight: 900;
        }

        QLabel#ActivityItem {
            background: #0d1c2c;
            border-left: 3px solid #2ee6ff;
            border-radius: 6px;
            padding: 9px;
            color: #eef6ff;
            font-size: 13px;
        }

        QLabel#TopologyText {
            color: #7d93a8;
            font-family: Consolas;
            font-size: 14px;
            line-height: 150%;
        }

        QLabel#SessionInfo {
            background: #0d1c2c;
            border-bottom: 1px solid rgba(46, 230, 255, 0.10);
            padding: 8px;
            color: #eef6ff;
        }

        QPushButton#DashQuickButton,
        QPushButton#DashButton {
            background: rgba(46, 230, 255, 0.06);
            border: 1px solid rgba(46, 230, 255, 0.18);
            border-radius: 9px;
            padding: 11px;
            font-weight: 800;
            color: #eef6ff;
        }

        QPushButton#DashQuickButton:hover,
        QPushButton#DashButton:hover {
            background: rgba(46, 230, 255, 0.14);
            border: 1px solid rgba(46, 230, 255, 0.40);
            color: #2ee6ff;
        }

        QPushButton#DashQuickButton:pressed,
        QPushButton#DashButton:pressed {
            background: rgba(46, 230, 255, 0.22);
            border: 1px solid rgba(46, 230, 255, 0.50);
            padding-top: 13px;
            padding-bottom: 9px;
        }

        /* ACCOUNT */
        QFrame#AccountHeroPanel,
        QFrame#AccountPanel,
        QFrame#AccountInfoCard_blue,
        QFrame#AccountInfoCard_green,
        QFrame#AccountInfoCard_purple,
        QFrame#AccountInfoCard_orange,
        QFrame#SecurityTile,
        QFrame#AccountMetricCard {
            background: rgba(13, 28, 44, 0.96);
            border: 1px solid rgba(46, 230, 255, 0.12);
            border-radius: 12px;
        }

        QLabel#AccountAvatar {
            background: rgba(46, 230, 255, 0.08);
            border: 2px solid rgba(46, 230, 255, 0.30);
            border-radius: 70px;
            min-width: 140px;
            max-width: 140px;
            min-height: 140px;
            max-height: 140px;
            color: #2ee6ff;
            font-size: 58px;
            font-weight: 900;
        }

        QLabel#AccountName {
            color: #ffffff;
            font-size: 30px;
            font-weight: 900;
        }

        QLabel#RoleBadge {
            background: rgba(184, 108, 255, 0.12);
            border: 1px solid rgba(184, 108, 255, 0.35);
            border-radius: 8px;
            padding: 6px 12px;
            color: #b86cff;
            font-size: 13px;
            font-weight: 900;
        }

        QLabel#AccountLine {
            color: #eef6ff;
            font-size: 14px;
        }

        QLabel#AccountCardTitle {
            color: #7d93a8;
            font-size: 12px;
            font-weight: 700;
        }

        QLabel#AccountCardValue {
            color: #ffffff;
            font-size: 22px;
            font-weight: 900;
        }

        QLabel#AccountCardHint {
            color: #7d93a8;
            font-size: 12px;
        }

        QLabel#AccountPanelTitle {
            color: #eef6ff;
            font-size: 15px;
            font-weight: 900;
        }

        QLabel#AccountBadgeGreen {
            background: rgba(80, 255, 133, 0.10);
            border: 1px solid rgba(80, 255, 133, 0.30);
            border-radius: 10px;
            padding: 12px 18px;
            color: #50ff85;
            font-weight: 900;
        }

        QLabel#AccountBadgePurple {
            background: rgba(184, 108, 255, 0.12);
            border: 1px solid rgba(184, 108, 255, 0.30);
            border-radius: 10px;
            padding: 12px 18px;
            color: #c26cff;
            font-weight: 900;
        }

        QLabel#SecurityTileTitle {
            color: #7d93a8;
            font-size: 13px;
            font-weight: 700;
        }

        QLabel#SecurityTileValue {
            color: #50ff85;
            font-size: 16px;
            font-weight: 900;
        }

        QLabel#SecurityTileHint {
            color: #eef6ff;
            font-size: 12px;
        }

        QLabel#AccountInfoLine {
            background: #0d1c2c;
            border: 1px solid rgba(46, 230, 255, 0.10);
            border-radius: 8px;
            padding: 12px;
            color: #eef6ff;
        }

        QPushButton#AccountPrimaryButton {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2ee6ff, stop:1 #1bb8d4);
            border: none;
            border-radius: 9px;
            padding: 12px;
            font-weight: 900;
            color: #0a1624;
        }

        QPushButton#AccountPrimaryButton:hover {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #5af0ff, stop:1 #2ee6ff);
        }

        QPushButton#AccountPrimaryButton:pressed {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1bb8d4, stop:1 #0e7a90);
            border: none;
            padding-top: 14px;
            padding-bottom: 10px;
        }

        /* VPN */
        QFrame#VPNPanel,
        QFrame#VPNInfoCard_blue,
        QFrame#VPNInfoCard_green {
            background: rgba(13, 28, 44, 0.96);
            border: 1px solid rgba(46, 230, 255, 0.12);
            border-radius: 12px;
        }
        QFrame#VPNHeroPanel {
            background: rgba(13, 28, 44, 0.50);
            border: 1px solid rgba(46, 230, 255, 0.12);
            border-radius: 12px;
        }
        QTextEdit#VPNConfigText {
            background: rgba(7, 20, 34, 0.38);
            border: 1px solid rgba(46, 230, 255, 0.12);
            border-radius: 8px;
            color: #50ff85;
        }

        QLabel#VPNOrb {
            background: rgba(80, 255, 133, 0.10);
            border: 2px solid rgba(80, 255, 133, 0.35);
            border-radius: 60px;
            min-width: 120px;
            max-width: 120px;
            min-height: 120px;
            max-height: 120px;
            color: #50ff85;
            font-size: 48px;
            font-weight: 900;
        }

        QLabel#VPNHeroSmall {
            color: #2ee6ff;
            font-size: 13px;
            font-weight: 900;
        }

        QLabel#VPNHeroValue,
        QLabel#VPNHeroValueConnected {
            color: #50ff85;
            font-size: 34px;
            font-weight: 900;
        }

        QLabel#VPNHeroValueDisconnected {
            color: #ff4d5f;
            font-size: 34px;
            font-weight: 900;
        }

        QLabel#VPNLocationValue {
            color: #ffffff;
            font-size: 26px;
            font-weight: 900;
        }

        QLabel#VPNHeroDetail {
            color: #eef6ff;
            font-size: 13px;
        }

        QLabel#VPNMapText,
        QLabel#VPNMonoText {
            color: #2ee6ff;
            font-family: Consolas;
            font-size: 13px;
            background: #0d1c2c;
            border: 1px solid rgba(46, 230, 255, 0.12);
            border-radius: 8px;
            padding: 14px;
        }

        QLabel#VPNCardTitle {
            color: #7d93a8;
            font-size: 12px;
            font-weight: 700;
        }

        QLabel#VPNCardValue {
            color: #ffffff;
            font-size: 20px;
            font-weight: 900;
        }

        QLabel#VPNCardHint {
            color: #7d93a8;
            font-size: 12px;
        }

        QLabel#VPNPanelTitle {
            color: #eef6ff;
            font-size: 14px;
            font-weight: 900;
        }

        QLabel#VPNConfigText {
            background: #0d1c2c;
            border: 1px solid rgba(46, 230, 255, 0.12);
            border-radius: 8px;
            padding: 10px;
            color: #eef6ff;
        }

        QPushButton#VPNTopButton {
            background: rgba(46, 230, 255, 0.06);
            border: 1px solid rgba(46, 230, 255, 0.18);
            border-radius: 9px;
            padding: 11px 18px;
            color: #eef6ff;
            font-weight: 900;
        }

        QPushButton#VPNTopButton:hover {
            background: rgba(46, 230, 255, 0.14);
            border: 1px solid rgba(46, 230, 255, 0.40);
            color: #2ee6ff;
        }

        QPushButton#VPNTopButton:pressed {
            background: rgba(46, 230, 255, 0.22);
            border: 1px solid rgba(46, 230, 255, 0.50);
            padding-top: 13px;
            padding-bottom: 9px;
        }

        QPushButton#VPNTopButtonGreen {
            background: rgba(80, 255, 133, 0.10);
            border: 1px solid rgba(80, 255, 133, 0.30);
            border-radius: 9px;
            padding: 11px 18px;
            color: #50ff85;
            font-weight: 900;
        }

        QPushButton#VPNTopButtonGreen:hover {
            background: rgba(80, 255, 133, 0.18);
        }

        QPushButton#VPNTopButtonGreen:pressed {
            background: rgba(80, 255, 133, 0.28);
            border: 1px solid rgba(80, 255, 133, 0.50);
            padding-top: 13px;
            padding-bottom: 9px;
        }

        QPushButton#VPNConnectButton {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #50ff85, stop:1 #2ecc71);
            border: none;
            border-radius: 9px;
            padding: 13px;
            color: #0a1624;
            font-weight: 900;
        }

        QPushButton#VPNConnectButton:hover {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #6dff9a, stop:1 #50ff85);
        }

        QPushButton#VPNConnectButton:pressed {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2ecc71, stop:1 #1e9a4f);
            border: none;
            padding-top: 15px;
            padding-bottom: 11px;
        }

        QPushButton#VPNDisconnectButton {
            background: rgba(46, 230, 255, 0.06);
            border: 1px solid rgba(46, 230, 255, 0.25);
            border-radius: 9px;
            padding: 13px;
            color: #2ee6ff;
            font-weight: 900;
        }

        QPushButton#VPNDisconnectButton:hover {
            background: rgba(46, 230, 255, 0.14);
        }

        QPushButton#VPNDisconnectButton:pressed {
            background: rgba(46, 230, 255, 0.22);
            border: 1px solid rgba(46, 230, 255, 0.45);
            padding-top: 15px;
            padding-bottom: 11px;
        }

        QPushButton#VPNConnectButton:disabled,
        QPushButton#VPNDisconnectButton:disabled {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.06);
            color: #6a7588;
        }

        /* ACTIONS */
        QFrame#ActionsHeroPanel {
            background: qlineargradient(
                x1:0, y1:0, x2:1, y2:1,
                stop:0 rgba(16, 32, 51, 0.95), stop:1 rgba(25, 35, 50, 0.9)
            );
            border: 1px solid rgba(46, 230, 255, 0.14);
            border-radius: 16px;
        }

        QLabel#ActionsHeroState {
            font-size: 28px;
            font-weight: 900;
            color: #eef6ff;
        }

        QLabel#ActionsHeroDetail {
            color: #7d93a8;
            font-size: 13px;
        }

        QLabel#ActionsLiveBadge {
            background: rgba(80, 255, 133, 0.10);
            border: 1px solid rgba(80, 255, 133, 0.30);
            border-radius: 10px;
            padding: 10px 16px;
            color: #50ff85;
            font-weight: 900;
        }

        QLabel#ActionsSectionTitle,
        QLabel#ActionsPanelTitle {
            color: #eef6ff;
            font-size: 14px;
            font-weight: 900;
        }

        QFrame#ActionCard_blue,
        QFrame#ActionCard_green,
        QFrame#ActionCard_orange,
        QFrame#ActionCard_red,
        QFrame#ActionCard_cyan,
        QFrame#ActionCard_purple,
        QFrame#ActionsRow {
            background: rgba(13, 28, 44, 0.96);
            border: 1px solid rgba(46, 230, 255, 0.12);
            border-radius: 12px;
        }
        QFrame#ActionsPanel {
            background: rgba(13, 28, 44, 0.48);
            border: 1px solid rgba(46, 230, 255, 0.12);
            border-radius: 12px;
        }

        QLabel#ActionIcon_blue,
        QLabel#ActionIcon_green,
        QLabel#ActionIcon_orange,
        QLabel#ActionIcon_red,
        QLabel#ActionIcon_cyan,
        QLabel#ActionIcon_purple {
            font-size: 32px;
            font-weight: 900;
        }

        QLabel#ActionIcon_blue   { color: #2ee6ff; }
        QLabel#ActionIcon_green  { color: #50ff85; }
        QLabel#ActionIcon_orange { color: #ffcc33; }
        QLabel#ActionIcon_red    { color: #ff4d5f; }
        QLabel#ActionIcon_cyan   { color: #00e5ff; }
        QLabel#ActionIcon_purple { color: #b86cff; }

        QLabel#ActionCardTitle {
            color: #ffffff;
            font-size: 17px;
            font-weight: 900;
        }

        QLabel#ActionCardDesc {
            color: #7d93a8;
            font-size: 13px;
        }

        QPushButton#ActionButton_blue,
        QPushButton#ActionButton_green,
        QPushButton#ActionButton_orange,
        QPushButton#ActionButton_red,
        QPushButton#ActionButton_cyan,
        QPushButton#ActionButton_purple {
            background: transparent;
            border-top: 1px solid rgba(46, 230, 255, 0.10);
            border-radius: 0px;
            color: #2ee6ff;
            padding: 10px;
            font-weight: 900;
        }

        QPushButton#ActionButton_green  { color: #50ff85; }
        QPushButton#ActionButton_orange { color: #ffcc33; }
        QPushButton#ActionButton_red    { color: #ff4d5f; }
        QPushButton#ActionButton_cyan   { color: #00e5ff; }
        QPushButton#ActionButton_purple { color: #b86cff; }

        QPushButton#ActionButton_blue:hover,
        QPushButton#ActionButton_green:hover,
        QPushButton#ActionButton_orange:hover,
        QPushButton#ActionButton_red:hover,
        QPushButton#ActionButton_cyan:hover,
        QPushButton#ActionButton_purple:hover {
            background: rgba(46, 230, 255, 0.06);
        }

        QPushButton#ActionButton_blue:pressed,
        QPushButton#ActionButton_green:pressed,
        QPushButton#ActionButton_orange:pressed,
        QPushButton#ActionButton_red:pressed,
        QPushButton#ActionButton_cyan:pressed,
        QPushButton#ActionButton_purple:pressed {
            background: rgba(46, 230, 255, 0.14);
            padding-top: 12px;
            padding-bottom: 8px;
        }

        QLabel#ActionsStatusLine,
        QLabel#ActionsRecentLine,
        QLabel#ActionsSafeText {
            background: #0d1c2c;
            border: 1px solid rgba(46, 230, 255, 0.10);
            border-radius: 8px;
            padding: 9px;
            color: #eef6ff;
        }

        QLabel#ActionsSafeText {
            color: #50ff85;
            line-height: 150%;
        }

        QLabel#ActionsRowTitle {
            color: #ffffff;
            font-size: 14px;
            font-weight: 900;
        }

        QLabel#ActionsRowDesc {
            color: #7d93a8;
            font-size: 12px;
        }

        QPushButton#ActionsSmallButton {
            background: rgba(46, 230, 255, 0.06);
            border: 1px solid rgba(46, 230, 255, 0.18);
            border-radius: 8px;
            padding: 8px 14px;
            color: #eef6ff;
        }

        QPushButton#ActionsSmallButton:hover {
            background: rgba(46, 230, 255, 0.14);
            border: 1px solid rgba(46, 230, 255, 0.40);
            color: #2ee6ff;
        }

        QPushButton#ActionsSmallButton:pressed {
            background: rgba(46, 230, 255, 0.22);
            border: 1px solid rgba(46, 230, 255, 0.50);
            padding-top: 10px;
            padding-bottom: 6px;
        }

        /* LOGS */
        QFrame#LogsHeroPanel {
            background: qlineargradient(
                x1:0, y1:0, x2:1, y2:1,
                stop:0 rgba(16, 32, 51, 0.95), stop:1 rgba(25, 35, 50, 0.9)
            );
            border: 1px solid rgba(46, 230, 255, 0.14);
            border-radius: 16px;
        }

        QLabel#LogsHeroState {
            font-size: 28px;
            font-weight: 900;
            color: #eef6ff;
        }

        QLabel#LogsHeroDetail {
            color: #7d93a8;
            font-size: 13px;
        }

        QLabel#LogsLiveBadge {
            background: rgba(80, 255, 133, 0.10);
            border: 1px solid rgba(80, 255, 133, 0.30);
            border-radius: 10px;
            padding: 10px 16px;
            color: #50ff85;
            font-weight: 900;
        }

        QFrame#LogsConsolePanel,
        QFrame#LogsSidePanel,
        QFrame#LogStatCard {
            background: rgba(13, 28, 44, 0.96);
            border: 1px solid rgba(46, 230, 255, 0.12);
            border-radius: 12px;
        }

        QTextEdit#LogsTextConsole {
            background: #071422;
            color: #50ff85;
            border: 1px solid rgba(46, 230, 255, 0.12);
            border-radius: 9px;
            padding: 12px;
            font-family: Consolas;
            font-size: 13px;
        }

        QLabel#LogsSideTitle {
            color: #eef6ff;
            font-size: 14px;
            font-weight: 900;
        }

        QLabel#LogStatTitle {
            color: #7d93a8;
            font-size: 12px;
            font-weight: 700;
        }

        QLabel#LogStatValue {
            color: #2ee6ff;
            font-size: 26px;
            font-weight: 900;
        }

        QLabel#LogStatHint {
            color: #7d93a8;
            font-size: 12px;
        }

        QLabel#LogsGraphText {
            background: #071422;
            border: 1px solid rgba(46, 230, 255, 0.12);
            border-radius: 8px;
            color: #2ee6ff;
            padding: 12px;
            font-family: Consolas;
            font-size: 13px;
        }

        QLabel#LogsPreviewText {
            background: #0d1c2c;
            border: 1px solid rgba(46, 230, 255, 0.10);
            border-radius: 8px;
            color: #eef6ff;
            padding: 12px;
            font-family: Consolas;
            font-size: 12px;
        }

        QPushButton#LogFilterButton,
        QPushButton#LogToolButton {
            background: rgba(46, 230, 255, 0.06);
            border: 1px solid rgba(46, 230, 255, 0.18);
            border-radius: 8px;
            padding: 9px 13px;
            color: #eef6ff;
            font-weight: 800;
        }

        QPushButton#LogFilterButton:hover,
        QPushButton#LogToolButton:hover {
            background: rgba(46, 230, 255, 0.14);
            border: 1px solid rgba(46, 230, 255, 0.40);
            color: #2ee6ff;
        }

        QPushButton#LogFilterButton:pressed,
        QPushButton#LogToolButton:pressed {
            background: rgba(46, 230, 255, 0.22);
            border: 1px solid rgba(46, 230, 255, 0.50);
            padding-top: 11px;
            padding-bottom: 7px;
        }

        QPushButton#LogPrimaryButton,
        QPushButton#LogDangerButton {
            background: rgba(46, 230, 255, 0.08);
            border: 1px solid rgba(46, 230, 255, 0.30);
            border-radius: 9px;
            padding: 11px 16px;
            color: #2ee6ff;
            font-weight: 900;
        }

        QPushButton#LogPrimaryButton:hover,
        QPushButton#LogDangerButton:hover {
            background: rgba(46, 230, 255, 0.16);
        }

        QPushButton#LogPrimaryButton:pressed,
        QPushButton#LogDangerButton:pressed {
            background: rgba(46, 230, 255, 0.24);
            border: 1px solid rgba(46, 230, 255, 0.50);
            padding-top: 13px;
            padding-bottom: 9px;
        }

        QPushButton#LogSuccessButton {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #50ff85, stop:1 #2ecc71);
            border: none;
            border-radius: 9px;
            padding: 11px 16px;
            color: #0a1624;
            font-weight: 900;
        }

        QPushButton#LogSuccessButton:hover {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #6dff9a, stop:1 #50ff85);
        }

        QPushButton#LogSuccessButton:pressed {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2ecc71, stop:1 #1e9a4f);
            border: none;
            padding-top: 13px;
            padding-bottom: 9px;
        }

        /* SETTINGS */
        QFrame#SettingsHeroPanel {
            background: qlineargradient(
                x1:0, y1:0, x2:1, y2:1,
                stop:0 rgba(16, 32, 51, 0.95), stop:1 rgba(25, 35, 50, 0.9)
            );
            border: 1px solid rgba(46, 230, 255, 0.14);
            border-radius: 16px;
        }

        QLabel#SettingsHeroState {
            font-size: 28px;
            font-weight: 900;
            color: #eef6ff;
        }

        QLabel#SettingsHeroDetail {
            color: #7d93a8;
            font-size: 13px;
        }

        QLabel#SettingsLiveBadge {
            background: rgba(80, 255, 133, 0.10);
            border: 1px solid #50ff85;
            border-radius: 10px;
            padding: 8px 14px;
            color: #50ff85;
            font-weight: 800;
        }

        QFrame#SettingsPanel,
        QFrame#SettingsSidePanel,
        QFrame#SettingsStatusCard {
            background: rgba(13, 28, 44, 0.96);
            border: 1px solid rgba(46, 230, 255, 0.12);
            border-radius: 12px;
        }

        QLabel#SettingsPanelTitle {
            color: #eef6ff;
            font-size: 14px;
            font-weight: 900;
        }

        QLabel#SettingsPathText,
        QLabel#SettingsConnectionState {
            background: #0d1c2c;
            border: 1px solid rgba(46, 230, 255, 0.10);
            border-radius: 8px;
            padding: 10px;
            color: #eef6ff;
        }

        QLabel#SettingsLogo {
            background: rgba(46, 230, 255, 0.08);
            border: 2px solid rgba(46, 230, 255, 0.30);
            border-radius: 55px;
            min-width: 110px;
            max-width: 110px;
            min-height: 110px;
            max-height: 110px;
            color: #2ee6ff;
            font-size: 48px;
            font-weight: 900;
        }

        QLabel#SettingsAppName {
            color: #ffffff;
            font-size: 20px;
            font-weight: 900;
        }

        QLabel#SettingsVersion {
            color: #7d93a8;
            font-size: 13px;
        }

        QLabel#SettingsSmallTitle {
            color: #7d93a8;
            font-size: 12px;
            font-weight: 700;
        }

        QLabel#SettingsStatusValue {
            color: #50ff85;
            font-size: 18px;
            font-weight: 900;
        }

        QPushButton#SettingsPrimaryButton,
        QPushButton#SettingsDangerButton {
            background: rgba(46, 230, 255, 0.08);
            border: 1px solid rgba(46, 230, 255, 0.30);
            border-radius: 9px;
            padding: 13px;
            color: #2ee6ff;
            font-weight: 900;
        }

        QPushButton#SettingsPrimaryButton:hover,
        QPushButton#SettingsDangerButton:hover {
            background: rgba(46, 230, 255, 0.16);
        }

        QPushButton#SettingsPrimaryButton:pressed,
        QPushButton#SettingsDangerButton:pressed {
            background: rgba(46, 230, 255, 0.24);
            border: 1px solid rgba(46, 230, 255, 0.50);
            padding-top: 15px;
            padding-bottom: 11px;
        }

        QPushButton#SettingsSecondaryButton {
            background: rgba(46, 230, 255, 0.06);
            border: 1px solid rgba(46, 230, 255, 0.18);
            border-radius: 9px;
            padding: 11px;
            color: #eef6ff;
            font-weight: 900;
        }

        QPushButton#SettingsSecondaryButton:hover {
            background: rgba(46, 230, 255, 0.12);
            border: 1px solid rgba(46, 230, 255, 0.35);
            color: #2ee6ff;
        }

        QPushButton#SettingsSecondaryButton:pressed {
            background: rgba(46, 230, 255, 0.22);
            border: 1px solid rgba(46, 230, 255, 0.50);
            padding-top: 13px;
            padding-bottom: 9px;
        }

        /* TERMINAL */
        QFrame#TerminalSidePanel,
        QFrame#TerminalHeroPanel {
            background: rgba(13, 28, 44, 0.96);
            border: 1px solid rgba(46, 230, 255, 0.12);
            border-radius: 16px;
        }
        QFrame#TerminalPanel {
            background: rgba(13, 28, 44, 0.55);
            border: 1px solid rgba(46, 230, 255, 0.12);
            border-radius: 16px;
        }

        QFrame#TerminalHeroPanel {
            background: qlineargradient(
                x1:0, y1:0, x2:1, y2:1,
                stop:0 rgba(16, 32, 51, 0.95), stop:1 rgba(25, 35, 50, 0.9)
            );
        }

        QTextEdit#TerminalOutput {
            background: rgba(7, 20, 34, 0.42);
            border: 1px solid rgba(46, 230, 255, 0.12);
            border-radius: 12px;
            color: #50ff85;
            font-family: Consolas;
            font-size: 13px;
            padding: 12px;
        }

        QLineEdit#TerminalInput {
            background: #0d1c2c;
            border: 1px solid rgba(46, 230, 255, 0.12);
            border-radius: 10px;
            padding: 11px;
            color: white;
            font-family: Consolas;
        }

        QLineEdit#TerminalInput:focus {
            border: 1px solid rgba(46, 230, 255, 0.45);
        }

        QLabel#TerminalPanelTitle,
        QLabel#TerminalSideTitle {
            font-size: 15px;
            font-weight: 900;
            color: #2ee6ff;
            letter-spacing: 1px;
        }

        QLabel#TerminalHeroState {
            font-size: 28px;
            font-weight: 900;
            color: #eef6ff;
        }

        QLabel#TerminalHeroDetail {
            color: #7d93a8;
            font-size: 13px;
        }

        QLabel#TerminalBadgeGreen {
            background: rgba(80, 255, 133, 0.12);
            border: 1px solid #50ff85;
            border-radius: 10px;
            padding: 8px 14px;
            color: #50ff85;
            font-weight: 800;
        }

        QLabel#TerminalBadgeRed {
            background: rgba(255, 77, 95, 0.12);
            border: 1px solid #ff4d5f;
            border-radius: 10px;
            padding: 8px 14px;
            color: #ff4d5f;
            font-weight: 800;
        }

        QLabel#TerminalBadgeOrange {
            background: rgba(255, 204, 51, 0.12);
            border: 1px solid #ffcc33;
            border-radius: 10px;
            padding: 8px 14px;
            color: #ffcc33;
            font-weight: 800;
        }

        QLabel#TerminalInfoPill {
            background: #0d1c2c;
            border: 1px solid rgba(46, 230, 255, 0.12);
            border-radius: 9px;
            padding: 6px 12px;
            color: #cde6ff;
            font-size: 12px;
            font-weight: 700;
        }

        QLabel#TerminalInfoPillGreen {
            background: rgba(80, 255, 133, 0.10);
            border: 1px solid #50ff85;
            border-radius: 9px;
            padding: 6px 12px;
            color: #50ff85;
            font-size: 12px;
            font-weight: 800;
        }

        QLabel#TerminalSideLine {
            color: #cde6ff;
            font-size: 13px;
        }

        QLabel#TerminalMonoText {
            color: #50ff85;
            font-family: Consolas;
            font-size: 12px;
        }

        QLabel#TerminalActivityLine {
            color: #7d93a8;
            font-size: 13px;
        }

        QPushButton#TerminalConnectButton,
        QPushButton#TerminalDisconnectButton {
            background: rgba(46, 230, 255, 0.08);
            border: 1px solid rgba(46, 230, 255, 0.30);
            border-radius: 10px;
            padding: 10px 16px;
            color: #2ee6ff;
            font-weight: 800;
        }

        QPushButton#TerminalConnectButton:hover,
        QPushButton#TerminalDisconnectButton:hover {
            background: rgba(46, 230, 255, 0.16);
        }

        QPushButton#TerminalConnectButton:pressed,
        QPushButton#TerminalDisconnectButton:pressed {
            background: rgba(46, 230, 255, 0.24);
            border: 1px solid rgba(46, 230, 255, 0.50);
            padding-top: 12px;
            padding-bottom: 8px;
        }

        QPushButton#TerminalToolButton {
            background: rgba(46, 230, 255, 0.06);
            border: 1px solid rgba(46, 230, 255, 0.18);
            border-radius: 10px;
            padding: 10px 14px;
            color: #eef6ff;
            font-weight: 700;
        }

        QPushButton#TerminalToolButton:hover {
            background: rgba(46, 230, 255, 0.12);
            color: #2ee6ff;
        }

        QPushButton#TerminalToolButton:pressed {
            background: rgba(46, 230, 255, 0.22);
            border: 1px solid rgba(46, 230, 255, 0.45);
            padding-top: 12px;
            padding-bottom: 8px;
        }

        QPushButton#TerminalConnectButton:disabled,
        QPushButton#TerminalDisconnectButton:disabled,
        QPushButton#TerminalToolButton:disabled {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.06);
            color: #6a7588;
        }

        /* ABOUT */
        QFrame#AboutHeroPanel,
        QFrame#AboutTelemetryPanel,
        QFrame#AboutInfoCard {
            background: rgba(13, 28, 44, 0.96);
            border: 1px solid rgba(46, 230, 255, 0.12);
            border-radius: 16px;
        }

        QFrame#AboutHeroPanel {
            background: qlineargradient(
                x1:0, y1:0, x2:1, y2:1,
                stop:0 rgba(16, 32, 51, 0.95), stop:1 rgba(25, 35, 50, 0.9)
            );
        }

        QLabel#AboutVersionBadge {
            background: rgba(80, 255, 133, 0.10);
            border: 1px solid #50ff85;
            border-radius: 10px;
            padding: 8px 14px;
            color: #50ff85;
            font-weight: 800;
        }

        QLabel#AboutLogo {
            background: transparent;
            color: #2ee6ff;
            font-size: 48px;
            font-weight: 900;
        }

        QLabel#AboutPanelTitle,
        QLabel#AboutCardTitle {
            color: #2ee6ff;
            font-size: 15px;
            font-weight: 900;
        }

        QLabel#AboutHeroState {
            font-size: 28px;
            font-weight: 900;
            color: #eef6ff;
        }

        QLabel#AboutHeroDetail {
            color: #7d93a8;
            font-size: 13px;
        }

        QLabel#AboutRoleStandard {
            background: rgba(80, 255, 133, 0.08);
            border: 1px solid rgba(80, 255, 133, 0.25);
            border-radius: 8px;
            padding: 10px;
            color: #eef6ff;
        }

        QLabel#AboutRoleAdmin {
            background: rgba(184, 108, 255, 0.10);
            border: 1px solid rgba(184, 108, 255, 0.30);
            border-radius: 8px;
            padding: 10px;
            color: #eef6ff;
        }

        /* LOGIN */
        QFrame#LoginBrandPanel,
        QFrame#LoginAccessPanel,
        QFrame#LoginStatusBox {
            background: rgba(13, 28, 44, 0.96);
            border: 1px solid rgba(46, 230, 255, 0.12);
            border-radius: 16px;
        }

        QLabel#LoginLogo,
        QLabel#LoginLogoFallback {
            color: #2ee6ff;
            font-size: 70px;
            font-weight: 900;
        }

        QLabel#LoginMainTitle {
            font-size: 28px;
            font-weight: 800;
            color: #eef6ff;
            letter-spacing: 1px;
        }

        QLabel#LoginSubtitle {
            font-size: 14px;
            color: #7d93a8;
        }

        QLabel#LoginInfoText {
            color: #eef6ff;
            font-size: 14px;
            line-height: 150%;
        }

        QLabel#LoginPanelTitle,
        QLabel#LoginPanelHeader {
            color: #ffffff;
            font-size: 18px;
            font-weight: 900;
        }

        QLabel#LoginPanelHint {
            color: #7d93a8;
            font-size: 12px;
        }

        QLabel#LoginStageTitle {
            color: #2ee6ff;
            font-size: 22px;
            font-weight: 900;
        }

        QLabel#LoginHudTitle {
            font-size: 13px;
            font-weight: 900;
            color: #2ee6ff;
            letter-spacing: 1px;
        }

        QLabel#LoginHudText {
            font-size: 11px;
            color: #7d93a8;
        }

        QLabel#LoginTopBadge {
            padding: 6px 11px;
            font-size: 13px;
        }

        QLabel#LoginMiniStatus {
            padding: 7px 10px;
            font-size: 13px;
        }

        QLabel#LoginRequirement {
            background: rgba(80, 255, 133, 0.08);
            border: 1px solid rgba(80, 255, 133, 0.25);
            border-radius: 8px;
            padding: 9px;
            color: #50ff85;
            font-weight: 800;
        }

        QLabel#LoginVPNStatus,
        QLabel#LoginConfigText {
            background: #0d1c2c;
            border: 1px solid rgba(46, 230, 255, 0.12);
            border-radius: 8px;
            padding: 11px;
            color: #eef6ff;
            font-weight: 800;
        }

        QLineEdit#LoginInput {
            background: #0d1c2c;
            border: 1px solid rgba(46, 230, 255, 0.12);
            border-radius: 10px;
            min-height: 36px;
            padding: 8px 12px;
            color: white;
            font-size: 14px;
        }

        QLineEdit#LoginInput:focus {
            border: 1px solid rgba(46, 230, 255, 0.45);
        }

        QPushButton#LoginPrimaryButton,
        QPushButton#LoginDangerButton {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2ee6ff, stop:1 #1bb8d4);
            border: none;
            border-radius: 10px;
            min-height: 38px;
            padding: 8px 12px;
            color: #0a1624;
            font-weight: 900;
        }

        QPushButton#LoginPrimaryButton:hover,
        QPushButton#LoginDangerButton:hover {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #5af0ff, stop:1 #2ee6ff);
        }

        QPushButton#LoginPrimaryButton:pressed,
        QPushButton#LoginDangerButton:pressed {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1bb8d4, stop:1 #0e7a90);
            border: none;
            padding-top: 10px;
            padding-bottom: 6px;
        }

        QPushButton#LoginPrimaryButton:disabled,
        QPushButton#LoginDangerButton:disabled {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.08);
            color: #6a7588;
        }

        QProgressBar#LoginProgress {
            background: #0d1c2c;
            border: 1px solid rgba(46, 230, 255, 0.12);
            border-radius: 8px;
            min-height: 14px;
            text-align: center;
            color: white;
        }

        QProgressBar#LoginProgress::chunk {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2ee6ff, stop:1 #50ff85);
            border-radius: 8px;
        }
    
    
        QTabBar::tab {
            background: rgba(10, 14, 20, 0.70);
            color: #7d93a8;
            padding: 8px 16px;
            border: 1px solid rgba(46, 230, 255, 0.18);
            border-bottom: none;
            margin-right: 10px;
        }
        QTabBar::tab:selected {
            background: rgba(46, 230, 255, 0.16);
            color: #eef6ff;
            border: 1px solid #2ee6ff;
            border-bottom: none;
            font-weight: 700;
        }
        QTabBar::tab:hover {
            color: #2ee6ff;
        }
        QPushButton:checked, QPushButton[active="true"] {
            background: rgba(46, 230, 255, 0.16);
            border: 1px solid #2ee6ff;
            color: #eef6ff;
        }
    
    
        QCheckBox::indicator, QTableWidget::indicator, QTableView::indicator {
            width: 18px;
            height: 18px;
            border: none;
            background: transparent;
        }
        QCheckBox::indicator:unchecked, QTableWidget::indicator:unchecked, QTableView::indicator:unchecked {
            border: none;
            background: transparent;
            image: url(assets/icons/checkbox-off.png);
        }
        QCheckBox::indicator:checked, QTableWidget::indicator:checked, QTableView::indicator:checked {
            border: none;
            background: transparent;
            image: url(assets/icons/checkbox-on.png);
        }
    """


# ---------------------------------------------------------------------------
# Colour remaps. Applied in two passes via sentinels so a replacement can
# never be re-matched by a later rule (e.g. navy -> white, then white -> text).
# ---------------------------------------------------------------------------

# Dark = deeper / blacker / cooler-cyan than Default (the original look).
_DARK_MAP = {
    "46, 230, 255": "0, 229, 255",      # cooler cyan accent
    "13, 28, 44": "8, 12, 18",          # cards -> near-black
    "7, 20, 34": "4, 8, 14",            # consoles
    "10, 22, 36": "6, 10, 16",          # panels / sidebar
    "16, 32, 51": "8, 14, 22",          # hero stop 1
    "25, 35, 50": "10, 16, 24",         # hero stop 2
    "10, 14, 20": "4, 6, 10",           # tabs
    "#0a1624": "#05070c",
    "#060606": "#010102",
    "#0d1c2c": "#080c12",
    "#071422": "#04080e",
    "#102033": "#0a1018",
    "#2ee6ff": "#00e5ff",
    "#5af0ff": "#33eeff",
    "#1bb8d4": "#00b8d4",
    "#00e5ff": "#00e5ff",
    "#55c7ff": "#00c2ff",
}

_LIGHT_MAP = {
    # rgb triplets used inside rgba(...)
    "46, 230, 255": "0, 112, 127",     # cyan accent
    "13, 28, 44": "255, 255, 255",      # card surface
    "7, 20, 34": "233, 238, 245",       # console / table surface
    "10, 22, 36": "248, 250, 253",      # login / header panels
    "16, 32, 51": "240, 244, 249",      # hero gradient stop 1
    "25, 35, 50": "228, 235, 244",      # hero gradient stop 2
    "10, 14, 20": "232, 237, 244",      # tab background
    "80, 255, 133": "17, 115, 58",      # green
    "184, 108, 255": "109, 40, 217",    # purple
    "255, 77, 95": "190, 18, 60",       # red
    "255, 90, 90": "185, 28, 28",       # red (danger)
    "255, 204, 51": "161, 98, 7",       # amber
    "255, 255, 255": "15, 23, 42",      # white overlays -> subtle dark overlays
    # solid hex colours
    "#0a1624": "#eef2f7",   # app background / text-on-accent
    "#060606": "#f5f7fa",
    "#0d1c2c": "#ffffff",   # inputs / pills
    "#071422": "#f1f5f9",   # consoles
    "#102033": "#e2e8f0",   # sidebar hover
    "#eef6ff": "#0f172a",   # primary text
    "#e8f0ff": "#0f172a",
    "#ffffff": "#0b1220",   # emphasised values
    "#cde6ff": "#1e293b",
    "#7d93a8": "#475569",   # muted text
    "#6a7588": "#6b7c8c",   # disabled text (visible, ~4.3:1)
    "#2ee6ff": "#00707f",   # accent
    "#5af0ff": "#00707f",
    "#1bb8d4": "#155e75",
    "#00e5ff": "#00707f",
    "#55c7ff": "#0369a1",
    "#50ff85": "#11733a",   # green
    "#6dff9a": "#11733a",
    "#2ecc71": "#166534",
    "#b86cff": "#6d28d9",   # purple
    "#c26cff": "#6d28d9",
    "#ff4d5f": "#be123c",   # red
    "#ff6b7a": "#be123c",
    "#ff8d8d": "#b91c1c",
    "#ffcc33": "#a16207",   # amber
    "#ff9900": "#c2410c",
    "#0e7a90": "#0a5a6a",   # pressed cyan primary shade
    "#1e9a4f": "#145c32",   # pressed green shade
    "#a81e2b": "#8f1824",   # pressed solid red
    "white;": "#0b1220;",   # 'color: white;' in a few inputs
    # extra colours used by per-widget inline styles (pages, wizard, VPN gate)
    "85, 199, 255": "3, 105, 161",
    "#8a96aa": "#475569",
    "#9aa8bc": "#475569",
    "#b8c4d4": "#334155",
    "#d0d8e8": "#1e293b",
    "#0a0a0c": "#f5f7fa",
    "#0b0b0e": "#f1f5f9",
    "#12141a": "#ffffff",
    "#101218": "#eef2f7",
    "#1e222a": "#e2e8f0",
    "#5a6578": "#6b7c8c",
    "#3aa8e0": "#0369a1",
    "#3a4a5e": "#cbd5e1",
    # contrast sweep: bright dark-theme text colours that had no light mapping
    "#ff6b6b": "#b42334", "#ff5555": "#b42334", "#ff6b81": "#b42334",
    "#f07178": "#b42334", "#f3a9b1": "#b42334", "#ff3b3b": "#b42334",
    "#7a8a99": "#5b6f80", "#888888": "#5b6f80", "#aaaaaa": "#5b6f80",
    "#9aa4ae": "#5b6f80", "#9fb0c3": "#5b6f80", "#c8d0dc": "#33475b",
    "#7d98b6": "#4a6178", "#6d89a8": "#4a6178", "#dcecff": "#1e293b",
    "#f5c451": "#8a5a00", "#fde68a": "#8a5a00", "#f59e0b": "#8a5a00",
    "#ff8833": "#b45309",
    "#7dffb0": "#11733a", "#7cff8b": "#11733a", "#62ff00": "#11733a",
    "#2fbf6a": "#11733a", "#93e6b0": "#11733a",
    "#22d3ee": "#00707f", "#8fdfeb": "#00707f", "#9cccf5": "#0369a1",
    "#c084fc": "#6d28d9", "#a78bfa": "#6d28d9", "#d6b4fb": "#6d28d9", "#e9d5ff": "#6d28d9",
    "#163d28": "#e7f7ee", "#1e5436": "#d3f0de", "#12303a": "#e2f5fa", "#1b4452": "#cdebf3",
}


def _remap(text: str, mapping: dict) -> str:
    # Longest keys first so e.g. '#0a1624' is handled before any shorter overlap.
    items = sorted(mapping.items(), key=lambda kv: len(kv[0]), reverse=True)
    for i, (src, _dst) in enumerate(items):
        text = text.replace(src, f"\x00{i}\x00")
    for i, (_src, dst) in enumerate(items):
        text = text.replace(f"\x00{i}\x00", dst)
    return text


# ---------------------------------------------------------------------------
# Palette-theme engine: recolour any Default-authored colour for a THEME_SPECS
# theme. Surfaces take the theme's panel hue; text/muted keep their luminance
# (so contrast matches Default); the cyan accent family becomes the theme accent.
# Results are cached per colour and per stylesheet, so switching stays fast.
# ---------------------------------------------------------------------------
import colorsys as _colorsys
import re as _re

_COLOR_RX = _re.compile(
    r"#([0-9a-fA-F]{6})(?![0-9a-fA-F])|(rgba?\(\s*)(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})")
_SRC_KEYS = {
    "bg": ("#060606",),
    "panel": ("#0a1624", "10,22,36"),
    "card": ("#0d1c2c", "13,28,44"),
    "text": ("#eef6ff", "#e8f0ff"),
    "muted": ("#7d93a8",),
    "accent": ("#2ee6ff", "46,230,255"),
}
_VARIANT_STATE: dict = {}


def _hex_rgb(h):
    h = h.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _lum(rgb):
    def ch(c):
        c = c / 255.0
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = rgb
    return 0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b)


def contrast_ratio(a, b) -> float:
    la, lb = _lum(_hex_rgb(a) if isinstance(a, str) else a), _lum(_hex_rgb(b) if isinstance(b, str) else b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def _hls_rgb(h, l, s):
    r, g, b = _colorsys.hls_to_rgb(h % 1.0, max(0.0, min(1.0, l)), max(0.0, min(1.0, s)))
    return int(round(r * 255)), int(round(g * 255)), int(round(b * 255))


def _match_lum(h, s, target):
    """Lightness for hue/sat h,s whose WCAG luminance is closest to target."""
    lo, hi = 0.0, 1.0
    for _ in range(22):
        mid = (lo + hi) / 2
        if _lum(_hls_rgb(h, mid, s)) < target:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def _variant(name):
    st = _VARIANT_STATE.get(name)
    if st is None:
        spec = THEME_SPECS[name]
        exact = {}
        for key, srcs in _SRC_KEYS.items():
            if spec.get(key):
                for src in srcs:
                    rgb = _hex_rgb(src) if src.startswith("#") else tuple(int(x) for x in src.split(","))
                    exact[rgb] = _hex_rgb(spec[key])
        ph, _pl, ps = _colorsys.rgb_to_hls(*[c / 255.0 for c in _hex_rgb(spec["panel"])])
        ah, al, as_ = _colorsys.rgb_to_hls(*[c / 255.0 for c in _hex_rgb(spec["accent"])])
        if "tint_sat" in spec:
            ps = spec["tint_sat"]
        st = {"exact": exact, "ph": ph, "ps": ps, "ah": ah, "al": al, "as": as_,
              "scale": float(spec.get("surface_scale", 1.0)),
              "tsat": 0.0 if spec.get("tint_sat") == 0.0 else None,
              "cache": {}, "outs": set(), "sheets": {}}
        _VARIANT_STATE[name] = st
    return st


def _variant_rgb(name, rgb):
    st = _variant(name)
    cache = st["cache"]
    out = cache.get(rgb)
    if out is not None:
        return out
    if rgb in st["outs"] and rgb not in st["exact"]:
        cache[rgb] = rgb               # already themed (idempotent)
        return rgb
    out = st["exact"].get(rgb)
    if out is None:
        r, g, b = rgb
        h, l, s = _colorsys.rgb_to_hls(r / 255.0, g / 255.0, b / 255.0)
        hd = h * 360.0
        lum = _lum(rgb)
        if s >= 0.55 and 180 <= hd <= 210 and l >= 0.35:            # cyan accent family
            out = _hls_rgb(st["ah"] + (h - 0.52) * 0.5,
                           max(0.2, min(0.92, st["al"] + (l - 0.59) * 0.8)),
                           st["as"] * min(1.0, s))
        elif s < 0.12 or 185 <= hd <= 245:                           # navy / neutral
            if l < 0.35:                                             # surfaces
                hh, ss = st["ph"], st["ps"]
                tl = lum * st["scale"]
            else:                                                    # text / muted
                hh = st["ph"]
                ss = 0.0 if st["tsat"] == 0.0 else s
                tl = lum
            out = _hls_rgb(hh, _match_lum(hh, ss, tl), ss)
        else:
            out = rgb                                                # status colours stay
    cache[rgb] = out
    st["outs"].add(out)
    return out


def _variant_sub(text, name):
    st = _variant(name)
    sheets = st["sheets"]
    hit = sheets.get(text)
    if hit is not None:
        return hit

    def rep(m):
        if m.group(1):
            r, g, b = _variant_rgb(name, _hex_rgb(m.group(1)))
            return f"#{r:02x}{g:02x}{b:02x}"
        rgb = (int(m.group(3)), int(m.group(4)), int(m.group(5)))
        if max(rgb) > 255:
            return m.group(0)
        r, g, b = _variant_rgb(name, rgb)
        return f"{m.group(2)}{r}, {g}, {b}"

    out = _COLOR_RX.sub(rep, text)
    if len(sheets) > 4096:
        sheets.clear()
    sheets[text] = out
    return out


def is_palette_theme(name=None) -> bool:
    return (name or _current["effective"]) in THEME_SPECS


def theme_remap(text, name=None) -> str:
    """Recolour a Default-authored stylesheet / colour string for a theme."""
    eff = name or _current["effective"]
    if not text or eff == "default":
        return text
    if eff == "dark":
        return _remap(text, _DARK_MAP)
    if eff == "light":
        return _remap(text, _LIGHT_MAP)
    if eff in THEME_SPECS:
        return _variant_sub(text, eff)
    return text


def theme_color(color, name=None) -> str:
    """Single colour (hex) for the active theme; used by custom painters."""
    if isinstance(color, str) and color.startswith("#") and len(color) == 7:
        eff = name or _current["effective"]
        if eff in THEME_SPECS:
            r, g, b = _variant_rgb(eff, _hex_rgb(color))
            return f"#{r:02x}{g:02x}{b:02x}"
    return color


def _variant_tuple(t, name):
    r, g, b = _variant_rgb(name, tuple(t[:3]))
    return (r, g, b) + tuple(t[3:])


_QSS_CACHE: dict = {}


def _system_prefers_light() -> bool:
    """True when the OS colour scheme is light. Falls back to dark on any error."""
    try:
        from PyQt6.QtCore import Qt
        from PyQt6.QtGui import QGuiApplication
        hints = QGuiApplication.styleHints()
        scheme = hints.colorScheme() if hints is not None else None
        return scheme == Qt.ColorScheme.Light
    except Exception:
        return False


def resolve_theme(name) -> str:
    """Normalize a theme name. 'default' is the original look (not OS-follow)."""
    name = str(name or "default").strip().lower()
    # Migrate v1 names that may still be in memory mid-session.
    if name in ("system", "os"):
        name = "default"
    if name not in THEMES:
        name = "default"
    return name


# Light login page: same palette as the mini DedSec VPN window (solid white
# cards, dark readable text, teal accents). Appended after the remapped base
# so it wins; dark/default never see it.
_LIGHT_MENU_QSS = (
    "QMenu { background-color: #ffffff; color: #0d1b2a; border: 1px solid #cfdde6;"
    " border-radius: 8px; padding: 5px 4px; font-family: 'Segoe UI'; font-size: 13px; }"
    "QMenu::item { background: transparent; color: #0d1b2a; padding: 6px 24px 6px 12px;"
    " border-radius: 5px; margin: 1px 3px; }"
    "QMenu::item:selected { background-color: #00707f; color: #ffffff; }"
    "QMenu::item:disabled { color: #6b7c8c; background: transparent; }"
    "QMenu::separator { height: 1px; background: #d5e2ea; margin: 4px 8px; }"
    "QMenu::icon { padding-left: 6px; }"
)
_DARK_MENU_QSS = (
    "QMenu { background-color: #0d1c2c; color: #eef6ff; border: 1px solid #2ee6ff;"
    " border-radius: 8px; padding: 5px 4px; font-family: 'Segoe UI'; font-size: 13px; }"
    "QMenu::item { background: transparent; color: #eef6ff; padding: 6px 24px 6px 12px;"
    " border-radius: 5px; margin: 1px 3px; }"
    "QMenu::item:selected { background-color: #2ee6ff; color: #04212a; }"
    "QMenu::item:disabled { color: #7d93a8; background: transparent; }"
    "QMenu::separator { height: 1px; background: #24384c; margin: 4px 8px; }"
)

_LIGHT_EXTRA_QSS = """
QMenu { background-color: #ffffff; color: #0d1b2a; border: 1px solid #cfdde6; }
QMenu::item { color: #0d1b2a; background: transparent; padding: 6px 24px 6px 12px; }
QMenu::item:selected { background-color: #00707f; color: #ffffff; }
QMenu::item:disabled { color: #6b7c8c; }
QToolTip { background-color: #ffffff; color: #0d1b2a; border: 1px solid #cfdde6; padding: 4px 6px; }
QHeaderView::section { color: #0d1b2a; }
QTableView, QTableWidget, QTreeView, QListView { color: #0d1b2a; }
QPushButton:disabled { color: #6b7c8c; }
QLineEdit:disabled, QTextEdit:disabled, QPlainTextEdit:disabled, QComboBox:disabled { color: #6b7c8c; }
QLineEdit, QTextEdit, QPlainTextEdit, QComboBox { placeholder-text-color: #4a6178; }
QPushButton:pressed { background: rgba(0, 112, 127, 0.18); }
QFrame#Sidebar QPushButton#DangerButton {
    background: #d92b3a; color: #ffffff; border: none;
}
QFrame#Sidebar QPushButton#DangerButton:hover {
    background: #ef3b4b; border: none; color: #ffffff;
}
QFrame#Sidebar QPushButton#DangerButton:pressed {
    background: #a81e2b; border: none; color: #ffffff;
    padding-top: 13px; padding-bottom: 9px;
}
"""

_LIGHT_LOGIN_QSS = """
QWidget#LoginPage QFrame#LoginMainPanel {
    background: #ffffff;
    border: 1px solid #d5e2ea;
    border-radius: 16px;
}
QWidget#LoginPage QFrame#LoginInnerPanel,
QWidget#LoginPage QFrame#LoginSideHud {
    background: #f3f7fa;
    border: 1px solid #d5e2ea;
    border-radius: 14px;
}
QWidget#LoginPage QLabel { color: #33475b; background: transparent; }
QWidget#LoginPage QLabel#LoginMainTitle { color: #0d1b2a; }
QWidget#LoginPage QLabel#LoginSubtitle { color: #33475b; font-size: 14px; }
QWidget#LoginPage QLabel#LoginHeroTitle { color: #0d1b2a; font-weight: 800; font-size: 13px; }
QWidget#LoginPage QLabel#LoginPanelHint,
QWidget#LoginPage QLabel#Hint,
QWidget#LoginPage QLabel#LoginHudText { color: #33475b; }
QWidget#LoginPage QLabel#LoginStageTitle,
QWidget#LoginPage QLabel#LoginHudTitle { color: #00707f; }
QWidget#LoginPage QLabel#LoginMiniStatus {
    color: #0d1b2a;
    background: #f3f7fa;
    border: 1px solid #d5e2ea;
    border-radius: 8px;
}
QWidget#LoginPage QLabel#LoginVPNStatus,
QWidget#LoginPage QLabel#LoginConfigText {
    background: #f3f7fa;
    border: 1px solid #cfdde6;
    color: #0d1b2a;
}
QWidget#LoginPage QLabel#DeviceIdLabel { color: #0d1b2a; }
QWidget#LoginPage QLineEdit#LoginInput {
    background: #ffffff;
    border: 1px solid #cfdde6;
    color: #0d1b2a;
}
QWidget#LoginPage QLineEdit#LoginInput:focus { border: 1px solid #00707f; }
QWidget#LoginPage QPushButton#LoginPrimaryButton {
    background: #00707f;
    color: #ffffff;
    border: none;
}
QWidget#LoginPage QPushButton#LoginPrimaryButton:hover { background: #008596; }
QWidget#LoginPage QPushButton#LoginPrimaryButton:pressed {
    background: #005a66;
    border: none;
    padding-top: 10px;
    padding-bottom: 6px;
}
QWidget#LoginPage QPushButton#LoginDangerButton {
    background: #d92b3a;
    color: #ffffff;
    border: none;
}
QWidget#LoginPage QPushButton#LoginDangerButton:hover { background: #ef3b4b; }
QWidget#LoginPage QPushButton#LoginDangerButton:pressed {
    background: #a81e2b;
    border: none;
    padding-top: 10px;
    padding-bottom: 6px;
}
QWidget#LoginPage QPushButton#LoginPrimaryButton:disabled,
QWidget#LoginPage QPushButton#LoginDangerButton:disabled {
    background: #e3ebf0;
    border: 1px solid #d5e2ea;
    color: #5b6f80;
}
QWidget#LoginPage QCheckBox { color: #33475b; }
QWidget#LoginPage QProgressBar#LoginProgress {
    background: #e9f1f6;
    border: 1px solid #cfdde6;
    color: #0d1b2a;
}
QWidget#LoginPage QProgressBar#LoginProgress::chunk { background: #00707f; }
"""


def build_qss(name) -> str:
    eff = resolve_theme(name)
    if eff not in _QSS_CACHE:
        if eff == "default":
            _QSS_CACHE[eff] = _BASE_QSS
        elif eff == "dark":
            _QSS_CACHE[eff] = _remap(_BASE_QSS, _DARK_MAP)
        elif eff in THEME_SPECS:
            _QSS_CACHE[eff] = _variant_sub(_BASE_QSS, eff)
        else:
            _QSS_CACHE[eff] = _remap(_BASE_QSS, _LIGHT_MAP) + _LIGHT_EXTRA_QSS + _LIGHT_LOGIN_QSS
    return _QSS_CACHE[eff]


_PALETTES = {
    "default": {
        "Window": "#060606", "Base": "#060606", "AlternateBase": "#0b0b0e",
        "Button": "#0b0b0e", "WindowText": "#e8f0ff", "Text": "#e8f0ff",
        "ButtonText": "#e8f0ff", "Highlight": "#2ee6ff", "HighlightedText": "#060606",
        "ToolTipBase": "#0d1c2c", "ToolTipText": "#eef6ff", "PlaceholderText": "#7d93a8",
    },
    "dark": {
        "Window": "#010102", "Base": "#010102", "AlternateBase": "#05070c",
        "Button": "#080c12", "WindowText": "#e8f0ff", "Text": "#e8f0ff",
        "ButtonText": "#e8f0ff", "Highlight": "#00e5ff", "HighlightedText": "#010102",
        "ToolTipBase": "#080c12", "ToolTipText": "#eef6ff", "PlaceholderText": "#7d93a8",
    },
    "light": {
        "Window": "#f5f7fa", "Base": "#ffffff", "AlternateBase": "#f1f5f9",
        "Button": "#e2e8f0", "WindowText": "#0f172a", "Text": "#0f172a",
        "ButtonText": "#0f172a", "Highlight": "#0e7490", "HighlightedText": "#ffffff",
        "ToolTipBase": "#ffffff", "ToolTipText": "#0d1b2a", "PlaceholderText": "#4a6178",
    },
}


def _palette_dict(eff):
    if eff not in _PALETTES and eff in THEME_SPECS:
        _PALETTES[eff] = {k: theme_color(v, eff) for k, v in _PALETTES["default"].items()}
    return _PALETTES[eff]


def build_palette(name) -> QPalette:
    eff = resolve_theme(name)
    pal = QPalette()
    for role, color in _palette_dict(eff).items():
        pal.setColor(getattr(QPalette.ColorRole, role), QColor(color))
    return pal


# Window-chrome colours (frameless title bar / shell) used by main_window.py.
_CHROME = {
    "default": {"bg": "#0a1624", "border": "#2ee6ff", "brand": "#2ee6ff",
                "button": "#7d93a8", "hover": "#2ee6ff", "danger": "#ff4d5f",
                "app_bg": "#060606", "wallpaper_tint": (6, 6, 6, 90),
                "gate_tint": (6, 12, 20, 155), "login_tint": (0, 0, 0, 0)},
    "dark": {"bg": "#05070c", "border": "#00e5ff", "brand": "#00e5ff",
             "button": "#7d93a8", "hover": "#00e5ff", "danger": "#ff4d5f",
             "app_bg": "#010102", "wallpaper_tint": (1, 1, 2, 140),
             "gate_tint": (1, 2, 4, 185), "login_tint": (0, 0, 0, 70)},
    "light": {"bg": "#eef2f7", "border": "#0e7490", "brand": "#0d1b2a",
              "button": "#475569", "hover": "#0e7490", "danger": "#be123c",
              "app_bg": "#f3f7fa", "wallpaper_tint": (243, 247, 250, 238),
              "gate_tint": (243, 247, 250, 238), "login_tint": (243, 247, 250, 238)},
}


def current_theme() -> str:
    """Effective theme currently applied ("default", "dark" or "light")."""
    return _current["effective"]


def requested_theme() -> str:
    """Theme the user picked ("default", "dark" or "light")."""
    return _current["requested"]


def chrome_colors(name=None) -> dict:
    eff = resolve_theme(name) if name else _current["effective"]
    if eff not in _CHROME and eff in THEME_SPECS:
        base = _CHROME["default"]
        c = {}
        for k, v in base.items():
            if isinstance(v, str):
                c[k] = theme_color(v, eff)
            elif isinstance(v, tuple):
                c[k] = _variant_tuple(v, eff)
            else:
                c[k] = v
        c["brand"] = THEME_SPECS[eff]["accent"]
        c["border"] = THEME_SPECS[eff]["accent"]
        c["hover"] = THEME_SPECS[eff]["accent"]
        c["danger"] = "#ff4d5f"
        c["wall_color"] = THEME_SPECS[eff]["accent"]
        # a little more wash so the cyan-art wallpaper recolour sits back
        c["wallpaper_tint"] = c["wallpaper_tint"][:3] + (120,)
        c["login_tint"] = _hex_rgb(THEME_SPECS[eff]["bg"]) + (110,)
        _CHROME[eff] = c
    return dict(_CHROME[eff])


_WALL_CACHE: dict = {}


def themed_wallpaper(pixmap, name=None):
    """Wallpaper recoloured to the theme accent (palette themes only). Cached."""
    eff = name or _current["effective"]
    if eff not in THEME_SPECS or pixmap is None or pixmap.isNull():
        return pixmap
    key = (pixmap.cacheKey(), eff)
    hit = _WALL_CACHE.get(key)
    if hit is not None:
        return hit
    from PyQt6.QtGui import QImage, QPainter, QPixmap
    img = pixmap.toImage().convertToFormat(QImage.Format.Format_Grayscale8)
    img = img.convertToFormat(QImage.Format.Format_ARGB32_Premultiplied)
    p = QPainter(img)
    p.setCompositionMode(QPainter.CompositionMode.CompositionMode_Multiply)
    acc = QColor(THEME_SPECS[eff]["accent"])
    p.fillRect(img.rect(), acc)
    p.end()
    out = QPixmap.fromImage(img)
    if len(_WALL_CACHE) > 12:
        _WALL_CACHE.clear()
    _WALL_CACHE[key] = out
    return out


# ---------------------------------------------------------------------------
# Inline (per-widget) stylesheet theming.
# Many pages call widget.setStyleSheet(...) with hard-coded dark colours. An
# app-wide event filter remaps those for LIGHT too, including sheets set later
# at runtime, and restores the authored originals when switching back to DARK.
# ---------------------------------------------------------------------------
_PROP_SRC = "_dslThemeSrc"       # stylesheet as authored by app code (dark)
_PROP_OUT = "_dslThemeOut"       # stylesheet we last applied


_PROP_EXEMPT = "dslThemeExempt"   # set True on a widget to keep its authored look


def _theme_exempt(w) -> bool:
    """True if w or any ancestor opted out (e.g. the dark NordVPN-style VPN gate)."""
    try:
        node = w
        while node is not None:
            if node.property(_PROP_EXEMPT):
                return True
            node = node.parentWidget()
    except RuntimeError:
        return False
    return False


def _retheme_widget(w, force=False):
    try:
        sheet = w.styleSheet()
    except RuntimeError:          # widget already deleted on the C++ side
        return
    if _theme_exempt(w):
        # Undo any remap applied before the widget was parented under an exempt root.
        src = w.property(_PROP_SRC)
        out = w.property(_PROP_OUT)
        w.setProperty(_PROP_SRC, None)
        w.setProperty(_PROP_OUT, None)
        if src is not None and out is not None and sheet == out and src != sheet:
            w.setStyleSheet(src)
        return
    out = w.property(_PROP_OUT)
    if not force and out is not None and sheet == out:
        return                    # our own output; nothing new authored
    if force and w.property(_PROP_SRC) is not None and (out is None or sheet == out):
        src = w.property(_PROP_SRC)
    else:
        src = sheet               # freshly authored by app code
    if not src:
        return
    eff = _current["effective"]
    if eff == "default":
        target = src
    elif eff == "dark":
        target = _remap(src, _DARK_MAP)
    elif eff in THEME_SPECS:
        target = _variant_sub(src, eff)
    else:
        target = _remap(src, _LIGHT_MAP)
    w.setProperty(_PROP_SRC, src)
    w.setProperty(_PROP_OUT, target)   # set before setStyleSheet -> no re-entry loop
    if target != sheet:
        w.setStyleSheet(target)


class _InlineThemer(QObject):
    _TYPES = (QEvent.Type.Polish, QEvent.Type.StyleChange)

    def eventFilter(self, obj, event):
        if event.type() in self._TYPES and isinstance(obj, QWidget):
            if isinstance(obj, QMenu) and event.type() == QEvent.Type.Polish:
                _style_menu(obj)
            _retheme_widget(obj)
        return False


def _wants_dark_menus(w) -> bool:
    node = w
    while node is not None:
        if node.property("dslDarkMenus"):
            return True
        node = node.parentWidget()
    return False


def _style_menu(menu):
    """Readable context / popup menus. Menus that carry their own sheet
    (tray, VPN gate) are left alone; dark-only windows get the dark menu."""
    try:
        if menu.property("_dslMenuStyled") is None and menu.styleSheet():
            return
        if _wants_dark_menus(menu):
            sheet = _DARK_MENU_QSS
        elif _current["effective"] == "light":
            sheet = _LIGHT_MENU_QSS
        elif _current["effective"] in THEME_SPECS:
            sheet = _variant_sub(_DARK_MENU_QSS, _current["effective"])
        else:
            return
        if menu.styleSheet() != sheet:
            menu.setProperty("_dslMenuStyled", True)
            menu.setProperty(_PROP_EXEMPT, True)
            menu.setStyleSheet(sheet)
    except RuntimeError:
        pass


_themer = {"obj": None}


def _install_inline_themer(app):
    if _themer["obj"] is None and app is not None:
        _themer["obj"] = _InlineThemer(app)
        app.installEventFilter(_themer["obj"])


def _retheme_all_widgets(app):
    for w in app.allWidgets():
        _retheme_widget(w, force=True)


def apply_theme(app, name) -> str:
    """Apply palette + stylesheet to the whole QApplication. Returns effective theme."""
    requested = str(name or "default").strip().lower()
    if requested not in THEMES:
        requested = "default"
    eff = resolve_theme(requested)
    _current["requested"] = requested
    _current["effective"] = eff
    if app is not None:
        _install_inline_themer(app)
        tops = [w for w in app.topLevelWidgets() if w.isVisible()]
        for w in tops:
            w.setUpdatesEnabled(False)
        try:
            app.setPalette(build_palette(eff))
            qss = build_qss(eff)
            if app.styleSheet() != qss:
                app.setStyleSheet(qss)
            _retheme_all_widgets(app)
            # The mini DedSec VPN window keeps its own palette (theme-exempt);
            # let it swap to the matching light/dark colours.
            gate = sys.modules.get("core.dedsec_vpn_gate")
            hook = getattr(gate, "retheme_all", None) if gate else None
            if callable(hook):
                try:
                    hook(eff)
                except Exception:
                    pass
        finally:
            for w in tops:
                try:
                    w.setUpdatesEnabled(True)
                    w.update()
                except RuntimeError:
                    pass
    return eff


def saved_theme() -> str:
    """Read the persisted preference from the app config (core.config)."""
    try:
        from core.config import ConfigManager
        value = str(ConfigManager.load().get("theme", "default")).strip().lower()
        return value if value in THEMES else "default"
    except Exception:
        return "default"


def apply_styles(app, theme=None):
    """Startup entry point (kept for backwards compatibility with app.py)."""
    return apply_theme(app, theme if theme is not None else saved_theme())
