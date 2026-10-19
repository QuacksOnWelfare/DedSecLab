from pathlib import Path
from datetime import datetime
import ctypes
import sys

from PyQt6.QtCore import QEvent, QObject, QPoint, QRectF, Qt, QTimer
from PyQt6.QtGui import QColor, QCursor, QIcon, QPainter, QPainterPath, QPen, QPixmap, QRegion
from PyQt6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMenu,
    QSizeGrip,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

DESIGN_W = 2560
DESIGN_H = 1600

from core.config import ConfigManager, APP_NAME
from core.server import MockServerClient
from pages.login_page import LoginPage
from pages.main_app_page import MainAppPage
from ui.styles import chrome_colors


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.config = ConfigManager.load()
        self.server = MockServerClient()
        self._drag = QPoint()
        self._resize_edge = None
        self._resize_origin = QPoint()
        self._resize_geom = None
        self._maxed = False
        self._restore_geom = None
        self._bar_pressed = False

        self.setWindowTitle(APP_NAME)
        self.resize(420, 720)
        self.setMinimumSize(380, 640)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Window)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setMouseTracking(True)

        self.shell = QWidget()
        self.shell.setObjectName("AppShell")
        self.shell.setMouseTracking(True)
        root = QVBoxLayout(self.shell)
        root.setContentsMargins(2, 2, 2, 2)
        root.setSpacing(0)
        self._shell_root = root

        bar = QFrame()
        self.title_bar = bar
        bar.setObjectName("TitleBar")
        bar.setFixedHeight(36)
        hl = QHBoxLayout(bar)
        hl.setContentsMargins(12, 0, 6, 0)
        self.brand_icon = QLabel()
        self.brand_icon.setObjectName("TitleBrandIcon")
        self.brand_icon.setFixedSize(22, 22)
        icon_path = Path(__file__).resolve().parent / "assets" / "dedsec_logo.png"
        if not icon_path.is_file():
            icon_path = Path(__file__).resolve().parent / "assets" / "applogo.png"
        if icon_path.is_file():
            ipm = QPixmap(str(icon_path))
            if not ipm.isNull():
                self.brand_icon.setPixmap(
                    ipm.scaled(
                        22, 22,
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation,
                    )
                )
        self.brand = QLabel("DEDSEC")
        self.brand.setObjectName("TitleBrand")
        hl.addWidget(self.brand_icon)
        hl.addWidget(self.brand)
        hl.addStretch()
        self.btn_min = QPushButton("-")
        self.btn_max = QPushButton("□")
        self.btn_close = QPushButton("✕")
        for b in (self.btn_min, self.btn_max, self.btn_close):
            b.setObjectName("WinBtn")
            b.setFlat(True)
            b.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_close.setObjectName("WinClose")
        self.btn_close.setToolTip("Close")
        self.btn_min.clicked.connect(self.showMinimized)
        self.btn_max.clicked.connect(self._toggle_max)
        self.btn_close.clicked.connect(self.close)
        hl.addWidget(self.btn_min)
        hl.addWidget(self.btn_max)
        hl.addWidget(self.btn_close)
        bar.mousePressEvent = self._bar_press
        bar.mouseMoveEvent = self._bar_drag
        bar.mouseReleaseEvent = self._bar_release
        bar.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        bar.customContextMenuRequested.connect(self._size_menu)
        self.btn_max.setToolTip("Maximise / restore  (right-click title bar for sizes)")
        bar.mouseDoubleClickEvent = lambda e: self._toggle_max()
        root.addWidget(bar)

        self.inner = QFrame()
        self.inner.setObjectName("InnerChrome")
        inner_lay = QVBoxLayout(self.inner)
        inner_lay.setContentsMargins(0, 0, 0, 0)
        inner_lay.setSpacing(0)
        self.stack = QStackedWidget()
        inner_lay.addWidget(self.stack)
        self.size_grip = QSizeGrip(self.inner)
        self.size_grip.setFixedSize(16, 16)
        self.size_grip.setToolTip("Drag to resize")
        self.size_grip.setStyleSheet("background: transparent;")
        root.addWidget(self.inner, 1)
        self.setCentralWidget(self.shell)

        self.login_page = LoginPage(self)
        self.main_app_page = MainAppPage(self)
        self.stack.addWidget(self.login_page)
        self.stack.addWidget(self.main_app_page)
        self.login_page.load_config()
        self._set_chrome(False)

        self._edge_cursor = False
        QApplication.instance().installEventFilter(self)

        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh_all)
        self.statusBar().hide()

    def _is_login(self) -> bool:
        return hasattr(self, "login_page") and self.stack.currentWidget() is getattr(self, "login_page", None)

    def _set_chrome(self, maximized: bool):
        login = self._is_login()
        rad = "16px" if login else "0px"
        if hasattr(self, "btn_max"):
            self.btn_max.setVisible(True)
        if hasattr(self, "brand"):
            self.brand.setVisible(True)
        if hasattr(self, "_shell_root"):
            self._shell_root.setContentsMargins(6, 6, 6, 6) if login else self._shell_root.setContentsMargins(0, 0, 0, 0)
        if hasattr(self, "title_bar"):
            self.title_bar.setVisible(True)
            self.title_bar.setFixedHeight(36)
        c = chrome_colors()
        border = f"2px solid {c['border']}" if login else "none"
        self._apply_round_mask(login and not maximized)
        self.shell.setStyleSheet(f"""
            QWidget#AppShell {{
                background: {c['bg']};
                border: {border};
                border-radius: {rad};
            }}
            QFrame#InnerChrome {{
                background: {c['bg']};
                border: none;
            }}
            QFrame#TitleBar {{
                background: {c['bg']};
                border: none;
            }}
            QLabel#TitleBrand {{
                color: {c['brand']};
                font-weight: 800;
                letter-spacing: 4px;
                font-size: 13px;
                background: transparent;
                border: none;
            }}
            QFrame#TitleBar QPushButton, QFrame#TitleBar QPushButton#WinBtn {{
                background: transparent;
                border: none;
                padding: 0;
                margin: 0;
                color: {c['button']};
                min-width: 28px;
                max-width: 28px;
                min-height: 28px;
                max-height: 28px;
                font-size: 14px;
                font-weight: 700;
            }}
            QFrame#TitleBar QPushButton:hover {{
                color: {c['hover']};
            }}
            QFrame#TitleBar QPushButton#WinClose {{
                background: #d92b3a;
                color: #ffffff;
                border-radius: 6px;
                margin-left: 4px;
            }}
            QFrame#TitleBar QPushButton#WinClose:hover {{
                background: #ff3b4e;
                color: #ffffff;
            }}
            QFrame#TitleBar QPushButton#WinClose:pressed {{
                background: #a81e2b;
            }}
        """)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        c = chrome_colors()
        if self._is_login():
            r = QRectF(self.rect()).adjusted(3, 3, -3, -3)
            path = QPainterPath()
            path.addRoundedRect(r, 16, 16)
            p.fillPath(path, QColor(c["bg"]))
            p.setPen(QPen(QColor(c["border"]), 2))
            p.drawPath(path)
        else:
            p.fillRect(self.rect(), QColor(c["bg"]))
        super().paintEvent(event)

    def _apply_round_mask(self, rounded: bool):
        if not rounded:
            self.clearMask()
            return
        path = QPainterPath()
        path.addRoundedRect(QRectF(self.rect()), 16, 16)
        self.setMask(QRegion(path.toFillPolygon().toPolygon()))

    def resizeEvent(self, e):
        super().resizeEvent(e)
        if hasattr(self, "size_grip"):
            g = self.size_grip
            g.move(self.inner.width() - g.width(), self.inner.height() - g.height())
            g.raise_()
            g.setVisible(not self._is_login() and not getattr(self, "_maxed", False))
        self._apply_round_mask(self._is_login() and not self._is_max())

    def changeEvent(self, e):
        super().changeEvent(e)
        if e.type() == e.Type.WindowStateChange and self._is_login():
            self._set_chrome(self.isMaximized())

    def _design_geom(self):
        screen = self.screen() or QApplication.primaryScreen()
        if screen is None:
            return 0, 0, DESIGN_W, DESIGN_H
        geo = screen.availableGeometry()
        w = min(DESIGN_W, int(geo.width() * 0.92))
        h = min(DESIGN_H, int(geo.height() * 0.92))
        x = geo.x() + max(0, (geo.width() - w) // 2)
        y = geo.y() + max(0, (geo.height() - h) // 2)
        return x, y, w, h

    def _open_at_design_size(self):
        self._maxed = False
        if self.isMaximized():
            self.showNormal()
        x, y, w, h = self._design_geom()
        self.setGeometry(x, y, w, h)
        self._set_chrome(False)

    def _is_max(self) -> bool:
        return self._maxed or self.isMaximized()

    def _toggle_max(self):
        # Manual maximise: just swap geometry. Avoids Windows' frameless
        # maximise/restore state changes, which made the window jump around.
        if self._is_login():
            return
        self._clear_edge_cursor()
        if self.isMaximized():
            self.showNormal()
        if self._maxed:
            self._maxed = False
            if self._restore_geom is not None:
                self.setGeometry(self._restore_geom)
        else:
            self._restore_geom = self.geometry()
            screen = self.screen() or QApplication.primaryScreen()
            if screen is not None:
                self._maxed = True
                self.setGeometry(screen.availableGeometry())
        self.btn_max.setText("❐" if self._maxed else "□")
        if hasattr(self, "size_grip"):
            self.size_grip.setVisible(not self._maxed)

    def _bar_press(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self._bar_pressed = True
            self._drag = e.globalPosition().toPoint() - self.frameGeometry().topLeft()

    def _bar_move(self, e):
        if not (self._bar_pressed and e.buttons() & Qt.MouseButton.LeftButton):
            return
        gp = e.globalPosition().toPoint()
        if (gp - self.frameGeometry().topLeft() - self._drag).manhattanLength() < 6:
            return
        self._bar_pressed = False
        if self._maxed and self._restore_geom is not None:
            # Dragging a maximised window: restore it under the cursor.
            rw = self._restore_geom.width()
            ratio = (gp.x() - self.x()) / max(1, self.width())
            self._maxed = False
            self.btn_max.setText("□")
            self.setGeometry(int(gp.x() - rw * ratio), gp.y() - 18, rw, self._restore_geom.height())
            self._drag = gp - self.frameGeometry().topLeft()
        self._moving = True
        self.move(gp - self._drag)

    def _bar_drag(self, e):
        if self._bar_pressed:
            self._bar_move(e)
            return
        if getattr(self, "_moving", False) and e.buttons() & Qt.MouseButton.LeftButton:
            self.move(e.globalPosition().toPoint() - self._drag)

    def _bar_release(self, e):
        self._bar_pressed = False
        was_moving = getattr(self, "_moving", False)
        self._moving = False
        if not was_moving or self._is_login() or self._maxed:
            return
        # Snap: dropping the window at the very top of the screen maximises it.
        gp = e.globalPosition().toPoint()
        screen = QApplication.screenAt(gp) or self.screen()
        if screen is not None and gp.y() <= screen.geometry().top() + 4:
            # remember the pre-drag size so restore puts it back sensibly
            self._toggle_max()

    def _size_menu(self, pos):
        if self._is_login():
            return
        m = QMenu(self)
        m.setStyleSheet(
            "QMenu{background:#0b1620;color:#d7f6ff;border:1px solid #1f4b5c;padding:4px;}"
            "QMenu::item{padding:6px 18px;}QMenu::item:selected{background:#123444;color:#00e5ff;}"
        )
        screen = self.screen() or QApplication.primaryScreen()
        geo = screen.availableGeometry() if screen else None
        presets = [(1024, 640), (1280, 720), (1366, 768), (1600, 900), (1920, 1080)]
        for w, h in presets:
            if geo is not None and (w > geo.width() or h > geo.height()):
                continue
            act = m.addAction(f"{w} × {h}")
            act.triggered.connect(lambda _=False, w=w, h=h: self._set_window_size(w, h))
        m.addSeparator()
        m.addAction("Fit to screen (maximise)" if not self._maxed else "Restore size").triggered.connect(self._toggle_max)
        m.addAction("Centre window").triggered.connect(self._centre_window)
        m.exec(self.title_bar.mapToGlobal(pos))

    def _set_window_size(self, w, h):
        if self._maxed:
            self._maxed = False
            self.btn_max.setText("□")
        w = max(self.minimumWidth(), w)
        h = max(self.minimumHeight(), h)
        self.resize(w, h)
        self._centre_window()

    def _centre_window(self):
        if self._maxed:
            return
        screen = self.screen() or QApplication.primaryScreen()
        if screen is None:
            return
        geo = screen.availableGeometry()
        self.move(geo.x() + (geo.width() - self.width()) // 2, geo.y() + (geo.height() - self.height()) // 2)

    def _edge_at(self, pos):
        if self._is_login() or self._is_max():
            return None
        m = 6
        r = self.rect()
        left = pos.x() <= m
        right = pos.x() >= r.width() - m
        top = pos.y() <= m
        bottom = pos.y() >= r.height() - m
        if top and left:
            return "tl"
        if top and right:
            return "tr"
        if bottom and left:
            return "bl"
        if bottom and right:
            return "br"
        if left:
            return "l"
        if right:
            return "r"
        if top:
            return "t"
        if bottom:
            return "b"
        return None

    _EDGE_MAP = {
        "l": Qt.Edge.LeftEdge, "r": Qt.Edge.RightEdge,
        "t": Qt.Edge.TopEdge, "b": Qt.Edge.BottomEdge,
        "tl": Qt.Edge.TopEdge | Qt.Edge.LeftEdge,
        "tr": Qt.Edge.TopEdge | Qt.Edge.RightEdge,
        "bl": Qt.Edge.BottomEdge | Qt.Edge.LeftEdge,
        "br": Qt.Edge.BottomEdge | Qt.Edge.RightEdge,
    }
    _EDGE_CURSOR = {
        "l": Qt.CursorShape.SizeHorCursor, "r": Qt.CursorShape.SizeHorCursor,
        "t": Qt.CursorShape.SizeVerCursor, "b": Qt.CursorShape.SizeVerCursor,
        "tl": Qt.CursorShape.SizeFDiagCursor, "br": Qt.CursorShape.SizeFDiagCursor,
        "tr": Qt.CursorShape.SizeBDiagCursor, "bl": Qt.CursorShape.SizeBDiagCursor,
    }

    def _clear_edge_cursor(self):
        if self._edge_cursor:
            QApplication.restoreOverrideCursor()
            self._edge_cursor = False

    def eventFilter(self, obj, ev):
        # Window-wide edge resize: works even when child widgets cover the
        # border, using the OS native resize (smooth, no lag).
        t = ev.type()
        if t not in (QEvent.Type.MouseMove, QEvent.Type.MouseButtonPress):
            return False
        if not isinstance(obj, QWidget) or obj.window() is not self:
            return False
        if self._is_login() or self._is_max():
            self._clear_edge_cursor()
            return False
        if t == QEvent.Type.MouseMove and ev.buttons() != Qt.MouseButton.NoButton:
            return False
        local = self.mapFromGlobal(ev.globalPosition().toPoint())
        edge = self._edge_at(local)
        if t == QEvent.Type.MouseMove:
            if edge:
                shape = self._EDGE_CURSOR[edge]
                if self._edge_cursor:
                    QApplication.changeOverrideCursor(QCursor(shape))
                else:
                    QApplication.setOverrideCursor(QCursor(shape))
                    self._edge_cursor = True
            else:
                self._clear_edge_cursor()
            return False
        if edge and ev.button() == Qt.MouseButton.LeftButton:
            wh = self.windowHandle()
            if wh is not None and wh.startSystemResize(self._EDGE_MAP[edge]):
                self._clear_edge_cursor()
                return True
        return False

    def leaveEvent(self, e):
        self._clear_edge_cursor()
        super().leaveEvent(e)

    def _tint_native_caption(self):
        if sys.platform != "win32":
            return
        try:
            hwnd = int(self.winId())
            dwmapi = ctypes.windll.dwmapi
            color = ctypes.c_int(0x00140E07)  # #070e14 - darker than the app
            text = ctypes.c_int(0x00A8937D)   # muted so the caption stays quiet
            DWMWA_BORDER_COLOR = 34
            DWMWA_CAPTION_COLOR = 35
            DWMWA_TEXT_COLOR = 36
            dwmapi.DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, ctypes.byref(color), 4)
            dwmapi.DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR, ctypes.byref(color), 4)
            dwmapi.DwmSetWindowAttribute(hwnd, DWMWA_TEXT_COLOR, ctypes.byref(text), 4)
            user32 = ctypes.windll.user32
            WM_SETICON = 0x0080
            user32.SendMessageW(hwnd, WM_SETICON, 0, 0)
            user32.SendMessageW(hwnd, WM_SETICON, 1, 0)
        except Exception:
            pass

    def refresh_theme(self):
        """Re-apply window chrome colours after the theme changes."""
        self._set_chrome(self.isMaximized())
        if hasattr(self, "login_page") and hasattr(self.login_page, "_apply_cover_wallpaper"):
            self.login_page._apply_cover_wallpaper()
        if hasattr(self, "login_page") and hasattr(self.login_page, "apply_login_theme"):
            try:
                self.login_page.apply_login_theme()
            except Exception:
                pass
        self.update()
        if hasattr(self, "main_app_page"):
            pages = getattr(self.main_app_page, "pages", None)
            if pages is not None:
                for i in range(pages.count()):
                    hook = getattr(pages.widget(i), "on_theme_changed", None)
                    if callable(hook):
                        try:
                            hook()
                        except Exception:
                            pass
            brand_hook = getattr(self.main_app_page, "apply_brand_theme", None)
            if callable(brand_hook):
                try:
                    brand_hook()
                except Exception:
                    pass
            self.main_app_page.update()

    def show_main_app(self):
        # Invisible while size changes. Windows otherwise moves the
        # 420x720 login card to 0,0 for one frame before the dashboard
        # geometry is applied.
        self.setWindowOpacity(0)
        QApplication.processEvents()
        self.stack.setCurrentWidget(self.main_app_page)
        self.clearMask()
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)
        self.setWindowTitle("DedSec Lab")
        self.setMinimumSize(980, 620)
        self._set_chrome(False)
        x, y, w, h = self._design_geom()
        self.setGeometry(x, y, w, h)
        QApplication.processEvents()
        self.setWindowOpacity(1)
        self.add_log("Connected to server.")
        self.timer.start(3000)
        QTimer.singleShot(80, self.main_app_page.refresh)

    def disconnect(self):
        self.server.disconnect()
        self.timer.stop()
        self.close()

    def refresh_all(self):
        if self.stack.currentWidget() == self.main_app_page:
            current_page = self.main_app_page.pages.currentWidget()
            from pages.terminal_page import TerminalPage
            if isinstance(current_page, TerminalPage):
                return
            if not self.isVisible() or self.isMinimized():
                return
            if hasattr(self.main_app_page, "refresh_live"):
                self.main_app_page.refresh_live()
            else:
                self.main_app_page.refresh()

    def add_log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.main_app_page.add_log(f"[{timestamp}] {message}")
