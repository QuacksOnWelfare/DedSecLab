import sys
import time
from pathlib import Path
import traceback

from PyQt6.QtCore import QPropertyAnimation, QEasingCurve, Qt, QTimer
from PyQt6.QtWidgets import QApplication, QMessageBox, QLabel, QWidget, QVBoxLayout, QHBoxLayout
from PyQt6.QtGui import QIcon, QImage, QPalette, QColor, QPixmap


def _hero_qss(color="#2ee6ff", size=56, tracking=2):
    return (
        "background: transparent; border: none;"
        f"color: {color};"
        "font-family: 'Segoe UI';"
        f"font-size: {size}px;"
        "font-weight: 900;"
        f"letter-spacing: {tracking}px;"
    )


def _build_splash():
    splash = QWidget()
    # The splash is always dark: keep it out of the light-theme inline remap.
    splash.setProperty("dslThemeExempt", True)
    splash.setWindowFlags(
        Qt.WindowType.FramelessWindowHint
        | Qt.WindowType.Tool
        | Qt.WindowType.WindowStaysOnTopHint
    )
    splash.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
    splash.setAttribute(Qt.WidgetAttribute.WA_NoSystemBackground, True)
    splash.setStyleSheet("QWidget { background: transparent; }")
    splash.setFixedSize(1100, 580)
    lay = QVBoxLayout(splash)
    lay.setContentsMargins(12, 4, 12, 4)
    lay.setSpacing(0)
    hero_row = QHBoxLayout()
    hero_row.setSpacing(18)
    hero_row.setContentsMargins(0, 0, 0, 0)
    w1 = QLabel("WELCOME")
    w1.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
    w1.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
    w1.setStyleSheet(_hero_qss("#eef6ff", 64, 2))
    w2 = QLabel("TO")
    w2.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
    w2.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
    w2.setStyleSheet(_hero_qss("#2ee6ff", 64, 2))
    hero_row.addStretch()
    hero_row.addWidget(w1)
    hero_row.addWidget(w2)
    hero_row.addStretch()
    lay.addLayout(hero_row)
    lay.addSpacing(140)  # keep WELCOME TO clear of the animated rings
    mark = QLabel()
    mark.setAlignment(Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop)
    mark.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
    mark.setStyleSheet("background: transparent; border: none;")
    mark.setFixedHeight(230)
    lay.addWidget(mark)
    lay.addStretch(1)
    splash._mark = mark
    splash._w1, splash._w2 = w1, w2
    try:
        from ui.fx import SplashFx
        fx = SplashFx(splash)
        fx.setGeometry(0, 0, splash.width(), splash.height())
        fx.lower()
        splash._fx = fx
    except Exception:
        traceback.print_exc()
    return splash


def _load_logo(mark):
    pix = QPixmap()
    for p in (
        "assets/applogo.png",
        str(Path(__file__).resolve().parent / "assets" / "applogo.png"),
        "assets/dedsec_logo.png",
        "assets/dedsec_logo.ico",
    ):
        cand = QPixmap(p)
        if not cand.isNull():
            pix = cand
            break
    if pix.isNull():
        mark.setText("DedSecLab")
        mark.setStyleSheet("color:#2ee6ff;font-size:28px;font-weight:800;")
        return
    img = pix.toImage().convertToFormat(QImage.Format.Format_ARGB32)
    if img.width() > 700:
        img = img.scaledToWidth(700, Qt.TransformationMode.FastTransformation)
    w, h = img.width(), img.height()

    def dark(x, y):
        c = QColor(img.pixel(x, y))
        return c.alpha() > 0 and c.red() < 16 and c.green() < 16 and c.blue() < 16

    visited = bytearray(w * h)
    stack = []
    for x in range(w):
        stack.append((x, 0))
        stack.append((x, h - 1))
    for y in range(h):
        stack.append((0, y))
        stack.append((w - 1, y))
    while stack:
        x, y = stack.pop()
        if x < 0 or y < 0 or x >= w or y >= h:
            continue
        i = y * w + x
        if visited[i]:
            continue
        visited[i] = 1
        if not dark(x, y):
            continue
        img.setPixelColor(x, y, QColor(0, 0, 0, 0))
        stack.extend(((x + 1, y), (x - 1, y), (x, y + 1), (x, y - 1)))

    min_x, min_y, max_x, max_y = w, h, 0, 0
    for y in range(h):
        for x in range(w):
            if QColor(img.pixel(x, y)).alpha() > 20:
                min_x = min(min_x, x)
                min_y = min(min_y, y)
                max_x = max(max_x, x)
                max_y = max(max_y, y)
    if max_x > min_x and max_y > min_y:
        pad = 2
        img = img.copy(
            max(0, min_x - pad),
            max(0, min_y - pad),
            min(img.width(), max_x - min_x + pad * 2),
            min(img.height(), max_y - min_y + pad * 2),
        )
    mark.setPixmap(
        QPixmap.fromImage(img).scaled(
            220, 140,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
    )


def main():
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    app.setWindowIcon(QIcon("assets/dedsec_logo.ico"))
    try:
        from core.config import ConfigManager
        _cfg = ConfigManager.load() or {}
    except Exception:
        _cfg = {}
    try:
        from ui.fx import install_click_ripple
        pass  # click fx disabled (caused lag)
    except Exception:
        traceback.print_exc()
    show_splash = bool(_cfg.get("splash_enabled", True))

    splash = _build_splash()
    fade_in = QPropertyAnimation(splash, b"windowOpacity", splash)
    fade_in.setDuration(420)
    fade_in.setStartValue(0.0)
    fade_in.setEndValue(1.0)
    fade_in.setEasingCurve(QEasingCurve.Type.OutCubic)
    if show_splash:
        _load_logo(splash._mark)
        splash.setWindowOpacity(0.0)
        splash.show()
        splash.move(splash.screen().geometry().center() - splash.rect().center())
        fade_in.start()
    app.processEvents()

    from pages.single_instance import SingleInstance
    guard = SingleInstance(app)
    if guard.already_running():
        splash.close()
        guard.warn_and_raise()
        sys.exit(0)

    from main_window import MainWindow
    from ui.styles import apply_styles
    from core.config import REQUIRE_VPN_GATE
    from core.dedsec_vpn_gate import VpnGate

    app.setStyle("Fusion")
    # Palette + stylesheet now come from ui/styles.py using the saved theme
    # preference (Settings -> Appearance). "default" follows the OS scheme.
    apply_styles(app)
    app.processEvents()

    window = {"w": None}

    def show_lab(_server_id=None):
        try:
            old = window["w"]
            if old is not None:
                old.close()
                old.deleteLater()
                window["w"] = None
            w = MainWindow()
            blank = QPixmap(1, 1)
            blank.fill(Qt.GlobalColor.transparent)
            w.setWindowIcon(QIcon(blank))
            w.setWindowOpacity(0.0)
            w.show()
            fade = QPropertyAnimation(w, b"windowOpacity", w)
            fade.setDuration(450)
            fade.setStartValue(0.0)
            fade.setEndValue(1.0)
            fade.setEasingCurve(QEasingCurve.Type.OutCubic)
            fade.start()
            w._startup_fade = fade
            window["w"] = w
        except Exception as e:
            traceback.print_exc()
            QMessageBox.critical(None, "Lab crash", str(e))

    def hide_lab():
        w = window["w"]
        if w is not None:
            w.hide()

    def start_gate():
        try:
            gate = VpnGate()
        except Exception as e:
            traceback.print_exc()
            QMessageBox.critical(None, "VPN gate crash", str(e))
            app.quit()
            return
        gate.launch_lab.connect(show_lab)
        gate.lab_relaunch.connect(show_lab)
        gate.vpn_down.connect(hide_lab)
        gate.setWindowOpacity(0.0)
        gate.exec_gate()
        fade = QPropertyAnimation(gate, b"windowOpacity", gate)
        fade.setDuration(380)
        fade.setStartValue(0.0)
        fade.setEndValue(1.0)
        fade.setEasingCurve(QEasingCurve.Type.OutCubic)
        fade.start()
        gate._open_fade = fade
        app._gate = gate

    fade_out = QPropertyAnimation(splash, b"windowOpacity", splash)
    fade_out.setDuration(380)
    fade_out.setStartValue(1.0)
    fade_out.setEndValue(0.0)
    fade_out.setEasingCurve(QEasingCurve.Type.InCubic)
    def _after_splash():
        # default: REQUIRE_VPN_GATE=False -> open lab without VPN.
        # Set REQUIRE_VPN_GATE=True in core/config.py to restore VPN-locked flow.
        if REQUIRE_VPN_GATE:
            start_gate()
        else:
            show_lab()

    fade_out.finished.connect(splash.close)
    fade_out.finished.connect(_after_splash)

    if show_splash:
        fade_in.finished.connect(lambda: QTimer.singleShot(4500, fade_out.start))
        fade_in.start()
    else:
        fade_in.stop()
        splash.hide()
        splash.close()
        QTimer.singleShot(0, _after_splash)
    app._splash = splash
    app._splash_in = fade_in
    app._splash_out = fade_out

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
