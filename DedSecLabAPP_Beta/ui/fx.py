"""DedSec visual effects: animated splash backdrop + app-wide click ripple."""
from __future__ import annotations

import math
import random

from PyQt6.QtCore import QObject, QEvent, QPointF, QRectF, Qt, QTimer, QElapsedTimer
from PyQt6.QtGui import QColor, QPainter, QPen, QBrush, QRadialGradient
from PyQt6.QtWidgets import QApplication, QWidget

CYAN = QColor("#2ee6ff")
CYAN_SOFT = QColor(46, 230, 255, 90)


class SplashFx(QWidget):
    """Transparent animated layer: pulsing rings, rotating arcs, drifting
    network nodes and a scan line. Sits behind the splash text/logo."""

    def __init__(self, parent: QWidget, center_y: float = 0.56):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self._cy = center_y
        self._clock = QElapsedTimer()
        self._clock.start()
        rnd = random.Random(7)
        self._nodes = [
            [rnd.uniform(0, 1), rnd.uniform(0, 1), rnd.uniform(-0.02, 0.02), rnd.uniform(-0.02, 0.02)]
            for _ in range(38)
        ]
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.update)
        self._timer.start(16)
        self.resize(parent.size())
        self.lower()

    def resizeEvent(self, e):  # keep full size
        super().resizeEvent(e)

    def paintEvent(self, _e):
        t = self._clock.elapsed() / 1000.0
        w, h = self.width(), self.height()
        cx, cy = w / 2.0, h * self._cy
        # Centre the rings on the logo itself when we can see it.
        mark = getattr(self.parent(), "_mark", None)
        try:
            pm = mark.pixmap() if mark is not None else None
            if pm is not None and not pm.isNull():
                ph_ = pm.height() / max(1.0, pm.devicePixelRatio())
                cy = mark.y() + ph_ / 2.0
                cx = mark.x() + mark.width() / 2.0
        except Exception:
            pass
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        fade = min(1.0, t / 0.6)
        # Soft glow behind logo, breathing
        glow_r = 150 + 12 * math.sin(t * 2.2)
        g = QRadialGradient(QPointF(cx, cy), glow_r)
        g.setColorAt(0.0, QColor(46, 230, 255, int(70 * fade)))
        g.setColorAt(1.0, QColor(46, 230, 255, 0))
        p.setBrush(QBrush(g))
        p.drawEllipse(QPointF(cx, cy), glow_r, glow_r)

        # Expanding pulse rings
        p.setBrush(Qt.BrushStyle.NoBrush)
        for k in range(3):
            ph = ((t * 0.55) + k / 3.0) % 1.0
            r = 70 + ph * 130
            a = int(170 * (1 - ph) * fade)
            p.setPen(QPen(QColor(46, 230, 255, a), 1.6))
            p.drawEllipse(QPointF(cx, cy), r, r)

        # Rotating HUD arcs
        for rad, speed, span, width in ((108, 90, 70, 2.4), (122, -60, 110, 1.4), (96, 140, 40, 1.2)):
            rect = QRectF(cx - rad, cy - rad, rad * 2, rad * 2)
            p.setPen(QPen(QColor(46, 230, 255, int(210 * fade)), width, cap=Qt.PenCapStyle.RoundCap))
            start = int((t * speed) % 360 * 16)
            p.drawArc(rect, start, int(span * 16))
            p.drawArc(rect, start + 180 * 16, int(span * 16))

        p.end()


class _RippleOverlay(QWidget):
    """One lightweight transparent child per top-level window. Draws small
    click rings; its timer only runs while a ripple is alive."""

    RADIUS = 14
    DURATION_MS = 320

    def __init__(self, top: QWidget):
        super().__init__(top)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setAttribute(Qt.WidgetAttribute.WA_NoSystemBackground, True)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._items: list = []  # (QPointF, QElapsedTimer)
        self._timer = QTimer(self)
        self._timer.setInterval(16)
        self._timer.timeout.connect(self._step)
        self.setGeometry(top.rect())
        self.hide()

    def add(self, pos: QPointF):
        top = self.parentWidget()
        if top is not None and self.geometry() != top.rect():
            self.setGeometry(top.rect())
        clk = QElapsedTimer()
        clk.start()
        self._items.append((pos, clk))
        if len(self._items) > 6:
            self._items = self._items[-6:]
        self.show()
        self.raise_()
        if not self._timer.isActive():
            self._timer.start()
        self.update(self._dirty(pos))

    def _dirty(self, pos):
        r = self.RADIUS + 4
        return QRectF(pos.x() - r, pos.y() - r, r * 2, r * 2).toAlignedRect()

    def _step(self):
        alive = []
        for pos, clk in self._items:
            self.update(self._dirty(pos))
            if clk.elapsed() < self.DURATION_MS:
                alive.append((pos, clk))
        self._items = alive
        if not alive:
            self._timer.stop()
            self.hide()

    def paintEvent(self, _e):
        if not self._items:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setBrush(Qt.BrushStyle.NoBrush)
        for pos, clk in self._items:
            ph = min(1.0, clk.elapsed() / self.DURATION_MS)
            ease = 1 - (1 - ph) ** 3
            a = int(220 * (1 - ph))
            p.setPen(QPen(QColor(46, 230, 255, a), 1.6))
            r = 3 + ease * (self.RADIUS - 3)
            p.drawEllipse(pos, r, r)
            if ph < 0.4:
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(QColor(46, 230, 255, int(180 * (1 - ph / 0.4))))
                p.drawEllipse(pos, 2.2, 2.2)
                p.setBrush(Qt.BrushStyle.NoBrush)
        p.end()


class ClickRippleFilter(QObject):
    """Install on QApplication: small cyan ring wherever the user clicks."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.enabled = True
        self._last = None

    def eventFilter(self, obj, event):
        if (
            self.enabled
            and event.type() == QEvent.Type.MouseButtonPress
            and isinstance(obj, QWidget)
            and not isinstance(obj, _RippleOverlay)
        ):
            try:
                key = int(event.timestamp())
                if key == self._last:
                    return False  # same click bubbling to parents
                self._last = key
                top = obj.window()
                if top is None or top.isHidden():
                    return False
                if top.windowType() in (Qt.WindowType.Popup, Qt.WindowType.ToolTip):
                    return False  # menus/combos: skip
                ov = getattr(top, "_dsl_ripple_overlay", None)
                if ov is None:
                    ov = _RippleOverlay(top)
                    top._dsl_ripple_overlay = ov
                gp = event.globalPosition().toPoint()
                ov.add(QPointF(top.mapFromGlobal(gp)))
            except Exception:
                pass
        return False


_FILTER = None


def install_click_ripple(app: QApplication) -> ClickRippleFilter:
    global _FILTER
    f = ClickRippleFilter(app)
    app.installEventFilter(f)
    app._dsl_click_fx = f
    _FILTER = f
    return f


def set_click_fx_enabled(on: bool) -> None:
    if _FILTER is not None:
        _FILTER.enabled = bool(on)
