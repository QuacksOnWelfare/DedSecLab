import random
from PyQt6.QtCore import Qt, QTimer, QRectF
from PyQt6.QtGui import (
    QColor,
    QPainter,
    QPen,
    QBrush,
    QFont,
)
from PyQt6.QtWidgets import QWidget


# =========================================================
# SOFT / LOW PROFILE COLORS
# =========================================================

SOFT_BLUE = "#7da6c2"
SOFT_GREEN = "#7fa98a"
SOFT_GRID = "#dbe4ec"
SOFT_BORDER = "#cfd8e3"
SOFT_BG = "#0f1720"
SOFT_TEXT = "#c8d2dc"


def _tq(color) -> QColor:
    """Colour for the active palette theme (Matrix, Crimson...); unchanged otherwise."""
    c = color if isinstance(color, QColor) else QColor(color)
    try:
        from ui.styles import theme_color
        out = theme_color(c.name())
        return c if out == c.name() else QColor(out)
    except Exception:
        return c


# =========================================================
# MINI GRAPH WIDGET
# Same API / same class / same methods
# =========================================================

class MiniGraphWidget(QWidget):
    def __init__(self, accent=SOFT_BLUE, max_points=32, parent=None):
        super().__init__(parent)

        self.accent = QColor(accent)
        self.max_points = max_points

        self.values = [
            random.randint(10, 60)
            for _ in range(max_points)
        ]

        # kept same sizing behavior
        self.setMinimumHeight(70)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.tick)

        # slightly calmer updates
        self.timer.start(1200)

    def tick(self):
        last = self.values[-1]

        new_value = max(
            5,
            min(
                95,
                last + random.randint(-8, 10)
            )
        )

        self.values.append(new_value)

        if len(self.values) > self.max_points:
            self.values.pop(0)

        self.update()

    def set_value(self, value):
        try:
            value = int(float(value))
        except Exception:
            return

        value = max(0, min(100, value))

        self.values.append(value)

        if len(self.values) > self.max_points:
            self.values.pop(0)

        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        acc = _tq(self.accent)

        painter.setRenderHint(
            QPainter.RenderHint.Antialiasing
        )

        rect = self.rect().adjusted(
            8,
            8,
            -8,
            -8
        )

        # subtle grid
        grid_pen = QPen(QColor(SOFT_GRID))
        grid_pen.setWidth(1)

        painter.setPen(grid_pen)

        for i in range(1, 4):
            y = rect.top() + rect.height() * i / 4

            painter.drawLine(
                rect.left(),
                int(y),
                rect.right(),
                int(y)
            )

        if len(self.values) < 2:
            return

        points = []

        step = rect.width() / (len(self.values) - 1)

        for i, value in enumerate(self.values):
            x = rect.left() + i * step

            y = rect.bottom() - (
                (value / 100) * rect.height()
            )

            points.append((x, y))

        # very subtle glow
        glow_pen = QPen(
            QColor(
                acc.red(),
                acc.green(),
                acc.blue(),
                20
            )
        )

        glow_pen.setWidth(2)

        painter.setPen(glow_pen)

        for i in range(len(points) - 1):
            painter.drawLine(
                int(points[i][0]),
                int(points[i][1]),
                int(points[i + 1][0]),
                int(points[i + 1][1])
            )

        # clean thin line
        line_pen = QPen(acc)
        line_pen.setWidth(1)

        painter.setPen(line_pen)

        for i in range(len(points) - 1):
            painter.drawLine(
                int(points[i][0]),
                int(points[i][1]),
                int(points[i + 1][0]),
                int(points[i + 1][1])
            )


# =========================================================
# STATUS RING WIDGET
# Same API / same class / same methods
# =========================================================

class StatusRingWidget(QWidget):
    def __init__(
        self,
        text="ONLINE",
        accent=SOFT_GREEN,
        parent=None
    ):
        super().__init__(parent)

        self.text = text
        self.accent = QColor(accent)

        self.angle = 0

        # preserved original size behavior
        self.setMinimumSize(120, 120)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.tick)

        # slower rotation = calmer
        self.timer.start(140)

    def tick(self):
        self.angle = (self.angle + 2) % 360
        self.update()

    _LIGHT_ACCENT = {
        "#ffcc33": "#8a5a00", "#50ff85": "#11733a", "#55c7ff": "#00707f",
        "#ff4d5f": "#b42334", "#ff9900": "#b45309", "#2ee6ff": "#00707f",
    }

    def set_light(self, light: bool):
        self._light = bool(light)
        self.update()

    def _accent(self):
        if getattr(self, "_light", False):
            return QColor(self._LIGHT_ACCENT.get(self.accent.name().lower(), self.accent.name()))
        return _tq(self.accent)

    def set_status(self, text, accent=None):
        self.text = text

        if accent:
            self.accent = QColor(accent)

        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        try:
            from ui.styles import current_theme
            self._light = current_theme() == "light"
        except Exception:
            pass
        light = getattr(self, "_light", False)
        acc = self._accent()

        painter.setRenderHint(
            QPainter.RenderHint.Antialiasing
        )

        size = min(
            self.width(),
            self.height()
        ) - 16

        x = (self.width() - size) / 2
        y = (self.height() - size) / 2

        rect = QRectF(x, y, size, size)

        # softer background
        painter.setBrush(
            QBrush(QColor("#ffffff") if light else _tq("#121b24"))
        )

        painter.setPen(
            QPen(QColor("#cfdde6" if light else SOFT_BORDER), 1)
        )

        painter.drawEllipse(rect)

        # subtle outer arc
        painter.setPen(
            QPen(
                QColor(
                    acc.red(),
                    acc.green(),
                    acc.blue(),
                    35
                ),
                4
            )
        )

        painter.drawArc(
            rect.adjusted(8, 8, -8, -8),
            self.angle * 16,
            110 * 16
        )

        # main arc
        painter.setPen(
            QPen(acc, 2)
        )

        painter.drawArc(
            rect.adjusted(12, 12, -12, -12),
            -self.angle * 16,
            180 * 16
        )

        # text
        painter.setPen(QColor("#0d1b2a" if light else SOFT_TEXT))

        painter.setFont(
            QFont(
                "Segoe UI",
                9,
                QFont.Weight.Normal
            )
        )

        painter.drawText(
            rect,
            Qt.AlignmentFlag.AlignCenter,
            self.text
        )


# =========================================================
# TRAFFIC BARS WIDGET
# Same API / same class
# =========================================================

class TrafficBarsWidget(QWidget):
    def __init__(
        self,
        accent=SOFT_GREEN,
        parent=None
    ):
        super().__init__(parent)

        self.accent = QColor(accent)

        self.values = [
            random.randint(10, 80)
            for _ in range(18)
        ]

        # preserved original sizing
        self.setMinimumHeight(70)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.tick)

        # calmer updates
        self.timer.start(950)

    def tick(self):
        self.values.append(
            random.randint(8, 90)
        )

        if len(self.values) > 18:
            self.values.pop(0)

        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        acc = _tq(self.accent)

        painter.setRenderHint(
            QPainter.RenderHint.Antialiasing
        )

        rect = self.rect().adjusted(
            8,
            8,
            -8,
            -8
        )

        count = len(self.values)

        if count == 0:
            return

        gap = 3

        bar_width = max(
            4,
            (
                rect.width()
                - gap * (count - 1)
            ) / count
        )

        for i, value in enumerate(self.values):

            height = rect.height() * (
                value / 100
            )

            x = rect.left() + i * (
                bar_width + gap
            )

            y = rect.bottom() - height

            painter.setBrush(
                QBrush(
                    QColor(
                        acc.red(),
                        acc.green(),
                        acc.blue(),
                        100
                    )
                )
            )

            painter.setPen(Qt.PenStyle.NoPen)

            painter.drawRoundedRect(
                QRectF(
                    x,
                    y,
                    bar_width,
                    height
                ),
                2,
                2
            )


# =========================================================
# CYBER DIVIDER
# SAME CLASS NAME = NO IMPORT BREAKS
# =========================================================

class CyberDivider(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setFixedHeight(2)

    def paintEvent(self, event):
        painter = QPainter(self)

        painter.setRenderHint(
            QPainter.RenderHint.Antialiasing
        )

        # soft subtle divider
        painter.setPen(
            QPen(
                QColor(SOFT_BORDER),
                1
            )
        )

        painter.drawLine(
            0,
            1,
            self.width(),
            1
        )

        # tiny accent line
        painter.setPen(
            QPen(
                QColor(SOFT_BLUE),
                1
            )
        )

        painter.drawLine(
            0,
            0,
            int(self.width() * 0.18),
            0
        )