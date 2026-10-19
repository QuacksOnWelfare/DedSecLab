import json
import re
import socket
import subprocess
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from core.tls import LabTLSError, http_get, http_post, http_put, verify_for
from core.winutil import ps_quote
from urllib.request import Request, urlopen

from pages.john_panel import JohnPanel
from pages.shodan_panel import ShodanPanel
from pages.ipcheck_panel import IpCheckPanel
from pages.geo_ip_panel import GeoIpPanel
from pages.tcp_monitor_panel import TcpMonitorPanel
from pages.macro_panel import MacroPanel
# CCTV removed: handled by separate standalone CCTV app
# from pages.cctv_page import CctvPage
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal, QRectF
from PyQt6.QtGui import QKeySequence, QShortcut, QPainter, QColor, QPen, QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QFrame, QMessageBox,
    QCheckBox, QComboBox, QScrollArea, QTabWidget,
    QSpinBox, QDoubleSpinBox, QKeySequenceEdit,
    QListWidget, QListWidgetItem, QProgressBar, QDialog, QLineEdit,
)
from ui.widgets import CyberDivider

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False


BUILTIN_PRESETS = {
    "Good Network": {
        "latency_enabled": False, "latency_ms": 20, "speed_enabled": False, "speed_kbps": 1000,
        "drop_enabled": False, "drop_pct": 0, "reorder_enabled": False, "reorder_pct": 0,
        "tamper_enabled": False, "tamper_pct": 0, "burst_enabled": False, "burst_ms": 0, "burst_pct": 0,
    },
    "Mobile 4G/5G": {
        "latency_enabled": True, "latency_ms": 60, "speed_enabled": True, "speed_kbps": 800,
        "drop_enabled": True, "drop_pct": 1.5, "reorder_enabled": True, "reorder_pct": 1,
        "tamper_enabled": False, "tamper_pct": 0, "burst_enabled": True, "burst_ms": 80, "burst_pct": 4,
    },
    "Poor Wi-Fi": {
        "latency_enabled": True, "latency_ms": 180, "speed_enabled": True, "speed_kbps": 250,
        "drop_enabled": True, "drop_pct": 8, "reorder_enabled": True, "reorder_pct": 6,
        "tamper_enabled": False, "tamper_pct": 0, "burst_enabled": True, "burst_ms": 250, "burst_pct": 12,
    },
    "Satellite / High Latency": {
        "latency_enabled": True, "latency_ms": 650, "speed_enabled": True, "speed_kbps": 400,
        "drop_enabled": True, "drop_pct": 3, "reorder_enabled": True, "reorder_pct": 4,
        "tamper_enabled": False, "tamper_pct": 0, "burst_enabled": True, "burst_ms": 400, "burst_pct": 10,
    },
    "Extreme Stress Test": {
        "latency_enabled": True, "latency_ms": 800, "speed_enabled": True, "speed_kbps": 80,
        "drop_enabled": True, "drop_pct": 35, "reorder_enabled": True, "reorder_pct": 40,
        "tamper_enabled": True, "tamper_pct": 15, "burst_enabled": True, "burst_ms": 600, "burst_pct": 30,
    },
    "DedSecLab Lag Module": {
        "latency_enabled": True, "latency_ms": 999, "speed_enabled": True, "speed_kbps": 115,
        "drop_enabled": True, "drop_pct": 90, "reorder_enabled": True, "reorder_pct": 90,
        "tamper_enabled": True, "tamper_pct": 90, "burst_enabled": True, "burst_ms": 999, "burst_pct": 90,
    },
}


class ProcessPickerDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Select app to bypass VPN")
        self.setMinimumSize(520, 420)
        self.resize(560, 480)
        self.selected_path = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)
        layout.addWidget(QLabel("Search, then double‑click an app (or Add selected)."))
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter by name...")
        self.search.setObjectName("EmulatorInput")
        self.search.textChanged.connect(self._filter)
        layout.addWidget(self.search)
        self.list = QListWidget()
        self.list.itemDoubleClicked.connect(self._accept_item)
        layout.addWidget(self.list, 1)
        row = QHBoxLayout()
        refresh = QPushButton("Refresh")
        refresh.setObjectName("ActionButton_blue")
        refresh.clicked.connect(self.load_processes)
        cancel = QPushButton("Cancel")
        cancel.setObjectName("ActionButton_red")
        cancel.clicked.connect(self.reject)
        add = QPushButton("Add selected")
        add.setObjectName("ActionButton_green")
        add.clicked.connect(self._accept_current)
        row.addWidget(refresh)
        row.addStretch()
        row.addWidget(cancel)
        row.addWidget(add)
        layout.addLayout(row)
        self._all_rows = []
        self.load_processes()

    def load_processes(self):
        self._all_rows = []
        seen = set()
        if PSUTIL_OK:
            for proc in psutil.process_iter(["name", "exe"]):
                try:
                    exe = proc.info.get("exe") or ""
                    name = proc.info.get("name") or ""
                    if not exe or not name:
                        continue
                    key = exe.lower()
                    if key in seen:
                        continue
                    seen.add(key)
                    self._all_rows.append((name.lower(), f"{name}    {exe}", exe))
                except (psutil.Error, OSError):
                    continue
        else:
            try:
                r = subprocess.run(
                    ["tasklist", "/FO", "CSV", "/NH"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
                )
                for line in (r.stdout or "").splitlines():
                    parts = [p.strip().strip('"') for p in line.split(",")]
                    if parts and parts[0].lower() not in seen:
                        seen.add(parts[0].lower())
                        self._all_rows.append((parts[0].lower(), parts[0], parts[0]))
            except Exception:
                pass
        self._all_rows.sort()
        self._filter(self.search.text())

    def _filter(self, text: str):
        q = (text or "").strip().lower()
        self.list.clear()
        for name_l, display, path in self._all_rows:
            if q and q not in name_l and q not in path.lower():
                continue
            item = QListWidgetItem(display)
            item.setData(Qt.ItemDataRole.UserRole, path)
            self.list.addItem(item)

    def _accept_item(self, item: QListWidgetItem):
        self.selected_path = item.data(Qt.ItemDataRole.UserRole)
        self.accept()

    def _accept_current(self):
        item = self.list.currentItem()
        if not item:
            QMessageBox.information(self, "Select app", "Pick a process first.")
            return
        self.selected_path = item.data(Qt.ItemDataRole.UserRole)
        self.accept()


class SpeedGauge(QWidget):
    def __init__(self, title: str, unit: str, accent: str = "#55c7ff", max_value: float = 100):
        super().__init__()
        self.title = title
        self.unit = unit
        self.accent = QColor(accent)
        self.max_value = max(max_value, 1)
        self._value = 0.0
        self._display = "--"
        self.setMinimumSize(140, 150)

    def set_reading(self, value: float | None, display: str | None = None):
        if value is None:
            self._value = 0
            self._display = "--"
        else:
            self._value = float(value)
            self._display = display if display is not None else f"{value:.0f}"
        self.update()

    def paintEvent(self, _event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        side = min(w, h - 36)
        cx, cy = w / 2, h / 2 - 8
        radius = side / 2 - 8
        rect = QRectF(cx - radius, cy - radius, radius * 2, radius * 2)
        pen = QPen(QColor(40, 48, 60), 10)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(pen)
        p.drawArc(rect, 225 * 16, -270 * 16)
        frac = max(0.0, min(1.0, self._value / self.max_value))
        pen = QPen(self.accent, 10)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(pen)
        p.drawArc(rect, 225 * 16, int(-270 * 16 * frac))
        p.setPen(QColor("#e8f0ff"))
        p.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        p.drawText(QRectF(0, cy - 18, w, 28), Qt.AlignmentFlag.AlignCenter, self._display)
        p.setPen(QColor("#7d98b6"))
        p.setFont(QFont("Segoe UI", 9))
        p.drawText(QRectF(0, cy + 12, w, 18), Qt.AlignmentFlag.AlignCenter, self.unit)
        p.setPen(self.accent)
        p.setFont(QFont("Segoe UI", 10, QFont.Weight.DemiBold))
        p.drawText(QRectF(0, h - 22, w, 18), Qt.AlignmentFlag.AlignCenter, self.title)
        p.end()


class SpeedTestWorker(QThread):
    progress = pyqtSignal(str)
    finished_ok = pyqtSignal(dict)
    finished_err = pyqtSignal(str)

    DOWN_BYTES = 25_000_000
    DOWN_STREAMS = 4
    UP_BYTES = 8 * 1024 * 1024

    def run(self):
        try:
            result = {
                "ping_ms": None, "download_mbps": None, "upload_mbps": None,
                "ip": None, "city": None, "region": None, "country": None,
                "isp": None, "org": None,
            }
            self.progress.emit("Resolving public IP...")
            result["ip"] = self._public_ip()
            self.progress.emit("Looking up location...")
            self._fill_geo(result)
            self.progress.emit("Measuring ping...")
            result["ping_ms"] = self._ping_ms()
            self.progress.emit("Warm-up...")
            try:
                urlopen(Request(
                    "https://speed.cloudflare.com/__down?bytes=100000",
                    headers={"User-Agent": "DedSecLab"},
                ), timeout=15).read()
            except Exception:
                pass
            self.progress.emit("Measuring download (multi-stream)...")
            result["download_mbps"] = self._download_mbps()
            self.progress.emit("Measuring upload...")
            result["upload_mbps"] = self._upload_mbps()
            self.finished_ok.emit(result)
        except Exception as e:
            self.finished_err.emit(f"{e}\n{traceback.format_exc()[-400:]}")

    def _public_ip(self) -> str:
        for url in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
            try:
                return urlopen(Request(url, headers={"User-Agent": "DedSecLab"}), timeout=8).read().decode().strip()
            except Exception:
                continue
        return "Unknown"

    def _fill_geo(self, result: dict):
        try:
            geo = json.loads(urlopen(Request(
                f"http://ip-api.com/json/{result['ip']}?fields=status,country,regionName,city,isp,org",
                headers={"User-Agent": "DedSecLab"},
            ), timeout=8).read().decode())
            if geo.get("status") == "success":
                result["city"] = geo.get("city")
                result["region"] = geo.get("regionName")
                result["country"] = geo.get("country")
                result["isp"] = geo.get("isp")
                result["org"] = geo.get("org")
        except Exception:
            pass

    def _ping_ms(self):
        try:
            r = subprocess.run(
                ["ping", "-n", "6", "1.1.1.1"],
                capture_output=True, text=True, timeout=20,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            out = r.stdout or ""
            m = re.search(r"Average\s*=\s*(\d+)\s*ms", out, re.I)
            if m:
                return float(m.group(1))
            times = [int(t) for t in re.findall(r"time[=<](\d+)\s*ms", out, re.I)]
            if times:
                times = times[1:] or times
                return sum(times) / len(times)
        except Exception:
            pass
        try:
            samples = []
            for _ in range(5):
                t0 = time.perf_counter()
                s = socket.create_connection(("1.1.1.1", 443), timeout=3)
                s.close()
                samples.append((time.perf_counter() - t0) * 1000)
            return sum(samples[1:]) / max(len(samples) - 1, 1)
        except Exception:
            return None

    def _one_download(self, bytes_n: int) -> tuple[int, float]:
        url = f"https://speed.cloudflare.com/__down?bytes={bytes_n}"
        t0 = time.perf_counter()
        data = urlopen(Request(url, headers={"User-Agent": "DedSecLab"}), timeout=60).read()
        dt = time.perf_counter() - t0
        return len(data), dt

    def _download_mbps(self):
        total_bytes = 0
        t0 = time.perf_counter()
        try:
            with ThreadPoolExecutor(max_workers=self.DOWN_STREAMS) as pool:
                futs = [pool.submit(self._one_download, self.DOWN_BYTES) for _ in range(self.DOWN_STREAMS)]
                for f in as_completed(futs):
                    try:
                        n, _ = f.result()
                        total_bytes += n
                    except Exception:
                        pass
            dt = time.perf_counter() - t0
            if dt <= 0 or total_bytes < 1_000_000:
                return None
            return (total_bytes * 8) / dt / 1_000_000
        except Exception:
            try:
                n, dt = self._one_download(15_000_000)
                if dt > 0 and n:
                    return (n * 8) / dt / 1_000_000
            except Exception:
                return None
        return None

    def _upload_mbps(self):
        payload = b"0" * self.UP_BYTES
        for url in ("https://speed.cloudflare.com/__up",):
            try:
                t0 = time.perf_counter()
                req = Request(
                    url, data=payload,
                    headers={"User-Agent": "DedSecLab", "Content-Type": "application/octet-stream"},
                    method="POST",
                )
                urlopen(req, timeout=90).read()
                dt = time.perf_counter() - t0
                if dt > 0:
                    return (len(payload) * 8) / dt / 1_000_000
            except Exception:
                continue
        try:
            payload = b"0" * (2 * 1024 * 1024)
            t0 = time.perf_counter()
            req = Request(
                "https://httpbin.org/post", data=payload,
                headers={"User-Agent": "DedSecLab", "Content-Type": "application/octet-stream"},
                method="POST",
            )
            urlopen(req, timeout=60).read()
            dt = time.perf_counter() - t0
            if dt > 0:
                return (len(payload) * 8) / dt / 1_000_000
        except Exception:
            pass
        return None


class ImpairmentCard(QFrame):
    def __init__(self, title: str, color: str = "#55c7ff"):
        super().__init__()
        self.setObjectName("ActionsPanel")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(8)
        header = QHBoxLayout()
        self.checkbox = QCheckBox(title)
        self.checkbox.setObjectName("EmulatorCheck")
        self.checkbox.setStyleSheet(f"color: {color}; font-weight: 600;")
        header.addWidget(self.checkbox)
        header.addStretch()
        layout.addLayout(header)
        self.fields_layout = QHBoxLayout()
        self.fields_layout.setSpacing(16)
        layout.addLayout(self.fields_layout)
        self._inputs = {}

    def add_field(self, label: str, key: str, default, suffix: str = "", is_float=False):
        col = QVBoxLayout()
        col.setSpacing(3)
        lbl = QLabel(label)
        lbl.setObjectName("EmulatorFieldLabel")
        col.addWidget(lbl)
        row = QHBoxLayout()
        if is_float:
            spin = QDoubleSpinBox()
            spin.setRange(0, 9999)
            spin.setDecimals(1)
            spin.setValue(float(default))
        else:
            spin = QSpinBox()
            spin.setRange(0, 9999)
            spin.setValue(int(default))
        spin.setObjectName("EmulatorInput")
        spin.setFixedWidth(90)
        spin.setAlignment(Qt.AlignmentFlag.AlignCenter)
        row.addWidget(spin)
        if suffix:
            row.addWidget(QLabel(suffix))
        row.addStretch()
        col.addLayout(row)
        self.fields_layout.addLayout(col)
        self._inputs[key] = spin

    def is_enabled(self):
        return self.checkbox.isChecked()

    def set_enabled(self, val: bool):
        self.checkbox.setChecked(val)

    def get_value(self, key):
        return self._inputs[key].value()

    def set_value(self, key, value):
        if key in self._inputs:
            self._inputs[key].setValue(value)


class LiveStatsBar(QFrame):
    def __init__(self):
        super().__init__()
        self.setObjectName("ActionsPanel")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 10, 16, 10)
        layout.setSpacing(18)
        self.labels = {}
        for title, key in [
            ("State", "state"), ("VPN IP", "vpn_ip"), ("Interface", "iface"),
            ("Delay", "delay"), ("Loss", "loss"), ("Rate", "rate"),
        ]:
            col = QVBoxLayout()
            t = QLabel(title.upper())
            t.setObjectName("EmulatorFieldLabel")
            t.setAlignment(Qt.AlignmentFlag.AlignCenter)
            v = QLabel("--")
            v.setStyleSheet("font-size: 14px; font-weight: 700;")
            v.setAlignment(Qt.AlignmentFlag.AlignCenter)
            col.addWidget(t)
            col.addWidget(v)
            layout.addLayout(col)
            self.labels[key] = v
        layout.addStretch()

    def set_idle(self):
        for k, d in [("state", "IDLE"), ("vpn_ip", "--"), ("iface", "tun0"),
                     ("delay", "--"), ("loss", "--"), ("rate", "--")]:
            self.labels[k].setText(d)

    def set_active(self, data: dict):
        cfg = data.get("config") or {}
        self.labels["state"].setText("ACTIVE")
        self.labels["vpn_ip"].setText(str(data.get("vpn_ip", "--")))
        self.labels["iface"].setText(str(data.get("iface", "tun0")))
        self.labels["delay"].setText(f"{cfg.get('delay_ms', 0)}ms")
        self.labels["loss"].setText(f"{cfg.get('loss_pct', 0)}%")
        rate = cfg.get("rate_kb") or 0
        self.labels["rate"].setText(f"{rate} KB/s" if rate else "Unlimited")


class NetworkTestingPanel(QFrame):
    def __init__(self, app_window, on_log=None):
        super().__init__()
        self.setObjectName("ActionsPanel")
        self.app_window = app_window
        self._on_log = on_log
        self._active = False
        self._shortcut = None
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(12)
        header = QHBoxLayout()
        title = QLabel("NETWORK IMPAIRMENT ENGINE")
        title.setObjectName("ActionsPanelTitle")
        self.status_badge = QLabel("● IDLE")
        self.status_badge.setObjectName("ActionsLiveBadge")
        header.addWidget(title)
        header.addStretch()
        header.addWidget(self.status_badge)
        root.addLayout(header)
        self.hotkey_hint = QLabel("Hotkey: SPACE - Start / Stop")
        self.hotkey_hint.setObjectName("ActionsHeroDetail")
        root.addWidget(self.hotkey_hint)
        controls = QHBoxLayout()
        filter_box = QVBoxLayout()
        fl = QLabel("DIRECTION")
        fl.setObjectName("EmulatorSectionLabel")
        self.filter_combo = QComboBox()
        self.filter_combo.setObjectName("EmulatorCombo")
        self.filter_combo.addItems(["both", "inbound", "outbound"])
        filter_box.addWidget(fl)
        filter_box.addWidget(self.filter_combo)
        controls.addLayout(filter_box)
        preset_box = QVBoxLayout()
        pl = QLabel("PRESET")
        pl.setObjectName("EmulatorSectionLabel")
        self.preset_combo = QComboBox()
        self.preset_combo.setObjectName("EmulatorCombo")
        self.preset_combo.addItem("- Custom -")
        for name in BUILTIN_PRESETS:
            self.preset_combo.addItem(name)
        self.preset_combo.currentIndexChanged.connect(self._apply_preset)
        preset_box.addWidget(pl)
        preset_box.addWidget(self.preset_combo)
        controls.addLayout(preset_box, 1)
        root.addLayout(controls)
        hotkey_row = QHBoxLayout()
        hk_lbl = QLabel("START / STOP HOTKEY")
        hk_lbl.setObjectName("EmulatorSectionLabel")
        self.hotkey_edit = QKeySequenceEdit(QKeySequence(Qt.Key.Key_Space))
        self.hotkey_edit.setMaximumWidth(180)
        self.hotkey_edit.keySequenceChanged.connect(self._on_hotkey_changed)
        hotkey_row.addWidget(hk_lbl)
        hotkey_row.addWidget(self.hotkey_edit)
        hotkey_row.addStretch()
        root.addLayout(hotkey_row)
        root.addWidget(CyberDivider())
        self.latency_card = ImpairmentCard("LATENCY", "#55c7ff")
        self.latency_card.add_field("Delay", "latency_ms", 100, "ms")
        self.speed_card = ImpairmentCard("SPEED LIMIT", "#50ff85")
        self.speed_card.add_field("Max Speed", "speed_kbps", 500, "KB/s", is_float=True)
        self.drop_card = ImpairmentCard("PACKET LOSS", "#ff5555")
        self.drop_card.add_field("Drop Rate", "drop_pct", 5, "%", is_float=True)
        self.reorder_card = ImpairmentCard("REORDER", "#ffcc33")
        self.reorder_card.add_field("Chance", "reorder_pct", 5, "%", is_float=True)
        self.tamper_card = ImpairmentCard("PACKET CORRUPTION", "#ff8833")
        self.tamper_card.add_field("Chance", "tamper_pct", 2, "%", is_float=True)
        self.burst_card = ImpairmentCard("BURST / JITTER", "#b86cff")
        self.burst_card.add_field("Jitter", "burst_ms", 50, "ms")
        self.burst_card.add_field("Chance", "burst_pct", 10, "%", is_float=True)
        grid = QGridLayout()
        grid.setSpacing(10)
        grid.addWidget(self.latency_card, 0, 0)
        grid.addWidget(self.speed_card, 0, 1)
        grid.addWidget(self.drop_card, 1, 0)
        grid.addWidget(self.reorder_card, 1, 1)
        grid.addWidget(self.tamper_card, 2, 0)
        grid.addWidget(self.burst_card, 2, 1)
        root.addLayout(grid)
        root.addWidget(CyberDivider())
        self.stats_bar = LiveStatsBar()
        root.addWidget(self.stats_bar)
        btn_wrap = QHBoxLayout()
        btn_wrap.addStretch(1)
        self.toggle_btn = QPushButton("▶  START ENGINE")
        self.toggle_btn.setFixedHeight(36)
        self.toggle_btn.setMinimumWidth(180)
        self.toggle_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.toggle_btn.clicked.connect(self.toggle_engine)
        self._apply_toggle_style(False)
        btn_wrap.addWidget(self.toggle_btn)
        btn_wrap.addStretch(1)
        root.addLayout(btn_wrap)
        self._poll = QTimer(self)
        self._poll.setInterval(3000)
        self._poll.timeout.connect(self.refresh_status)
        self._install_shortcut(QKeySequence(Qt.Key.Key_Space))
        idx = self.preset_combo.findText("DedSecLab Lag Module")
        if idx >= 0:
            self.preset_combo.setCurrentIndex(idx)

    def _apply_toggle_style(self, active: bool):
        if active:
            self.toggle_btn.setStyleSheet(
                "QPushButton{background:rgba(80,20,28,.85);color:#ff6b6b;border:1px solid rgba(255,85,85,.35);"
                "border-radius:12px;font-size:13px;font-weight:600;padding:8px 20px;}"
            )
        else:
            self.toggle_btn.setStyleSheet(
                "QPushButton{background:rgba(28,36,48,.95);color:#c8d0dc;border:1px solid rgba(85,199,255,.22);"
                "border-radius:12px;font-size:13px;font-weight:600;padding:8px 20px;}"
                "QPushButton:hover{color:#55c7ff;border:1px solid rgba(85,199,255,.45);}"
            )

    def _on_hotkey_changed(self, seq):
        self._install_shortcut(seq)

    def _install_shortcut(self, seq):
        if self._shortcut:
            self._shortcut.setEnabled(False)
            self._shortcut.deleteLater()
            self._shortcut = None
        if not seq or seq.isEmpty():
            self.hotkey_hint.setText("Hotkey: (none)")
            self._update_toggle_btn()
            return
        self._shortcut = QShortcut(seq, self)
        self._shortcut.setContext(Qt.ShortcutContext.ApplicationShortcut)
        self._shortcut.activated.connect(self.toggle_engine)
        self.hotkey_hint.setText(f"Hotkey: {seq.toString(QKeySequence.SequenceFormat.NativeText)} - Start / Stop")
        self._update_toggle_btn()

    def _update_toggle_btn(self):
        key = self._shortcut.key().toString(QKeySequence.SequenceFormat.NativeText) if self._shortcut else ""
        if self._active:
            self.toggle_btn.setText(f"■  STOP ENGINE   [{key}]" if key else "■  STOP ENGINE")
            self._apply_toggle_style(True)
        else:
            self.toggle_btn.setText(f"▶  START ENGINE   [{key}]" if key else "▶  START ENGINE")
            self._apply_toggle_style(False)

    def _api(self, method, path, json_body=None):
        server = self.app_window.server
        if method == "GET" and hasattr(server, "get"):
            try:
                return server.get(path)
            except TypeError:
                pass
        if method == "POST" and hasattr(server, "post"):
            try:
                return server.post(path, json_body)
            except TypeError:
                try:
                    return server.post(path, json=json_body)
                except Exception:
                    pass
        import requests
        base = str(
            getattr(server, "base_url", None)
            or getattr(server, "url", None)
            or getattr(server, "api_url", None)
            or getattr(server, "host", "https://YOUR_LAB_VPN_IP:8443")
        ).rstrip("/")
        url = f"{base}{path}"
        try:
            r = http_get(url, timeout=8) if method == "GET" else http_post(
                url, json=json_body or {}, timeout=12
            )
        except LabTLSError as e:
            return {"ok": False, "reason": str(e)}
        try:
            return r.json()
        except Exception:
            return {"ok": False, "reason": r.text[:200]}

    def _log(self, msg):
        if self._on_log:
            self._on_log(msg)

    def _set_badge(self, text, color):
        self.status_badge.setText(f"● {text}")
        self.status_badge.setStyleSheet(f"color: {color};")

    def _apply_preset(self, index):
        if index <= 0:
            return
        p = BUILTIN_PRESETS.get(self.preset_combo.currentText())
        if not p:
            return
        self.latency_card.set_enabled(p["latency_enabled"])
        self.latency_card.set_value("latency_ms", p["latency_ms"])
        self.speed_card.set_enabled(p["speed_enabled"])
        self.speed_card.set_value("speed_kbps", p["speed_kbps"])
        self.drop_card.set_enabled(p["drop_enabled"])
        self.drop_card.set_value("drop_pct", p["drop_pct"])
        self.reorder_card.set_enabled(p["reorder_enabled"])
        self.reorder_card.set_value("reorder_pct", p["reorder_pct"])
        self.tamper_card.set_enabled(p["tamper_enabled"])
        self.tamper_card.set_value("tamper_pct", p["tamper_pct"])
        self.burst_card.set_enabled(p["burst_enabled"])
        self.burst_card.set_value("burst_ms", p["burst_ms"])
        self.burst_card.set_value("burst_pct", p["burst_pct"])

    def _collect_payload(self):
        direction = self.filter_combo.currentText()
        if direction == "inbound":
            direction = "in"
        elif direction == "outbound":
            direction = "out"
        return {
            "delay_ms": int(self.latency_card.get_value("latency_ms")),
            "jitter_ms": int(self.burst_card.get_value("burst_ms")),
            "loss_pct": float(self.drop_card.get_value("drop_pct")),
            "corrupt_pct": float(self.tamper_card.get_value("tamper_pct")),
            "reorder_pct": float(self.reorder_card.get_value("reorder_pct")),
            "rate_kb": float(self.speed_card.get_value("speed_kbps")),
            "direction": direction,
            "preset": self.preset_combo.currentText() if self.preset_combo.currentIndex() > 0 else "",
            "enabled": {
                "latency": self.latency_card.is_enabled(), "jitter": self.burst_card.is_enabled(),
                "loss": self.drop_card.is_enabled(), "corrupt": self.tamper_card.is_enabled(),
                "reorder": self.reorder_card.is_enabled(), "speed": self.speed_card.is_enabled(),
            },
        }

    def start_engine(self):
        self._set_badge("STARTING...", "#ffcc33")
        try:
            data = self._api("POST", "/api/net-emulate/start", self._collect_payload())
        except Exception as e:
            self._set_badge("ERROR", "#ff5555")
            QMessageBox.warning(self, "Start Failed", str(e))
            return
        if not data or not data.get("ok"):
            self._set_badge("ERROR", "#ff5555")
            QMessageBox.warning(self, "Start Failed", str((data or {}).get("reason", "Unknown")))
            return
        self._active = True
        self._update_toggle_btn()
        self._set_badge("ACTIVE", "#50ff85")
        self.stats_bar.set_active(data)
        self._poll.start()
        self._log(f"Impairment started on {data.get('vpn_ip')}")

    def stop_engine(self):
        self._set_badge("STOPPING...", "#ffcc33")
        try:
            self._api("POST", "/api/net-emulate/stop")
        except Exception as e:
            self._set_badge("ERROR", "#ff5555")
            QMessageBox.warning(self, "Stop Failed", str(e))
            return
        self._active = False
        self._update_toggle_btn()
        self._set_badge("IDLE", "#888888")
        self.stats_bar.set_idle()
        self._poll.stop()
        self._log("Impairment stopped")

    def toggle_engine(self):
        if self._active:
            self.stop_engine()
        else:
            self.start_engine()

    def refresh_status(self):
        try:
            data = self._api("GET", "/api/net-emulate/status")
        except Exception:
            return
        if not data or not data.get("ok"):
            return
        if data.get("active"):
            self._active = True
            self._update_toggle_btn()
            self._set_badge("ACTIVE", "#50ff85")
            self.stats_bar.set_active(data)
            if not self._poll.isActive():
                self._poll.start()
        else:
            self._active = False
            self._update_toggle_btn()
            self._set_badge("IDLE", "#888888")
            self.stats_bar.set_idle()
            self._poll.stop()


class NetworkingPage(QWidget):
    def __init__(self, app_window):
        super().__init__()
        self.app_window = app_window
        self._speed_worker = None
        self._whitelist = []

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 14)
        root.setSpacing(12)

        header = QHBoxLayout()
        title_box = QVBoxLayout()
        title_box.setSpacing(3)
        title = QLabel("NETWORKING")
        title.setObjectName("PageTitle")
        subtitle = QLabel("Speed test • App VPN bypass • Console sharing • Lag • Tools")
        subtitle.setObjectName("StatusLine")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        self.network_badge = QLabel("● Ready")
        self.network_badge.setObjectName("ActionsLiveBadge")
        header.addLayout(title_box)
        header.addStretch()
        header.addWidget(self.network_badge)
        root.addLayout(header)

        self.tabs = QTabWidget()
        self.tabs.setObjectName("NetworkTabs")

        tools_tab = QWidget()
        tools_outer = QVBoxLayout(tools_tab)
        tools_outer.setContentsMargins(0, 10, 0, 0)
        tools_scroll = QScrollArea()
        tools_scroll.setWidgetResizable(True)
        tools_scroll.setFrameShape(QFrame.Shape.NoFrame)
        tools_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        tools_inner = QWidget()
        tools_layout = QVBoxLayout(tools_inner)
        tools_layout.setContentsMargins(0, 0, 8, 8)
        tools_layout.setSpacing(14)

        speed = QFrame()
        speed.setObjectName("ActionsPanel")
        sp = QVBoxLayout(speed)
        sp.setContentsMargins(16, 14, 16, 14)
        sp.setSpacing(10)
        sh = QHBoxLayout()
        st = QLabel("CONNECTION SPEED TEST")
        st.setObjectName("ActionsPanelTitle")
        self.speed_status = QLabel("● Idle")
        self.speed_status.setObjectName("ActionsLiveBadge")
        sh.addWidget(st)
        sh.addStretch()
        sh.addWidget(self.speed_status)
        sp.addLayout(sh)
        gauges = QHBoxLayout()
        self.gauge_ping = SpeedGauge("PING", "ms", "#55c7ff", 200)
        self.gauge_down = SpeedGauge("DOWNLOAD", "Mbps", "#50ff85", 500)
        self.gauge_up = SpeedGauge("UPLOAD", "Mbps", "#b86cff", 100)
        gauges.addWidget(self.gauge_ping)
        gauges.addWidget(self.gauge_down)
        gauges.addWidget(self.gauge_up)
        sp.addLayout(gauges)
        info_row = QHBoxLayout()
        self.ip_label = QLabel("IP: -")
        self.ip_label.setObjectName("ActionsHeroState")
        self.loc_label = QLabel("Location: -")
        self.loc_label.setObjectName("ActionsHeroDetail")
        self.isp_label = QLabel("ISP: -")
        self.isp_label.setObjectName("ActionsHeroDetail")
        info_row.addWidget(self.ip_label)
        info_row.addWidget(self.loc_label, 1)
        info_row.addWidget(self.isp_label, 1)
        sp.addLayout(info_row)
        self.speed_progress = QProgressBar()
        self.speed_progress.setRange(0, 0)
        self.speed_progress.setVisible(False)
        self.speed_progress.setFixedHeight(6)
        sp.addWidget(self.speed_progress)
        note = QLabel("Uses multi-stream Cloudflare samples (closer to real tests; still not identical to Ookla).")
        note.setObjectName("ActionsHeroDetail")
        note.setWordWrap(True)
        sp.addWidget(note)
        sb = QHBoxLayout()
        self.speed_btn = QPushButton("▶  Run Speed Test")
        self.speed_btn.setObjectName("ActionButton_cyan")
        self.speed_btn.setMinimumHeight(36)
        self.speed_btn.clicked.connect(self.run_speed_test)
        sb.addStretch()
        sb.addWidget(self.speed_btn)
        sb.addStretch()
        sp.addLayout(sb)
        tools_layout.addWidget(speed)

        wl = QFrame()
        wl.setObjectName("ActionsPanel")
        wll = QVBoxLayout(wl)
        wll.setContentsMargins(16, 14, 16, 14)
        wll.setSpacing(8)
        wt = QLabel("VPN APP BYPASS")
        wt.setObjectName("ActionsPanelTitle")
        wll.addWidget(wt)
        wll.addWidget(QLabel(
            "Add apps that should try to skip the VPN. Apply rules as Administrator."
        ))
        self.wl_list = QListWidget()
        self.wl_list.setMaximumHeight(100)
        self.wl_list.setMinimumHeight(64)
        wll.addWidget(self.wl_list)
        wb = QHBoxLayout()
        self.wl_add_btn = QPushButton("＋  Add app...")
        self.wl_add_btn.setObjectName("ActionButton_green")
        self.wl_add_btn.clicked.connect(self.whitelist_add_dialog)
        self.wl_remove_btn = QPushButton("Remove")
        self.wl_remove_btn.setObjectName("ActionButton_red")
        self.wl_remove_btn.clicked.connect(self.whitelist_remove)
        self.wl_apply_btn = QPushButton("Apply rules")
        self.wl_apply_btn.setObjectName("ActionButton_cyan")
        self.wl_apply_btn.clicked.connect(self.apply_whitelist_rules)
        self.wl_clear_btn = QPushButton("Clear rules")
        self.wl_clear_btn.setObjectName("ActionButton_blue")
        self.wl_clear_btn.clicked.connect(self.clear_whitelist_rules)
        wb.addWidget(self.wl_add_btn)
        wb.addWidget(self.wl_remove_btn)
        wb.addWidget(self.wl_apply_btn)
        wb.addWidget(self.wl_clear_btn)
        wb.addStretch()
        wll.addLayout(wb)
        tools_layout.addWidget(wl)

        tools_row = QHBoxLayout()
        tools_row.setSpacing(12)
        reset = QFrame()
        reset.setObjectName("ActionsPanel")
        rl = QVBoxLayout(reset)
        rl.setContentsMargins(14, 12, 14, 12)
        rl.setSpacing(8)
        rt = QLabel("QUICK TOOLS")
        rt.setObjectName("ActionsPanelTitle")
        rb = QHBoxLayout()
        self.flush_btn = QPushButton("Flush DNS")
        self.flush_btn.setObjectName("ActionButton_blue")
        self.flush_btn.clicked.connect(self.flush_dns)
        self.adapters_btn = QPushButton("Adapters")
        self.adapters_btn.setObjectName("ActionButton_cyan")
        self.adapters_btn.clicked.connect(self.open_adapters)
        self.steps_btn = QPushButton("Console share steps")
        self.steps_btn.setObjectName("ActionButton_green")
        self.steps_btn.clicked.connect(self.show_share_steps)
        rb.addWidget(self.flush_btn)
        rb.addWidget(self.adapters_btn)
        rb.addWidget(self.steps_btn)
        rb.addStretch()
        rl.addWidget(rt)
        rl.addLayout(rb)
        tools_row.addWidget(reset)
        tools_layout.addLayout(tools_row)
        tools_layout.addStretch()

        tools_scroll.setWidget(tools_inner)
        tools_outer.addWidget(tools_scroll)
        self.tabs.addTab(tools_tab, "  Network Tools  ")

        testing_tab = QWidget()
        testing_layout = QVBoxLayout(testing_tab)
        testing_layout.setContentsMargins(0, 8, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.testing_panel = NetworkTestingPanel(app_window, on_log=self._testing_log)
        scroll.setWidget(self.testing_panel)
        testing_layout.addWidget(scroll)
        self.tabs.addTab(testing_tab, "  Lag Switch  ")

        self.tabs.addTab(MacroPanel(app_window), "  Macros  ")

        for name, cls, attr in (
            ("Password Cracker", JohnPanel, "john_panel"),
            ("Shodan", ShodanPanel, "shodan_panel"),
            ("Surveillance", IpCheckPanel, "ipcheck_panel"),
            ("IP Lookup ", GeoIpPanel, "geo_panel"),
            ("TCP Connections", TcpMonitorPanel, "tcp_monitor_panel"),
        ):
            tab = QWidget()
            lay = QVBoxLayout(tab)
            lay.setContentsMargins(0, 8, 0, 0)
            sc = QScrollArea()
            sc.setWidgetResizable(True)
            sc.setFrameShape(QFrame.Shape.NoFrame)
            sc.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
            panel = cls(app_window)
            setattr(self, attr, panel)
            sc.setWidget(panel)
            lay.addWidget(sc)
            self.tabs.addTab(tab, f"  {name}  ")

        # CCTV tab removed (now a separate standalone app)

        root.addWidget(self.tabs, 1)
        bar = self.tabs.tabBar()
        bar.setExpanding(True)
        bar.setUsesScrollButtons(False)
        bar.setDrawBase(False)
        bar.setElideMode(Qt.TextElideMode.ElideNone)
        self.tabs.setStyleSheet(
            "QTabWidget#NetworkTabs::pane { border: none; margin: 0; top: 0; }"
            "QTabWidget#NetworkTabs::tab-bar { left: 0; }"
            "QTabBar::tab { margin: 0 3px; padding: 9px 0; border-radius: 6px; }"
        )
        QTimer.singleShot(0, self._fit_tabs)
        self._load_whitelist()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._fit_tabs()

    def _fit_tabs(self):
        bar = self.tabs.tabBar()
        count = bar.count()
        if count <= 0:
            return
        width = self.tabs.width()
        if width < 100:
            return
        each = max(1, width // count)
        gap = 6  # breathing room between tabs so they are not cramped
        tab_w = max(1, each - gap)
        bar.setStyleSheet(
            "QTabBar::tab {"
            f" width: {tab_w}px; min-width: {tab_w}px; max-width: {tab_w}px;"
            f" margin: 0px {gap // 2}px; padding: 9px 0px; border-radius: 6px;"
            "}"
        )

    def run_speed_test(self):
        if self._speed_worker and self._speed_worker.isRunning():
            return
        self.speed_btn.setEnabled(False)
        self.speed_progress.setVisible(True)
        self.speed_status.setText("● Testing...")
        self.speed_status.setStyleSheet("color: #ffcc33;")
        self.gauge_ping.set_reading(None)
        self.gauge_down.set_reading(None)
        self.gauge_up.set_reading(None)
        self._speed_worker = SpeedTestWorker()
        self._speed_worker.progress.connect(lambda m: self.network_badge.setText(f"● {m}"))
        self._speed_worker.finished_ok.connect(self._on_speed_ok)
        self._speed_worker.finished_err.connect(self._on_speed_err)
        self._speed_worker.start()

    def _on_speed_ok(self, data: dict):
        self.speed_btn.setEnabled(True)
        self.speed_progress.setVisible(False)
        self.speed_status.setText("● Done")
        self.speed_status.setStyleSheet("color: #50ff85;")
        self.network_badge.setText("● Speed test done")
        ping, down, up = data.get("ping_ms"), data.get("download_mbps"), data.get("upload_mbps")
        if ping is not None:
            self.gauge_ping.set_reading(min(ping, 200), f"{ping:.0f}")
        if down is not None:
            self.gauge_down.set_reading(min(down, 500), f"{down:.1f}")
        if up is not None:
            self.gauge_up.set_reading(min(up, 100), f"{up:.1f}")
        ip = data.get("ip") or "-"
        self.ip_label.setText(f"IP: {ip}")
        loc = [p for p in (data.get("city"), data.get("region"), data.get("country")) if p]
        self.loc_label.setText("Location: " + (", ".join(loc) if loc else "-"))
        self.isp_label.setText(f"ISP: {data.get('isp') or data.get('org') or '-'}")

    def _on_speed_err(self, msg: str):
        self.speed_btn.setEnabled(True)
        self.speed_progress.setVisible(False)
        self.speed_status.setText("● Error")
        self.speed_status.setStyleSheet("color: #ff5555;")
        QMessageBox.warning(self, "Speed Test", msg[:500])

    def _whitelist_path(self) -> Path:
        base = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parents[1]
        return base / "vpn_app_whitelist.json"

    def _load_whitelist(self):
        try:
            p = self._whitelist_path()
            if p.exists():
                data = json.loads(p.read_text(encoding="utf-8"))
                self._whitelist = data if isinstance(data, list) else []
        except Exception:
            self._whitelist = []
        self._refresh_wl_list()

    def _save_whitelist(self):
        try:
            self._whitelist_path().write_text(json.dumps(self._whitelist, indent=2), encoding="utf-8")
        except Exception as e:
            QMessageBox.warning(self, "Whitelist", str(e))

    def _refresh_wl_list(self):
        self.wl_list.clear()
        for path in self._whitelist:
            name = Path(path).name if str(path).lower().endswith(".exe") else path
            item = QListWidgetItem(f"{name}")
            item.setToolTip(path)
            item.setData(Qt.ItemDataRole.UserRole, path)
            self.wl_list.addItem(item)

    def whitelist_add_dialog(self):
        dlg = ProcessPickerDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted or not dlg.selected_path:
            return
        path = dlg.selected_path
        if path in self._whitelist:
            QMessageBox.information(self, "Whitelist", "Already added.")
            return
        self._whitelist.append(path)
        self._save_whitelist()
        self._refresh_wl_list()

    def whitelist_remove(self):
        item = self.wl_list.currentItem()
        if not item:
            return
        path = item.data(Qt.ItemDataRole.UserRole)
        self._whitelist = [p for p in self._whitelist if p != path]
        self._save_whitelist()
        self._refresh_wl_list()

    def _vpn_interface_aliases(self):
        aliases = []
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-NetAdapter | Select-Object -ExpandProperty Name"],
                capture_output=True, text=True, timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            for line in (r.stdout or "").splitlines():
                name = line.strip()
                low = name.lower()
                if any(k in low for k in ("openvpn", "tap", "tun", "nordlynx", "wireguard", "wintun", "vpn")):
                    aliases.append(name)
        except Exception:
            pass
        return aliases or ["OpenVPN TAP-Windows6", "OpenVPN Data Channel Offload"]

    def apply_whitelist_rules(self):
        if not self._whitelist:
            QMessageBox.information(self, "Whitelist", "Add an app first.")
            return
        ifaces = self._vpn_interface_aliases()
        ok, errors = 0, []
        for exe in self._whitelist:
            if not str(exe).lower().endswith(".exe"):
                errors.append(f"Need full path: {exe}")
                continue
            safe = re.sub(r"[^A-Za-z0-9]", "_", Path(exe).stem)[:40]
            for iface in ifaces:
                rule = f"DedSecVPNBypass_{safe}"
                # Values are passed as single-quoted PowerShell literals via ps_quote
                # (doubles embedded quotes) - never raw interpolation.
                ps = (
                    f"Remove-NetFirewallRule -DisplayName {ps_quote(rule)} "
                    f"-ErrorAction SilentlyContinue; "
                    f"New-NetFirewallRule -DisplayName {ps_quote(rule)} -Direction Outbound "
                    f"-Program {ps_quote(exe)} -InterfaceAlias {ps_quote(iface)} "
                    f"-Action Block -ErrorAction Stop | Out-Null"
                )
                try:
                    r = subprocess.run(
                        ["powershell", "-NoProfile", "-Command", ps],
                        capture_output=True, text=True, timeout=20,
                        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
                    )
                    if r.returncode == 0:
                        ok += 1
                    else:
                        errors.append((r.stderr or r.stdout or "fail")[:100])
                except Exception as e:
                    errors.append(str(e)[:100])
        msg = f"Applied {ok} rule(s).\nAdapters: {', '.join(ifaces)}"
        if errors:
            msg += "\n\n" + "\n".join(errors[:4]) + "\n(Run as Administrator if needed.)"
        QMessageBox.information(self, "VPN Bypass", msg)

    def clear_whitelist_rules(self):
        try:
            subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-NetFirewallRule -DisplayName 'DedSecVPNBypass_*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule"],
                capture_output=True, text=True, timeout=20,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            QMessageBox.information(self, "VPN Bypass", "Cleared DedSec bypass rules.")
        except Exception as e:
            QMessageBox.warning(self, "VPN Bypass", str(e))

    def _testing_log(self, msg: str):
        self.network_badge.setText(f"● {msg[:40]}")
        try:
            self.app_window.add_log(msg)
        except Exception:
            pass

    def flush_dns(self):
        try:
            subprocess.run(["ipconfig", "/flushdns"], shell=False, check=False)
            self.network_badge.setText("● DNS flushed")
            QMessageBox.information(self, "Done", "DNS cache flushed.")
        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))

    def open_adapters(self):
        try:
            subprocess.Popen(["control", "ncpa.cpl"], shell=False)
        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))

    def show_share_steps(self):
        QMessageBox.information(
            self, "Console VPN Sharing",
            "1. Connect PC to VPN\n2. Ethernet to console\n"
            "3. Adapter properties -> Sharing\n4. Allow other users -> Ethernet\n5. Test on console",
        )