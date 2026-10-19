"""
Macro + Autoclicker panel - local only.
Saves profiles under %APPDATA%\\DedSecLab\\macros
No API / no network.
"""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal, QTime
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QPushButton,
    QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox, QCheckBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QAbstractItemView, QMessageBox, QTimeEdit,
    QFileDialog, QGroupBox,
)

IS_WIN = sys.platform.startswith("win")

if IS_WIN:
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)

    INPUT_MOUSE = 0
    INPUT_KEYBOARD = 1
    KEYEVENTF_KEYUP = 0x0002
    KEYEVENTF_SCANCODE = 0x0008
    KEYEVENTF_EXTENDEDKEY = 0x0001
    MOUSEEVENTF_LEFTDOWN = 0x0002
    MOUSEEVENTF_LEFTUP = 0x0004
    MOUSEEVENTF_RIGHTDOWN = 0x0008
    MOUSEEVENTF_RIGHTUP = 0x0010
    MOUSEEVENTF_MIDDLEDOWN = 0x0020
    MOUSEEVENTF_MIDDLEUP = 0x0040
    MOUSEEVENTF_ABSOLUTE = 0x8000
    MOUSEEVENTF_MOVE = 0x0001

    class KEYBDINPUT(ctypes.Structure):
        _fields_ = (
            ("wVk", wintypes.WORD),
            ("wScan", wintypes.WORD),
            ("dwFlags", wintypes.DWORD),
            ("time", wintypes.DWORD),
            ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong)),
        )

    class MOUSEINPUT(ctypes.Structure):
        _fields_ = (
            ("dx", wintypes.LONG),
            ("dy", wintypes.LONG),
            ("mouseData", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("time", wintypes.DWORD),
            ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong)),
        )

    class HARDWAREINPUT(ctypes.Structure):
        _fields_ = (
            ("uMsg", wintypes.DWORD),
            ("wParamL", wintypes.WORD),
            ("wParamH", wintypes.WORD),
        )

    class INPUTUNION(ctypes.Union):
        _fields_ = (("ki", KEYBDINPUT), ("mi", MOUSEINPUT), ("hi", HARDWAREINPUT))

    class INPUT(ctypes.Structure):
        _fields_ = (("type", wintypes.DWORD), ("union", INPUTUNION))

    user32.GetAsyncKeyState.argtypes = [ctypes.c_int]
    user32.GetAsyncKeyState.restype = wintypes.SHORT
    user32.GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
    user32.GetCursorPos.restype = wintypes.BOOL
    user32.SendInput.argtypes = [wintypes.UINT, ctypes.POINTER(INPUT), ctypes.c_int]
    user32.SendInput.restype = wintypes.UINT
    user32.GetSystemMetrics.argtypes = [ctypes.c_int]
    user32.GetSystemMetrics.restype = ctypes.c_int
    user32.MapVirtualKeyW.argtypes = [wintypes.UINT, wintypes.UINT]
    user32.MapVirtualKeyW.restype = wintypes.UINT


CONFIG_DIR = Path(os.environ.get("APPDATA") or Path.home()) / "DedSecLab" / "macros"
PROFILES_FILE = CONFIG_DIR / "profiles.json"

VK_NAMES = {
    0x01: "LMB", 0x02: "RMB", 0x04: "MMB",
    0x08: "BACK", 0x09: "TAB", 0x0D: "ENTER", 0x10: "SHIFT",
    0x11: "CTRL", 0x12: "ALT", 0x14: "CAPS", 0x1B: "ESC",
    0x20: "SPACE", 0x25: "LEFT", 0x26: "UP", 0x27: "RIGHT", 0x28: "DOWN",
    0x2E: "DEL", 0x70: "F1", 0x71: "F2", 0x72: "F3", 0x73: "F4",
    0x74: "F5", 0x75: "F6", 0x76: "F7", 0x77: "F8", 0x78: "F9",
    0x79: "F10", 0x7A: "F11", 0x7B: "F12",
}
for i in range(48, 58):
    VK_NAMES[i] = chr(i)
for i in range(65, 91):
    VK_NAMES[i] = chr(i)

IGNORE_WHILE_RECORD = {0x77, 0x78, 0x79}  # F8 stop-play, F9 rec, F10 play


def vk_name(vk: int) -> str:
    return VK_NAMES.get(int(vk), f"VK_{int(vk):02X}")


def ensure_dir() -> Path:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    return CONFIG_DIR


def load_store() -> dict:
    ensure_dir()
    if not PROFILES_FILE.exists():
        return {"profiles": {}, "last": ""}
    try:
        data = json.loads(PROFILES_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {"profiles": {}, "last": ""}
        data.setdefault("profiles", {})
        data.setdefault("last", "")
        return data
    except Exception:
        return {"profiles": {}, "last": ""}


def save_store(data: dict) -> None:
    ensure_dir()
    PROFILES_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def send_key(vk: int, down: bool) -> None:
    if not IS_WIN:
        return
    scan = user32.MapVirtualKeyW(int(vk), 0)
    flags = 0 if down else KEYEVENTF_KEYUP
    extra = ctypes.pointer(ctypes.c_ulong(0))
    inp = INPUT(type=INPUT_KEYBOARD, union=INPUTUNION(ki=KEYBDINPUT(
        wVk=int(vk), wScan=scan, dwFlags=flags, time=0, dwExtraInfo=extra
    )))
    user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))


def send_click(button: str, down: bool, x=None, y=None) -> None:
    if not IS_WIN:
        return
    flags = {
        ("left", True): MOUSEEVENTF_LEFTDOWN,
        ("left", False): MOUSEEVENTF_LEFTUP,
        ("right", True): MOUSEEVENTF_RIGHTDOWN,
        ("right", False): MOUSEEVENTF_RIGHTUP,
        ("middle", True): MOUSEEVENTF_MIDDLEDOWN,
        ("middle", False): MOUSEEVENTF_MIDDLEUP,
    }.get((button, down), MOUSEEVENTF_LEFTDOWN if down else MOUSEEVENTF_LEFTUP)
    dx = dy = 0
    extra_flags = flags
    if x is not None and y is not None:
        sw = max(1, user32.GetSystemMetrics(0))
        sh = max(1, user32.GetSystemMetrics(1))
        dx = int(int(x) * 65535 / sw)
        dy = int(int(y) * 65535 / sh)
        extra_flags |= MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE
    extra = ctypes.pointer(ctypes.c_ulong(0))
    inp = INPUT(type=INPUT_MOUSE, union=INPUTUNION(mi=MOUSEINPUT(
        dx=dx, dy=dy, mouseData=0, dwFlags=extra_flags, time=0, dwExtraInfo=extra
    )))
    user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))


def cursor_pos():
    if not IS_WIN:
        return 0, 0
    pt = wintypes.POINT()
    user32.GetCursorPos(ctypes.byref(pt))
    return int(pt.x), int(pt.y)


class RecordWorker(QThread):
    event_captured = pyqtSignal(dict)
    status = pyqtSignal(str)

    def __init__(self, capture_mouse=True, parent=None):
        super().__init__(parent)
        self._stop = False
        self.capture_mouse = capture_mouse

    def stop(self):
        self._stop = True

    def run(self):
        if not IS_WIN:
            self.status.emit("Windows only")
            return
        prev = {vk: False for vk in range(1, 256)}
        last_t = time.perf_counter()
        self.status.emit("recording")
        while not self._stop:
            now = time.perf_counter()
            delay = int((now - last_t) * 1000)
            for vk in range(1, 256):
                if vk in IGNORE_WHILE_RECORD:
                    continue
                down = bool(user32.GetAsyncKeyState(vk) & 0x8000)
                if down == prev[vk]:
                    continue
                prev[vk] = down
                if vk in (1, 2, 4) and not self.capture_mouse:
                    continue
                ev = {
                    "t": "click" if vk in (1, 2, 4) else "key",
                    "action": "down" if down else "up",
                    "vk": vk,
                    "name": vk_name(vk),
                    "delay_ms": max(0, delay),
                }
                if ev["t"] == "click":
                    ev["button"] = {1: "left", 2: "right", 4: "middle"}[vk]
                    ev["x"], ev["y"] = cursor_pos()
                self.event_captured.emit(ev)
                last_t = now
            time.sleep(0.006)
        self.status.emit("idle")


class PlayWorker(QThread):
    status = pyqtSignal(str)
    finished_ok = pyqtSignal()

    def __init__(self, events: list, speed: float = 1.0, loops: int = 1, parent=None):
        super().__init__(parent)
        self.events = events
        self.speed = max(0.05, float(speed))
        self.loops = max(0, int(loops))  # 0 = infinite
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        if not IS_WIN:
            self.status.emit("Windows only")
            return
        loop = 0
        self.status.emit("playing")
        while not self._stop:
            loop += 1
            if self.loops and loop > self.loops:
                break
            for ev in self.events:
                if self._stop:
                    break
                wait = max(0.0, float(ev.get("delay_ms") or 0) / 1000.0 / self.speed)
                end = time.perf_counter() + wait
                while not self._stop and time.perf_counter() < end:
                    time.sleep(0.004)
                if self._stop:
                    break
                kind = ev.get("t")
                down = ev.get("action") == "down"
                if kind == "key":
                    send_key(int(ev.get("vk") or 0), down)
                elif kind == "click":
                    send_click(ev.get("button") or "left", down, ev.get("x"), ev.get("y"))
        self.status.emit("idle")
        self.finished_ok.emit()


class ClickWorker(QThread):
    status = pyqtSignal(str)

    def __init__(self, mode: str, interval_ms: int, button="left", vk=None, hold_ms=30, parent=None):
        super().__init__(parent)
        self.mode = mode
        self.interval_ms = max(10, int(interval_ms))
        self.button = button
        self.vk = vk
        self.hold_ms = max(5, int(hold_ms))
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        if not IS_WIN:
            self.status.emit("Windows only")
            return
        self.status.emit("clicking")
        while not self._stop:
            if self.mode == "key" and self.vk:
                send_key(int(self.vk), True)
                time.sleep(self.hold_ms / 1000.0)
                send_key(int(self.vk), False)
            else:
                send_click(self.button, True)
                time.sleep(self.hold_ms / 1000.0)
                send_click(self.button, False)
            end = time.perf_counter() + (self.interval_ms / 1000.0)
            while not self._stop and time.perf_counter() < end:
                time.sleep(0.004)
        self.status.emit("idle")


class MacroPanel(QWidget):
    def __init__(self, app_window=None):
        super().__init__()
        self.app_window = app_window
        self.events: list[dict] = []
        self.rec = None
        self.play = None
        self.clicker = None
        self._bind_vk = None
        self._build()
        self._sched = QTimer(self)
        self._sched.setInterval(1000)
        self._sched.timeout.connect(self._tick_schedule)
        self._sched.start()
        self.reload_profiles()

    def config_dir(self) -> Path:
        return ensure_dir()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(10)

        title = QLabel("MACRO / AUTOCLICKER")
        title.setObjectName("PageTitle")
        hint = QLabel(
            "Local only · saved in AppData\\DedSecLab\\macros · F9 record · F10 play · F8 stop"
        )
        hint.setObjectName("Hint")
        root.addWidget(title)
        root.addWidget(hint)

        if not IS_WIN:
            warn = QLabel("This tool uses Windows SendInput. Open the app on Windows to record and play.")
            warn.setObjectName("Hint")
            root.addWidget(warn)

        # profiles
        prow = QHBoxLayout()
        self.profile_box = QComboBox()
        self.profile_box.setEditable(True)
        self.profile_box.setPlaceholderText("Profile name")
        self.btn_save = QPushButton("Save profile")
        self.btn_save.clicked.connect(self.save_profile)
        self.btn_load = QPushButton("Load")
        self.btn_load.clicked.connect(self.load_selected)
        self.btn_del = QPushButton("Delete")
        self.btn_del.clicked.connect(self.delete_profile)
        self.btn_export = QPushButton("Export JSON")
        self.btn_export.clicked.connect(self.export_json)
        self.btn_import = QPushButton("Import JSON")
        self.btn_import.clicked.connect(self.import_json)
        path_lbl = QLabel(str(CONFIG_DIR))
        path_lbl.setObjectName("Hint")
        path_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        prow.addWidget(QLabel("Profile"))
        prow.addWidget(self.profile_box, 1)
        prow.addWidget(self.btn_save)
        prow.addWidget(self.btn_load)
        prow.addWidget(self.btn_del)
        prow.addWidget(self.btn_export)
        prow.addWidget(self.btn_import)
        root.addLayout(prow)
        root.addWidget(path_lbl)

        # record / play
        rec_box = QGroupBox("Macro recorder")
        rl = QVBoxLayout(rec_box)
        brow = QHBoxLayout()
        self.btn_rec = QPushButton("Record")
        self.btn_rec.setObjectName("ActionButton_cyan")
        self.btn_rec.clicked.connect(self.toggle_record)
        self.btn_play = QPushButton("Play")
        self.btn_play.setObjectName("ActionButton_green")
        self.btn_play.clicked.connect(self.toggle_play)
        self.btn_stop = QPushButton("Stop")
        self.btn_stop.clicked.connect(self.stop_all)
        self.btn_clear = QPushButton("Clear events")
        self.btn_clear.clicked.connect(self.clear_events)
        self.chk_mouse = QCheckBox("Record mouse clicks + position")
        self.chk_mouse.setChecked(True)
        self.status_lbl = QLabel("Status: idle")
        self.status_lbl.setObjectName("Hint")
        for b in (self.btn_rec, self.btn_play, self.btn_stop, self.btn_clear):
            b.setMinimumHeight(34)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
        brow.addWidget(self.btn_rec)
        brow.addWidget(self.btn_play)
        brow.addWidget(self.btn_stop)
        brow.addWidget(self.btn_clear)
        brow.addWidget(self.chk_mouse)
        brow.addWidget(self.status_lbl, 1)
        rl.addLayout(brow)

        opt = QGridLayout()
        opt.addWidget(QLabel("Speed"), 0, 0)
        self.speed = QDoubleSpinBox()
        self.speed.setRange(0.10, 8.00)
        self.speed.setSingleStep(0.10)
        self.speed.setValue(1.00)
        self.speed.setSuffix(" x")
        opt.addWidget(self.speed, 0, 1)
        opt.addWidget(QLabel("Loops (0 = forever)"), 0, 2)
        self.loops = QSpinBox()
        self.loops.setRange(0, 9999)
        self.loops.setValue(1)
        opt.addWidget(self.loops, 0, 3)
        opt.addWidget(QLabel("Start at"), 1, 0)
        self.start_at = QTimeEdit()
        self.start_at.setDisplayFormat("HH:mm:ss")
        self.start_at.setTime(QTime(0, 0, 0))
        opt.addWidget(self.start_at, 1, 1)
        opt.addWidget(QLabel("Stop at"), 1, 2)
        self.stop_at = QTimeEdit()
        self.stop_at.setDisplayFormat("HH:mm:ss")
        self.stop_at.setTime(QTime(23, 59, 59))
        opt.addWidget(self.stop_at, 1, 3)
        self.chk_sched = QCheckBox("Use start / stop schedule")
        opt.addWidget(self.chk_sched, 2, 0, 1, 2)
        self.chk_loop_sched = QCheckBox("Auto-play when start time hits")
        opt.addWidget(self.chk_loop_sched, 2, 2, 1, 2)
        rl.addLayout(opt)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["#", "Delay ms", "Type", "Name", "Action", "XY"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.itemChanged.connect(self._on_cell_edit)
        rl.addWidget(self.table, 1)

        editrow = QHBoxLayout()
        self.btn_del_row = QPushButton("Delete selected event")
        self.btn_del_row.clicked.connect(self.delete_selected)
        self.count_lbl = QLabel("0 events")
        self.count_lbl.setObjectName("Hint")
        editrow.addWidget(self.btn_del_row)
        editrow.addWidget(self.count_lbl)
        editrow.addStretch()
        rl.addLayout(editrow)
        root.addWidget(rec_box, 1)

        # autoclicker
        clk = QGroupBox("Autoclicker")
        cl = QGridLayout(clk)
        cl.addWidget(QLabel("Mode"), 0, 0)
        self.click_mode = QComboBox()
        self.click_mode.addItems(["Left click", "Right click", "Middle click", "Repeat a key"])
        cl.addWidget(self.click_mode, 0, 1)
        cl.addWidget(QLabel("Interval ms"), 0, 2)
        self.click_ms = QSpinBox()
        self.click_ms.setRange(10, 60000)
        self.click_ms.setValue(100)
        cl.addWidget(self.click_ms, 0, 3)
        cl.addWidget(QLabel("Hold ms"), 1, 0)
        self.hold_ms = QSpinBox()
        self.hold_ms.setRange(5, 1000)
        self.hold_ms.setValue(25)
        cl.addWidget(self.hold_ms, 1, 1)
        cl.addWidget(QLabel("Bound key"), 1, 2)
        self.bind_lbl = QLabel("none - press Bind key")
        self.bind_lbl.setObjectName("Hint")
        cl.addWidget(self.bind_lbl, 1, 3)
        self.btn_bind = QPushButton("Bind key")
        self.btn_bind.clicked.connect(self.bind_key)
        self.btn_click = QPushButton("Start clicker")
        self.btn_click.setObjectName("ActionButton_green")
        self.btn_click.clicked.connect(self.toggle_clicker)
        cl.addWidget(self.btn_bind, 2, 0, 1, 2)
        cl.addWidget(self.btn_click, 2, 2, 1, 2)
        root.addWidget(clk)

        note = QLabel(
            "Playback goes to the focused window. F8 always stops. "
            "Do not use this to bypass game anti-cheat or to automate other people's accounts."
        )
        note.setObjectName("Hint")
        note.setWordWrap(True)
        root.addWidget(note)

        self.hot_f8 = QTimer(self)
        self.hot_f8.setInterval(80)
        self.hot_f8.timeout.connect(self._poll_hotkeys)
        self.hot_f8.start()

    def _log(self, msg: str):
        self.status_lbl.setText(f"Status: {msg}")
        if self.app_window and hasattr(self.app_window, "add_log"):
            try:
                self.app_window.add_log(f"[Macro] {msg}")
            except Exception:
                pass

    def _poll_hotkeys(self):
        if not IS_WIN:
            return
        if user32.GetAsyncKeyState(0x77) & 1:
            self.stop_all()
        if user32.GetAsyncKeyState(0x78) & 1:
            self.toggle_record()
        if user32.GetAsyncKeyState(0x79) & 1:
            self.toggle_play()

    def toggle_record(self):
        if self.rec and self.rec.isRunning():
            self.rec.stop()
            self.rec.wait(400)
            self.rec = None
            self.btn_rec.setText("Record")
            self._log("record stopped")
            return
        self.stop_play_only()
        self.rec = RecordWorker(capture_mouse=self.chk_mouse.isChecked(), parent=self)
        self.rec.event_captured.connect(self._add_event)
        self.rec.status.connect(self._log)
        self.rec.start()
        self.btn_rec.setText("Stop record")
        self._log("recording - switch to the target window")

    def _add_event(self, ev: dict):
        self.events.append(ev)
        self._refresh_table(scroll=True)

    def clear_events(self):
        self.events = []
        self._refresh_table()

    def delete_selected(self):
        rows = sorted({i.row() for i in self.table.selectedItems()}, reverse=True)
        for r in rows:
            if 0 <= r < len(self.events):
                self.events.pop(r)
        self._refresh_table()

    def _refresh_table(self, scroll=False):
        self.table.blockSignals(True)
        self.table.setRowCount(0)
        for i, ev in enumerate(self.events):
            r = self.table.rowCount()
            self.table.insertRow(r)
            xy = ""
            if ev.get("t") == "click":
                xy = f"{ev.get('x', '')},{ev.get('y', '')}"
            vals = [
                str(i + 1),
                str(int(ev.get("delay_ms") or 0)),
                ev.get("t", ""),
                ev.get("name", ""),
                ev.get("action", ""),
                xy,
            ]
            for c, v in enumerate(vals):
                item = QTableWidgetItem(v)
                if c == 0:
                    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.table.setItem(r, c, item)
        self.table.blockSignals(False)
        self.count_lbl.setText(f"{len(self.events)} events")
        if scroll and self.table.rowCount():
            self.table.scrollToBottom()

    def _on_cell_edit(self, item: QTableWidgetItem):
        r, c = item.row(), item.column()
        if not (0 <= r < len(self.events)):
            return
        text = item.text().strip()
        if c == 1:
            try:
                self.events[r]["delay_ms"] = max(0, int(text))
            except ValueError:
                item.setText(str(self.events[r].get("delay_ms", 0)))
        elif c == 3:
            self.events[r]["name"] = text
        elif c == 4 and text in ("down", "up"):
            self.events[r]["action"] = text

    def toggle_play(self):
        if self.play and self.play.isRunning():
            self.stop_play_only()
            return
        if not self.events:
            QMessageBox.information(self, "Play", "Record or load a profile first.")
            return
        self.stop_record_only()
        self.play = PlayWorker(
            list(self.events),
            speed=self.speed.value(),
            loops=self.loops.value(),
            parent=self,
        )
        self.play.status.connect(self._log)
        self.play.finished_ok.connect(lambda: self.btn_play.setText("Play"))
        self.play.start()
        self.btn_play.setText("Stop play")

    def stop_play_only(self):
        if self.play and self.play.isRunning():
            self.play.stop()
            self.play.wait(500)
        self.play = None
        self.btn_play.setText("Play")

    def stop_record_only(self):
        if self.rec and self.rec.isRunning():
            self.rec.stop()
            self.rec.wait(400)
        self.rec = None
        self.btn_rec.setText("Record")

    def stop_clicker_only(self):
        if self.clicker and self.clicker.isRunning():
            self.clicker.stop()
            self.clicker.wait(400)
        self.clicker = None
        self.btn_click.setText("Start clicker")

    def stop_all(self):
        self.stop_record_only()
        self.stop_play_only()
        self.stop_clicker_only()
        self._log("stopped")

    def _tick_schedule(self):
        if not self.chk_sched.isChecked():
            return
        now = QTime.currentTime()
        start = self.start_at.time()
        stop = self.stop_at.time()
        in_window = start <= now <= stop if start <= stop else (now >= start or now <= stop)
        playing = self.play and self.play.isRunning()
        if self.chk_loop_sched.isChecked() and in_window and not playing and self.events:
            if now.second() == start.second() and now.minute() == start.minute() and now.hour() == start.hour():
                self.toggle_play()
        if playing and not in_window:
            self.stop_play_only()
            self._log("stopped by schedule")

    def bind_key(self):
        if not IS_WIN:
            return
        self.bind_lbl.setText("press any key...")
        QTimer.singleShot(150, self._capture_bind)

    def _capture_bind(self):
        deadline = time.time() + 5
        while time.time() < deadline:
            for vk in range(8, 256):
                if user32.GetAsyncKeyState(vk) & 0x8000:
                    self._bind_vk = vk
                    self.bind_lbl.setText(vk_name(vk))
                    return
            time.sleep(0.02)
            from PyQt6.QtWidgets import QApplication
            QApplication.processEvents()
        self.bind_lbl.setText("none - press Bind key")

    def toggle_clicker(self):
        if self.clicker and self.clicker.isRunning():
            self.stop_clicker_only()
            self._log("clicker stopped")
            return
        mode_txt = self.click_mode.currentText()
        if mode_txt.startswith("Repeat"):
            if not self._bind_vk:
                QMessageBox.information(self, "Clicker", "Bind a key first.")
                return
            mode, button, vk = "key", "left", self._bind_vk
        else:
            button = mode_txt.split()[0].lower()
            mode, vk = "mouse", None
        self.clicker = ClickWorker(
            mode=mode,
            interval_ms=self.click_ms.value(),
            button=button,
            vk=vk,
            hold_ms=self.hold_ms.value(),
            parent=self,
        )
        self.clicker.status.connect(self._log)
        self.clicker.start()
        self.btn_click.setText("Stop clicker")

    def current_profile_payload(self) -> dict:
        return {
            "events": self.events,
            "speed": self.speed.value(),
            "loops": self.loops.value(),
            "start": self.start_at.time().toString("HH:mm:ss"),
            "stop": self.stop_at.time().toString("HH:mm:ss"),
            "schedule": self.chk_sched.isChecked(),
            "auto_play": self.chk_loop_sched.isChecked(),
            "mouse": self.chk_mouse.isChecked(),
            "click_mode": self.click_mode.currentText(),
            "click_ms": self.click_ms.value(),
            "hold_ms": self.hold_ms.value(),
            "bind_vk": self._bind_vk,
            "updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    def apply_payload(self, data: dict):
        self.events = list(data.get("events") or [])
        self.speed.setValue(float(data.get("speed") or 1))
        self.loops.setValue(int(data.get("loops") or 1))
        self.start_at.setTime(QTime.fromString(str(data.get("start") or "00:00:00"), "HH:mm:ss"))
        self.stop_at.setTime(QTime.fromString(str(data.get("stop") or "23:59:59"), "HH:mm:ss"))
        self.chk_sched.setChecked(bool(data.get("schedule")))
        self.chk_loop_sched.setChecked(bool(data.get("auto_play")))
        self.chk_mouse.setChecked(bool(data.get("mouse", True)))
        idx = self.click_mode.findText(str(data.get("click_mode") or ""))
        if idx >= 0:
            self.click_mode.setCurrentIndex(idx)
        self.click_ms.setValue(int(data.get("click_ms") or 100))
        self.hold_ms.setValue(int(data.get("hold_ms") or 25))
        self._bind_vk = data.get("bind_vk")
        self.bind_lbl.setText(vk_name(self._bind_vk) if self._bind_vk else "none - press Bind key")
        self._refresh_table()

    def reload_profiles(self):
        store = load_store()
        names = sorted(store.get("profiles", {}))
        current = self.profile_box.currentText()
        self.profile_box.blockSignals(True)
        self.profile_box.clear()
        self.profile_box.addItems(names)
        if current:
            self.profile_box.setCurrentText(current)
        elif store.get("last"):
            self.profile_box.setCurrentText(store["last"])
        self.profile_box.blockSignals(False)

    def save_profile(self):
        name = self.profile_box.currentText().strip() or "default"
        store = load_store()
        store["profiles"][name] = self.current_profile_payload()
        store["last"] = name
        save_store(store)
        self.reload_profiles()
        self.profile_box.setCurrentText(name)
        self._log(f"saved {name} -> {PROFILES_FILE}")

    def load_selected(self):
        name = self.profile_box.currentText().strip()
        store = load_store()
        data = (store.get("profiles") or {}).get(name)
        if not data:
            QMessageBox.information(self, "Load", "No profile with that name.")
            return
        self.apply_payload(data)
        store["last"] = name
        save_store(store)
        self._log(f"loaded {name}")

    def delete_profile(self):
        name = self.profile_box.currentText().strip()
        store = load_store()
        if name in store.get("profiles", {}):
            del store["profiles"][name]
            save_store(store)
            self.reload_profiles()
            self._log(f"deleted {name}")

    def export_json(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export macro", str(CONFIG_DIR / "macro.json"), "JSON (*.json)")
        if not path:
            return
        Path(path).write_text(json.dumps(self.current_profile_payload(), indent=2), encoding="utf-8")
        self._log(f"exported {path}")

    def import_json(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import macro", str(CONFIG_DIR), "JSON (*.json)")
        if not path:
            return
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception as e:
            QMessageBox.warning(self, "Import", str(e))
            return
        if "events" not in data and "profiles" in data:
            QMessageBox.information(self, "Import", "That file is a profile store. Copy it into AppData\\DedSecLab\\macros instead.")
            return
        self.apply_payload(data)
        self._log(f"imported {path}")
