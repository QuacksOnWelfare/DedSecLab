#!/usr/bin/env python3
"""Private CCTV wall. Plays only RTSP addresses the user saved."""

import json
from urllib.request import Request, urlopen
import sys
import uuid
from pathlib import Path
from urllib.parse import urlparse

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont, QPixmap, QPainter, QColor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QFrame, QDialog, QLineEdit,
    QListWidget, QListWidgetItem, QMessageBox, QSizePolicy,
)

MAX_CAMERAS = 4
WALL_SLOTS = 4


def _store_path() -> Path:
    base = Path.home() / "AppData" / "Roaming" / "DedSecLab"
    base.mkdir(parents=True, exist_ok=True)
    return base / "cctv_wall.json"


def _mask_rtsp(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        return "no address saved"
    try:
        parsed = urlparse(raw)
        host = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port else ""
        path = parsed.path or ""
        return f"rtsp://{host}{port}{path}" if host else "rtsp address saved"
    except Exception:
        return "rtsp address saved"


def _valid_rtsp(url: str) -> bool:
    raw = (url or "").strip()
    if not raw.lower().startswith(("rtsp://", "rtsps://")):
        return False
    parsed = urlparse(raw)
    return bool(parsed.hostname)


_VLC_INSTANCE = None
_VLC_DETAIL = "VLC not loaded"


def shared_vlc():
    global _VLC_INSTANCE, _VLC_DETAIL
    if _VLC_INSTANCE is not None:
        return _VLC_INSTANCE, "LIVE"
    try:
        import vlc
        _VLC_INSTANCE = vlc.Instance(
            "--intf", "dummy",
            "--no-video-title-show",
            "--network-caching=300",
            "--rtsp-tcp",
            "--quiet",
        )
        _VLC_DETAIL = "LIVE" if _VLC_INSTANCE is not None else "VLC failed to start"
    except Exception as exc:
        _VLC_INSTANCE = None
        _VLC_DETAIL = f"VLC missing · {exc.__class__.__name__}"
    return _VLC_INSTANCE, _VLC_DETAIL


class VlcPool:
    def __init__(self):
        self._players = {}
        self._instance, self.detail = shared_vlc()
        self.ready = self._instance is not None

    def play(self, key: str, rtsp: str, widget: QWidget) -> bool:
        if not self._instance or not rtsp or widget is None:
            return False
        try:
            player = self._players.get(key)
            if player is None:
                player = self._instance.media_player_new()
                self._players[key] = player
            media = self._instance.media_new(rtsp)
            player.set_media(media)
            hwnd = int(widget.winId())
            if sys.platform.startswith("linux"):
                player.set_xwindow(hwnd)
            elif sys.platform == "darwin":
                player.set_nsobject(hwnd)
            else:
                player.set_hwnd(hwnd)
            player.play()
            QTimer.singleShot(500, lambda pl=player: self._kick_audio(pl))
            return True
        except Exception:
            return False

    def _kick_audio(self, player) -> None:
        try:
            player.audio_set_volume(100)
            player.audio_set_mute(True)
            player.audio_set_mute(False)
        except Exception:
            pass

    def stop(self, key: str) -> None:
        player = self._players.get(key)
        if not player:
            return
        try:
            player.audio_set_mute(True)
            player.pause()
        except Exception:
            pass
        self._players.pop(key, None)

    def stop_all(self) -> None:
        for key in list(self._players):
            self.stop(key)



def _paint_btn(btn, on: bool) -> None:
    if btn is None:
        return
    btn.setFixedSize(64, 28)
    if not on:
        btn.setObjectName("CctvIcon")
        btn.setStyleSheet("")
        return
    btn.setObjectName("CctvIcon")
    btn.setStyleSheet(
        "QPushButton { background: #14361f; color: #7dffb0; border: 1px solid #2fbf6a;"
        " border-radius: 2px; font-family: Consolas; font-size: 11px; font-weight: 700;"
        " padding: 0 8px; }"
    )

def _host_of(url: str) -> str:
    try:
        return urlparse(url or "").hostname or ""
    except Exception:
        return ""


def lookup_isp(url: str) -> dict:
    host = _host_of(url)
    if not host:
        return {"text": "No host in this address.", "code": ""}
    try:
        raw = urlopen(Request(
            f"http://ip-api.com/json/{host}?fields=status,query,country,countryCode,regionName,city,isp,org,as",
            headers={"User-Agent": "DedSecLab"},
        ), timeout=8).read().decode()
        data = json.loads(raw)
    except Exception as exc:
        return {"text": f"Lookup failed for {host}\n{exc}", "code": ""}
    if data.get("status") != "success":
        return {"text": f"Host: {host}\nNo public ISP record.", "code": ""}
    code = (data.get("countryCode") or "").upper()
    lines = [
        f"Host: {host}",
        f"IP: {data.get('query') or '-'}",
        f"Country: {data.get('country') or '-'}",
        f"ISP: {data.get('isp') or '-'}",
        f"Org: {data.get('org') or '-'}",
        f"ASN: {data.get('as') or '-'}",
        f"Location: {', '.join(p for p in (data.get('city'), data.get('regionName'), data.get('country')) if p) or '-'}",
    ]
    return {"text": "\n".join(lines), "code": code}


def country_icon(code: str) -> QPixmap:
    pix = QPixmap(64, 64)
    pix.fill(QColor("#10261c"))
    painter = QPainter(pix)
    painter.setPen(QColor("#d8ffe9"))
    painter.setFont(QFont("Consolas", 16, QFont.Weight.Bold))
    painter.drawText(pix.rect(), Qt.AlignmentFlag.AlignCenter, code or "--")
    painter.end()
    return pix


def show_stream_info(parent, url: str) -> None:
    info = lookup_isp(url)
    box = QMessageBox(parent)
    box.setWindowTitle("Stream info")
    box.setText(info.get("text") or "No info")
    box.setIconPixmap(country_icon(info.get("code") or ""))
    box.exec()


class CameraTile(QFrame):
    def __init__(self, slot: int, compact: bool = False):
        super().__init__()
        self.setObjectName("CctvTile")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setMinimumSize(240, 160)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.video = QFrame()
        self.video.setObjectName("CctvVideo")
        self.video.setAttribute(Qt.WidgetAttribute.WA_NativeWindow, True)
        self.video.setAttribute(Qt.WidgetAttribute.WA_DontCreateNativeAncestors, True)
        layout.addWidget(self.video, 1)
        self.watermark = QLabel("STREAM OFFLINE", self.video)
        self.watermark.setObjectName("CctvWatermark")
        self.watermark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = QFont("Consolas", 18 if compact else 26)
        font.setBold(True)
        self.watermark.setFont(font)
        self.slot = slot
        self.compact = compact
        self.play_btn = None
        self.mute_btn = None
        self.info_btn = None
        if not compact:
            bar = QFrame()
            bar.setObjectName("CctvBar")
            bar.setFixedHeight(48)
            row = QHBoxLayout(bar)
            row.setContentsMargins(8, 6, 8, 6)
            row.setSpacing(8)
            self.slot_lbl = QLabel(f"CAM {slot:02d}")
            self.slot_lbl.setObjectName("CctvSlot")
            self.play_btn = QPushButton("PLAY")
            self.play_btn.setObjectName("CctvIcon")
            self.play_btn.setFixedSize(64, 28)
            self.mute_btn = QPushButton("MUTE")
            self.mute_btn.setObjectName("CctvIcon")
            self.mute_btn.setFixedSize(64, 28)
            self.mute_btn.setCheckable(False)
            self.info_btn = QPushButton("INFO")
            self.info_btn.setObjectName("CctvIcon")
            self.info_btn.setFixedSize(64, 28)
            row.addWidget(self.slot_lbl)
            row.addStretch()
            row.addWidget(self.play_btn)
            row.addWidget(self.mute_btn)
            row.addWidget(self.info_btn)
            layout.addWidget(bar)
            self.play_btn.hide()
            self.mute_btn.hide()
            self.info_btn.hide()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.watermark.setGeometry(0, 0, self.video.width(), self.video.height())

    def show_empty(self) -> None:
        self.watermark.setText("STREAM OFFLINE")
        self.watermark.show()
        self.watermark.raise_()
        for btn in (self.play_btn, self.mute_btn, self.info_btn):
            if btn is not None:
                btn.hide()

    def show_held(self) -> None:
        self.watermark.setText("OPEN IN FULL SCREEN")
        self.watermark.show()
        self.watermark.raise_()
        for btn in (self.play_btn, self.mute_btn, self.info_btn):
            if btn is not None:
                btn.hide()

    def show_ready(self) -> None:
        self.watermark.setText("READY")
        self.watermark.show()
        self.watermark.raise_()
        if self.play_btn is not None:
            self.play_btn.setText("PLAY")
            _paint_btn(self.play_btn, False)
            self.play_btn.show()
            self.mute_btn.show()
            self.info_btn.show()

    def show_live(self) -> None:
        self.watermark.hide()
        if self.play_btn is not None:
            self.play_btn.setText("STOP")
            _paint_btn(self.play_btn, True)
            self.play_btn.show()
            self.mute_btn.show()
            self.info_btn.show()

    def show_error(self, text: str) -> None:
        self.watermark.setText(text)
        self.watermark.show()
        self.watermark.raise_()


class CameraDialog(QDialog):
    def __init__(self, parent=None, camera: dict | None = None):
        super().__init__(parent)
        self.setWindowTitle("Camera")
        self.setModal(True)
        self.setMinimumWidth(460)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)
        layout.addWidget(QLabel("RTSP address"))
        self.rtsp_edit = QLineEdit()
        self.rtsp_edit.setPlaceholderText("rtsp://192.168.1.20:554/stream1")
        self.rtsp_edit.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.rtsp_edit)
        hint = QLabel("Only an address you add is played. Empty slots stay offline.")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        show_row = QHBoxLayout()
        self.reveal_btn = QPushButton("Show address")
        self.reveal_btn.setCheckable(True)
        self.reveal_btn.toggled.connect(self._toggle_reveal)
        show_row.addWidget(self.reveal_btn)
        show_row.addStretch()
        layout.addLayout(show_row)
        buttons = QHBoxLayout()
        buttons.addStretch()
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        save = QPushButton("Save")
        save.clicked.connect(self._save)
        buttons.addWidget(cancel)
        buttons.addWidget(save)
        layout.addLayout(buttons)
        self._camera = dict(camera or {})
        if camera:
            self.rtsp_edit.setText(camera.get("rtsp", ""))

    def _toggle_reveal(self, checked: bool) -> None:
        self.rtsp_edit.setEchoMode(
            QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
        )
        self.reveal_btn.setText("Hide address" if checked else "Show address")

    def _save(self) -> None:
        rtsp = self.rtsp_edit.text().strip()
        if not _valid_rtsp(rtsp):
            QMessageBox.warning(self, "Camera", "Address must start with rtsp:// or rtsps:// and include a host.")
            return
        self._camera["rtsp"] = rtsp
        self.accept()

    def camera(self) -> dict:
        return self._camera


class LibraryDialog(QDialog):
    def __init__(self, page: "CctvPage"):
        super().__init__(page)
        self.page = page
        self.setWindowTitle("CCTV library")
        self.setModal(True)
        self.resize(560, 420)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)
        layout.addWidget(QLabel("Up to 4 cameras. All of them sit on the wall."))
        self.list = QListWidget()
        layout.addWidget(self.list, 1)
        row = QHBoxLayout()
        self.add_btn = QPushButton("Add")
        self.edit_btn = QPushButton("Edit")
        self.remove_btn = QPushButton("Remove")
        self.pin_btn = QPushButton("Show on wall")
        self.add_btn.clicked.connect(self._add)
        self.edit_btn.clicked.connect(self._edit)
        self.remove_btn.clicked.connect(self._remove)
        self.pin_btn.clicked.connect(self._pin)
        row.addWidget(self.add_btn)
        row.addWidget(self.edit_btn)
        row.addWidget(self.remove_btn)
        row.addWidget(self.pin_btn)
        row.addStretch()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        row.addWidget(close_btn)
        layout.addLayout(row)
        self._reload()

    def _reload(self) -> None:
        self.list.clear()
        pinned = sum(1 for cam in self.page.cameras if cam.get("pinned"))
        for cam in self.page.cameras:
            mark = "ON WALL" if cam.get("pinned") else "library"
            item = QListWidgetItem(f"{mark}    {_mask_rtsp(cam.get('rtsp', ''))}")
            item.setData(Qt.ItemDataRole.UserRole, cam.get("id"))
            self.list.addItem(item)
        self.add_btn.setEnabled(len(self.page.cameras) < MAX_CAMERAS)
        self.setWindowTitle(f"CCTV library  ·  {len(self.page.cameras)}/{MAX_CAMERAS}  ·  wall {pinned}/{WALL_SLOTS}")

    def _selected_id(self) -> str:
        item = self.list.currentItem()
        return item.data(Qt.ItemDataRole.UserRole) if item else ""

    def _add(self) -> None:
        if len(self.page.cameras) >= MAX_CAMERAS:
            return
        dialog = CameraDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        cam = dialog.camera()
        cam["id"] = uuid.uuid4().hex[:12]
        cam["name"] = f"CAM {len(self.page.cameras)+1:02d}"
        cam["pinned"] = sum(1 for row in self.page.cameras if row.get("pinned")) < WALL_SLOTS
        self.page.cameras.append(cam)
        self.page.save_and_refresh()
        self._reload()

    def _edit(self) -> None:
        cam_id = self._selected_id()
        cam = self.page.camera_by_id(cam_id)
        if not cam:
            return
        dialog = CameraDialog(self, cam)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        cam.update(dialog.camera())
        self.page.save_and_refresh()
        self._reload()

    def _remove(self) -> None:
        cam_id = self._selected_id()
        if not cam_id:
            return
        self.page.cameras = [cam for cam in self.page.cameras if cam.get("id") != cam_id]
        self.page.save_and_refresh()
        self._reload()

    def _pin(self) -> None:
        cam_id = self._selected_id()
        cam = self.page.camera_by_id(cam_id)
        if not cam:
            return
        if cam.get("pinned"):
            cam["pinned"] = False
        else:
            pinned = sum(1 for row in self.page.cameras if row.get("pinned"))
            if pinned >= WALL_SLOTS:
                QMessageBox.information(self, "Wall full", "The wall already has 4 cameras. Take one off first.")
                return
            cam["pinned"] = True
        self.page.save_and_refresh()
        self._reload()


class CctvWallWindow(QWidget):
    """Fullscreen monitor. Feeds only. Esc closes it."""

    def __init__(self, cameras: list[dict], pool: VlcPool, on_closed=None, parent=None):
        self.on_closed = on_closed
        super().__init__(parent)
        self.setWindowTitle("DedSec CCTV")
        self.setWindowFlag(Qt.WindowType.Window, True)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        self.cameras = [dict(cam) for cam in cameras[:WALL_SLOTS]]
        self.pool = pool
        self.setStyleSheet("""
            QWidget { background: #000; }
            QFrame#CctvBar { background: #10141a; border-top: 1px solid #2a3340; }
            QLabel#CctvSlot { color: #d5dde8; font-family: Consolas, monospace; font-size: 11px; }
            QPushButton#CctvIcon {
                background: #1a222c; color: #e8eef6; border: 1px solid #3c4a5c;
                border-radius: 2px; font-family: Consolas, monospace; font-size: 11px;
                font-weight: 700; min-width: 54px; max-height: 28px;
            }
            QPushButton#CctvOn { background: #14361f; color: #7dffb0; border: 1px solid #2fbf6a; font-family: Consolas, monospace; font-size: 11px; font-weight: 700; letter-spacing: 1px; }
            QLabel#CctvEsc { color: #9fb0c3; font-family: Consolas, monospace; font-size: 12px; letter-spacing: 1px; }
        """)
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)
        top = QHBoxLayout()
        top.addStretch()
        esc = QLabel("PRESS ESC TO CLOSE")
        esc.setObjectName("CctvEsc")
        top.addWidget(esc)
        root.addLayout(top)
        grid_host = QWidget()
        grid = QGridLayout(grid_host)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(6)
        self.tiles = []
        for index in range(WALL_SLOTS):
            tile = CameraTile(index + 1)
            self.tiles.append(tile)
            grid.addWidget(tile, index // 2, index % 2)
        grid.setRowStretch(0, 1)
        grid.setRowStretch(1, 1)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        root.addWidget(grid_host, 1)
        self._arm_tiles()

    def _arm_tiles(self) -> None:
        for index, tile in enumerate(self.tiles):
            cam = self.cameras[index] if index < len(self.cameras) else None
            if not cam:
                tile.show_empty()
                continue
            if not self.pool.ready:
                tile.show_error(self.pool.detail)
                continue
            tile.show_ready()
            tile.play_btn.clicked.connect(lambda _=False, i=index: self.toggle_play(i))
            tile.mute_btn.clicked.connect(lambda _=False, i=index: self.toggle_mute(i, not getattr(self.tiles[i], '_muted', False)))
            tile.info_btn.clicked.connect(lambda _=False, i=index: self.show_info(i))

    def toggle_play(self, index: int) -> None:
        cam = self.cameras[index]
        tile = self.tiles[index]
        key = f"fs-{index}"
        if key in self.pool._players:
            self.pool.stop(key)
            tile.show_ready()
            return
        tile.video.winId()
        ok = self.pool.play(key, cam.get("rtsp", ""), tile.video)
        tile.show_live() if ok else tile.show_error("STREAM FAILED")

    def toggle_mute(self, index: int, checked: bool) -> None:
        player = self.pool._players.get(f"fs-{index}")
        if not player:
            return
        try:
            player.audio_set_mute(checked)
        except Exception:
            pass
        btn = self.tiles[index].mute_btn
        btn.setText("MUTED" if checked else "MUTE")
        _paint_btn(btn, checked)

    def show_info(self, index: int) -> None:
        cam = self.cameras[index] if index < len(self.cameras) else None
        if cam:
            show_stream_info(self, cam.get("rtsp", ""))

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            self.close()
            return
        super().keyPressEvent(event)

    def closeEvent(self, event):
        for key in list(self.pool._players):
            if str(key).startswith("fs-"):
                self.pool.stop(key)
        if self.on_closed:
            try:
                self.on_closed()
            except Exception:
                pass
        super().closeEvent(event)


class CctvPage(QWidget):
    def __init__(self, app_window=None):
        super().__init__()
        self.app_window = app_window
        self.cameras: list[dict] = []
        self.pool = VlcPool()
        self._wall = None
        self._build()
        self._apply_style()
        self.load()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 12, 16, 12)
        root.setSpacing(10)
        header = QHBoxLayout()
        title_box = QVBoxLayout()
        title_box.setSpacing(2)
        title = QLabel("CCTV")
        title.setObjectName("PageTitle")
        subtitle = QLabel("Private wall  ·  your RTSP only  ·  unused slots stay offline")
        subtitle.setObjectName("StatusLine")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header.addLayout(title_box)
        header.addStretch()
        self.count_badge = QLabel("0 / 4")
        self.count_badge.setObjectName("ActionsLiveBadge")
        self.library_btn = QPushButton("Camera library")
        self.library_btn.setObjectName("ActionButton_cyan")
        self.library_btn.clicked.connect(self.open_library)
        self.full_btn = QPushButton("Full screen")
        self.full_btn.setObjectName("ActionButton_green")
        self.full_btn.clicked.connect(self.open_fullscreen)
        header.addWidget(self.count_badge)
        header.addWidget(self.library_btn)
        header.addWidget(self.full_btn)
        root.addLayout(header)

        wall = QFrame()
        wall.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        grid = QGridLayout(wall)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(10)
        self.tiles = []
        for index in range(WALL_SLOTS):
            tile = CameraTile(index + 1)
            self.tiles.append(tile)
            grid.addWidget(tile, index // 2, index % 2)
        grid.setRowStretch(0, 1)
        grid.setRowStretch(1, 1)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        root.addWidget(wall, 1)
        footer = QLabel("Empty slots stay offline. Play starts a saved stream. Full screen plays after the window opens. Esc closes it.")
        footer.setObjectName("StatusLine")
        root.addWidget(footer)

    def _apply_style(self) -> None:
        self.setStyleSheet("""
            QFrame#CctvTile {
                background: #07090c;
                border: 1px solid #2a3340;
                border-radius: 2px;
            }
            QFrame#CctvVideo { background: #000; border: none; }
            QLabel#CctvWatermark {
                color: #ff3b3b;
                font-family: Consolas, monospace;
                font-weight: 800;
                letter-spacing: 4px;
                background: rgba(0, 0, 0, 0.78);
            }
            QFrame#CctvBar { background: #10141a; border-top: 1px solid #2a3340; }
            QLabel#CctvSlot { color: #d5dde8; font-family: Consolas, monospace; font-size: 11px; letter-spacing: 1px; }
            QPushButton#CctvIcon {
                background: #1a222c;
                color: #e8eef6;
                border: 1px solid #3c4a5c;
                border-radius: 2px;
                font-family: Consolas, monospace;
                font-size: 11px;
                font-weight: 700;
                letter-spacing: 1px;
                padding: 0 8px;
            }
            QPushButton#CctvIcon:hover { background: #243140; border-color: #6d89a8; }
            QPushButton#CctvIcon:checked, QPushButton#CctvOn {
                background: #14361f; color: #7dffb0; border: 1px solid #2fbf6a;
                font-family: Consolas, monospace; font-size: 11px; font-weight: 700; letter-spacing: 1px;
                padding: 0px; min-width: 64px; max-width: 64px; min-height: 28px; max-height: 28px;
            }
            QLabel#CctvEsc { color: #9fb0c3; font-family: Consolas, monospace; font-size: 12px; letter-spacing: 1px; }
        """)

    def load(self) -> None:
        path = _store_path()
        self.cameras = []
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                rows = data.get("cameras", []) if isinstance(data, dict) else []
                for row in rows[:MAX_CAMERAS]:
                    if not isinstance(row, dict) or not _valid_rtsp(row.get("rtsp", "")):
                        continue
                    self.cameras.append({
                        "id": str(row.get("id") or uuid.uuid4().hex[:12]),
                        "name": str(row.get("name") or "Camera")[:40],
                        "rtsp": str(row.get("rtsp")).strip(),
                        "pinned": bool(row.get("pinned")),
                    })
            except Exception:
                self.cameras = []
        self._cap_pins()
        QTimer.singleShot(250, self.refresh)

    def _cap_pins(self) -> None:
        kept = 0
        for cam in self.cameras:
            if cam.get("pinned") and kept < WALL_SLOTS:
                kept += 1
            else:
                cam["pinned"] = False

    def save_and_refresh(self) -> None:
        self._cap_pins()
        try:
            _store_path().write_text(json.dumps({"cameras": self.cameras[:MAX_CAMERAS]}, indent=2), encoding="utf-8")
        except Exception:
            pass
        self.refresh()

    def camera_by_id(self, cam_id: str) -> dict | None:
        for cam in self.cameras:
            if cam.get("id") == cam_id:
                return cam
        return None

    def refresh(self) -> None:
        if self._wall is not None:
            return
        self.pool.stop_all()
        pinned = [cam for cam in self.cameras if cam.get("pinned")][:WALL_SLOTS]
        self._pinned = pinned
        for index, tile in enumerate(self.tiles):
            cam = pinned[index] if index < len(pinned) else None
            try:
                tile.play_btn.clicked.disconnect()
            except Exception:
                pass
            if not cam:
                tile.show_empty()
                continue
            if not self.pool.ready:
                tile.show_error(self.pool.detail)
                continue
            tile.show_ready()
            tile.play_btn.clicked.connect(lambda _=False, i=index: self.toggle_play(i))
            tile.mute_btn.clicked.connect(lambda _=False, i=index: self.toggle_mute(i, not getattr(self.tiles[i], '_muted', False)))
            tile.info_btn.clicked.connect(lambda _=False, i=index: self.show_info(i))
        self.count_badge.setText(f"{len(self.cameras)} / {MAX_CAMERAS}")

    def toggle_mute(self, index: int, checked: bool) -> None:
        player = self.pool._players.get(f"wall-{index}")
        if player:
            try:
                player.audio_set_mute(checked)
            except Exception:
                pass
        tile = self.tiles[index]
        tile._muted = checked
        btn = tile.mute_btn
        btn.setText("MUTED" if checked else "MUTE")
        _paint_btn(btn, checked)

    def show_info(self, index: int) -> None:
        cam = self._pinned[index] if index < len(getattr(self, "_pinned", [])) else None
        if not cam:
            return
        show_stream_info(self, cam.get("rtsp", ""))

    def toggle_play(self, index: int) -> None:
        if self._wall is not None:
            return
        cam = self._pinned[index] if index < len(self._pinned) else None
        tile = self.tiles[index]
        key = f"wall-{index}"
        if key in self.pool._players:
            self.pool.stop(key)
            tile.show_ready()
            return
        tile.video.winId()
        ok = self.pool.play(key, cam.get("rtsp", ""), tile.video)
        if ok:
            tile.show_live()
        else:
            tile.show_error("STREAM FAILED")

    def open_library(self) -> None:
        LibraryDialog(self).exec()

    def open_fullscreen(self) -> None:
        pinned = [cam for cam in self.cameras if cam.get("pinned")][:WALL_SLOTS]
        if not pinned:
            QMessageBox.information(self, "CCTV", "Add a camera and put it on the wall first.")
            return
        if self._wall is not None:
            try:
                self._wall.close()
            except Exception:
                pass
            self._wall = None
        for key in list(self.pool._players):
            if str(key).startswith("wall-"):
                self.pool.stop(key)
        for tile in self.tiles:
            if tile.play_btn is not None and not tile.watermark.text().startswith("STREAM OFFLINE"):
                tile.show_held()
        self._wall = CctvWallWindow(pinned, self.pool, on_closed=self._wall_closed)
        self._wall.show()
        self._wall.showFullScreen()

    def _wall_closed(self) -> None:
        self._wall = None
        self.refresh()

    def closeEvent(self, event):
        self.pool.stop_all()
        wall = self._wall
        self._wall = None
        if wall is not None:
            wall.on_closed = None
            wall.close()
        super().closeEvent(event)
