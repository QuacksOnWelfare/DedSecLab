"""
John the Ripper panel - API front-end (VPN + one-time token).
Features:
  - Big cracked-password display
  - Server wordlists from /api/john/status
  - Custom wordlist import from PC (uploaded to server)
"""
from __future__ import annotations

import json
import re
import ssl
from core.tls import LabTLSError, ssl_context_for
import urllib.error
import urllib.request
from pathlib import Path

from PyQt6.QtCore import Qt, QThread, pyqtSignal

# TLS via core.tls.ssl_context_for (pinned lab CA).
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QPushButton,
    QFrame, QLineEdit, QTextEdit, QComboBox, QFileDialog, QMessageBox,
    QSizePolicy, QScrollArea, QCheckBox,
)


class ApiWorker(QThread):
    finished_ok = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(
        self,
        method: str,
        url: str,
        body: dict | None = None,
        raw_body: bytes | None = None,
        headers: dict | None = None,
        timeout: int = 3700,
        parent=None,
    ):
        super().__init__(parent)
        self.method = method.upper()
        self.url = url
        self.body = body
        self.raw_body = raw_body
        self.headers = headers or {}
        self.timeout = timeout

    def run(self):
        try:
            data = self.raw_body
            headers = dict(self.headers)
            if self.body is not None:
                data = json.dumps(self.body).encode("utf-8")
                headers.setdefault("Content-Type", "application/json")
            req = urllib.request.Request(
                self.url,
                data=data,
                headers=headers,
                method=self.method,
            )
            with urllib.request.urlopen(req, timeout=self.timeout, context=ssl_context_for(self.url)) as resp:
                raw = resp.read().decode("utf-8", errors="ignore")
                try:
                    payload = json.loads(raw) if raw else {}
                except Exception:
                    payload = {"ok": False, "reason": raw[:500]}
                self.finished_ok.emit(payload)
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode("utf-8", errors="ignore")
                payload = json.loads(body)
                reason = payload.get("reason") or payload.get("detail") or body[:400]
                if isinstance(reason, list):
                    reason = str(reason)
            except Exception:
                reason = str(e)
            self.failed.emit(str(reason))
        except Exception as e:
            self.failed.emit(str(e))


class JohnPanel(QWidget):
    # Max custom wordlist upload size (bytes) - keep sane for VPN/API
    MAX_UPLOAD_BYTES = 8 * 1024 * 1024  # 8 MB

    def __init__(self, app_window=None):
        super().__init__()
        self.app_window = app_window
        self._worker = None
        self._pending_action = None  # "status" | "start" | "show" | "upload"
        self._custom_wordlist_path: Path | None = None
        self._custom_wordlist_name: str | None = None
        self._last_cracked: str | None = None
        self._build_ui()
        # Soft auto-refresh wordlists after UI is up
        self.check_status(silent=True)

    # ------------------------------------------------------------------ UI helpers
    def _card(self, title: str) -> tuple[QFrame, QVBoxLayout]:
        frame = QFrame()
        frame.setObjectName("ActionsPanel")
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(10)
        t = QLabel(title.upper())
        t.setObjectName("ActionsPanelTitle")
        lay.addWidget(t)
        return frame, lay

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        outer.addWidget(scroll)

        body = QWidget()
        scroll.setWidget(body)
        root = QVBoxLayout(body)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(12)

        # Header
        header = QLabel("JOHN THE RIPPER  ·  VPN API")
        header.setObjectName("PageTitle")
        sub = QLabel(
            "Lab-only · VPN + one-time token · only crack hashes you are authorized to test"
        )
        sub.setObjectName("StatusLine")
        root.addWidget(header)
        root.addWidget(sub)

        # ---- BIG PASSWORD RESULT ----
        self.pass_card, pl = self._card("Cracked password")
        self.pass_hint = QLabel("No password cracked yet - run an attack, then Show cracked")
        self.pass_hint.setObjectName("ActionsHeroDetail")
        self.pass_hint.setWordWrap(True)

        self.pass_display = QLabel("-")
        self.pass_display.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.pass_display.setWordWrap(True)
        self.pass_display.setMinimumHeight(72)
        self.pass_display.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        font = QFont()
        font.setFamily("Consolas")
        font.setPointSize(28)
        font.setBold(True)
        self.pass_display.setFont(font)
        self.pass_display.setStyleSheet(
            "QLabel {"
            "  background: #070a10;"
            "  color: #50ff85;"
            "  border: 1px solid #1a3a28;"
            "  border-radius: 10px;"
            "  padding: 16px 12px;"
            "}"
        )

        pass_btns = QHBoxLayout()
        self.btn_copy_pass = QPushButton("Copy password")
        self.btn_copy_pass.setObjectName("ActionButton_green")
        self.btn_copy_pass.setEnabled(False)
        self.btn_copy_pass.clicked.connect(self.copy_password)
        self.btn_clear_pass = QPushButton("Clear")
        self.btn_clear_pass.setObjectName("ActionButton_blue")
        self.btn_clear_pass.clicked.connect(self.clear_password_display)
        pass_btns.addWidget(self.btn_copy_pass)
        pass_btns.addWidget(self.btn_clear_pass)
        pass_btns.addStretch()

        pl.addWidget(self.pass_hint)
        pl.addWidget(self.pass_display)
        pl.addLayout(pass_btns)
        root.addWidget(self.pass_card)

        # ---- HASH ----
        hash_card, hl = self._card("Hash")
        self.hash_edit = QTextEdit()
        self.hash_edit.setPlaceholderText("Paste hash here (one per line)...")
        self.hash_edit.setFixedHeight(88)
        row = QHBoxLayout()
        btn_load = QPushButton("Load file")
        btn_load.setObjectName("ActionButton_blue")
        btn_load.clicked.connect(self.load_hash_file)
        btn_detect = QPushButton("Detect type")
        btn_detect.setObjectName("ActionButton_cyan")
        btn_detect.clicked.connect(self.detect_local)
        row.addWidget(btn_load)
        row.addWidget(btn_detect)
        row.addStretch()
        hl.addWidget(self.hash_edit)
        hl.addLayout(row)
        root.addWidget(hash_card)

        # ---- OPTIONS ----
        opt_card, ol = self._card("Options")
        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(10)

        grid.addWidget(QLabel("Format"), 0, 0)
        self.format_box = QComboBox()
        self.format_box.setObjectName("EmulatorCombo")
        self.format_box.addItems([
            "Raw-MD5", "Raw-SHA1", "Raw-SHA256", "Raw-SHA512",
            "NT", "bcrypt", "sha512crypt", "md5crypt", "sha256crypt",
            "Auto",
        ])
        # Default to Raw-MD5 so the demo hash works without surprises
        self.format_box.setCurrentText("Raw-MD5")
        grid.addWidget(self.format_box, 0, 1)

        grid.addWidget(QLabel("Wordlist"), 1, 0)
        wl_row = QHBoxLayout()
        self.wordlist_box = QComboBox()
        self.wordlist_box.setObjectName("EmulatorCombo")
        self.wordlist_box.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.wordlist_box.addItem("rockyou.txt")
        self.wordlist_box.addItem("password.lst")
        self.wordlist_box.addItem("- Custom (from this PC) -")
        self.wordlist_box.currentIndexChanged.connect(self._on_wordlist_changed)
        wl_row.addWidget(self.wordlist_box, 1)

        self.btn_import_wl = QPushButton("Import...")
        self.btn_import_wl.setObjectName("ActionButton_cyan")
        self.btn_import_wl.setToolTip("Import a custom wordlist from your PC (uploaded to the lab server)")
        self.btn_import_wl.clicked.connect(self.import_custom_wordlist)
        wl_row.addWidget(self.btn_import_wl)
        grid.addLayout(wl_row, 1, 1)

        self.custom_wl_label = QLabel("No custom wordlist selected")
        self.custom_wl_label.setObjectName("ActionsHeroDetail")
        self.custom_wl_label.setWordWrap(True)
        grid.addWidget(QLabel("Custom file"), 2, 0)
        grid.addWidget(self.custom_wl_label, 2, 1)

        grid.addWidget(QLabel("API"), 3, 0)
        self.api_label = QLabel("VPN · token auth · same as Terminal")
        self.api_label.setObjectName("ActionsHeroDetail")
        grid.addWidget(self.api_label, 3, 1)

        ol.addLayout(grid)
        root.addWidget(opt_card)

        # ---- CUPP (generate wordlist from profile) ----
        cupp_card, cl = self._card("CUPP · generate wordlist")
        cl.addWidget(QLabel(
            "Lab only - profile fields -> custom wordlist on the server (same idea as cupp -i)"
        ))
        cg = QGridLayout()
        cg.setHorizontalSpacing(10)
        cg.setVerticalSpacing(6)

        def _line(placeholder=""):
            e = QLineEdit()
            e.setPlaceholderText(placeholder)
            return e

        self.cupp_first = _line("First name")
        self.cupp_surname = _line("Surname")
        self.cupp_nick = _line("Nickname")
        self.cupp_birth = _line("Birthdate DDMMYYYY")
        self.cupp_partner = _line("Partner name")
        self.cupp_partner_nick = _line("Partner nickname")
        self.cupp_partner_birth = _line("Partner birth DDMMYYYY")
        self.cupp_child = _line("Child name")
        self.cupp_child_nick = _line("Child nickname")
        self.cupp_child_birth = _line("Child birth DDMMYYYY")
        self.cupp_pet = _line("Pet name")
        self.cupp_company = _line("Company")
        self.cupp_keywords = _line("Extra keywords (comma separated)")

        fields = [
            (0, "First name", self.cupp_first),
            (1, "Surname", self.cupp_surname),
            (2, "Nickname", self.cupp_nick),
            (3, "Birthdate", self.cupp_birth),
            (4, "Partner", self.cupp_partner),
            (5, "Partner nick", self.cupp_partner_nick),
            (6, "Partner birth", self.cupp_partner_birth),
            (7, "Child", self.cupp_child),
            (8, "Child nick", self.cupp_child_nick),
            (9, "Child birth", self.cupp_child_birth),
            (10, "Pet", self.cupp_pet),
            (11, "Company", self.cupp_company),
            (12, "Keywords", self.cupp_keywords),
        ]
        for row, label, widget in fields:
            cg.addWidget(QLabel(label), row, 0)
            cg.addWidget(widget, row, 1)

        opt_row = QHBoxLayout()
        self.cupp_special = QCheckBox("Special chars")
        self.cupp_special.setChecked(True)
        self.cupp_numbers = QCheckBox("Random numbers")
        self.cupp_numbers.setChecked(True)
        self.cupp_leet = QCheckBox("Leet mode")
        self.cupp_leet.setChecked(False)
        opt_row.addWidget(self.cupp_special)
        opt_row.addWidget(self.cupp_numbers)
        opt_row.addWidget(self.cupp_leet)
        opt_row.addStretch()

        self.btn_cupp = QPushButton("Generate wordlist (CUPP)")
        self.btn_cupp.setObjectName("ActionButton_cyan")
        self.btn_cupp.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_cupp.setMinimumHeight(36)
        self.btn_cupp.clicked.connect(self.run_cupp)

        cl.addLayout(cg)
        cl.addLayout(opt_row)
        cl.addWidget(self.btn_cupp)
        root.addWidget(cupp_card)

        # ---- ACTIONS ----
        actions = QHBoxLayout()
        self.btn_status = QPushButton("Check John / VPS")
        self.btn_status.setObjectName("ActionButton_cyan")
        self.btn_status.clicked.connect(lambda: self.check_status(silent=False))

        self.btn_run = QPushButton("Start attack")
        self.btn_run.setObjectName("ActionButton_green")
        self.btn_run.clicked.connect(self.start_john)

        self.btn_show = QPushButton("Show cracked")
        self.btn_show.setObjectName("ActionButton_blue")
        self.btn_show.clicked.connect(self.show_cracked)

        for b in (
            self.btn_status, self.btn_run, self.btn_show,
            btn_load, btn_detect, self.btn_import_wl,
            self.btn_copy_pass, self.btn_clear_pass, self.btn_cupp,
        ):
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setMinimumHeight(36)

        actions.addWidget(self.btn_status)
        actions.addWidget(self.btn_run)
        actions.addWidget(self.btn_show)
        actions.addStretch()
        root.addLayout(actions)

        # ---- OUTPUT LOG ----
        log_card, ll = self._card("Output")
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setMinimumHeight(160)
        self.log.setStyleSheet(
            "background:#070a10; color:#50ff85; font-family: Consolas, monospace;"
        )
        ll.addWidget(self.log)
        root.addWidget(log_card, 1)

        root.addStretch(0)

    # ------------------------------------------------------------------ helpers
    def _server_base(self) -> str:
        if self.app_window and hasattr(self.app_window, "config"):
            url = self.app_window.config.get("server_url", "https://YOUR_LAB_VPN_IP:8443")
        else:
            url = "https://YOUR_LAB_VPN_IP:8443"
        return str(url).strip().rstrip("/")

    def _append(self, text: str):
        self.log.append(text)
        if self.app_window and hasattr(self.app_window, "add_log"):
            try:
                self.app_window.add_log(f"[John] {text[:120]}")
            except Exception:
                pass

    def _set_busy(self, busy: bool):
        self.btn_run.setEnabled(not busy)
        self.btn_status.setEnabled(not busy)
        self.btn_show.setEnabled(not busy)
        self.btn_import_wl.setEnabled(not busy)
        if hasattr(self, "btn_cupp"):
            self.btn_cupp.setEnabled(not busy)

    def _require_login(self) -> bool:
        if not self.app_window:
            return True
        user = None
        if hasattr(self.app_window, "server"):
            user = getattr(self.app_window.server, "user", None)
        if not user:
            QMessageBox.warning(self, "Not logged in", "Login first (same as Terminal).")
            return False
        return True

    def _run_api(
        self,
        method: str,
        path: str,
        body: dict | None = None,
        note: str = "",
        action: str = "",
        timeout: int = 3700,
    ):
        if self._worker and self._worker.isRunning():
            QMessageBox.information(self, "Busy", "A John request is already running.")
            return
        if note:
            self._append(note)
        self._pending_action = action
        self._set_busy(True)
        url = self._server_base() + path
        self._worker = ApiWorker(method, url, body=body, timeout=timeout)
        self._worker.finished_ok.connect(self._on_ok)
        self._worker.failed.connect(self._on_fail)
        self._worker.start()

    def _fetch_token_sync(self) -> str | None:
        url = self._server_base() + "/api/john/token"
        try:
            req = urllib.request.Request(
                url,
                data=b"{}",
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=12, context=ssl_context_for(url)) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
            if data.get("ok") and data.get("token"):
                return data["token"]
            self._append(f"TOKEN ERROR: {data.get('reason', data)}")
            return None
        except Exception as e:
            self._append(f"TOKEN ERROR: {e}")
            return None

    # ------------------------------------------------------------------ password display
    def set_password_display(self, password: str | None, raw_show: str = ""):
        if password:
            self._last_cracked = password
            self.pass_display.setText(password)
            self.pass_hint.setText("Cracked - shown large below (lab use only)")
            self.btn_copy_pass.setEnabled(True)
            self.pass_display.setStyleSheet(
                "QLabel {"
                "  background: #071410;"
                "  color: #50ff85;"
                "  border: 2px solid #50ff85;"
                "  border-radius: 10px;"
                "  padding: 16px 12px;"
                "}"
            )
        else:
            self._last_cracked = None
            self.pass_display.setText("-")
            self.pass_hint.setText(
                "No clear password in result"
                + (f" · raw: {raw_show[:80]}" if raw_show else "")
            )
            self.btn_copy_pass.setEnabled(False)
            self.pass_display.setStyleSheet(
                "QLabel {"
                "  background: #070a10;"
                "  color: #50ff85;"
                "  border: 1px solid #1a3a28;"
                "  border-radius: 10px;"
                "  padding: 16px 12px;"
                "}"
            )

    def clear_password_display(self):
        self.set_password_display(None)
        self.pass_hint.setText("No password cracked yet - run an attack, then Show cracked")

    def copy_password(self):
        if not self._last_cracked:
            return
        from PyQt6.QtWidgets import QApplication
        QApplication.clipboard().setText(self._last_cracked)
        self._append("Password copied to clipboard.")

    @staticmethod
    def _extract_password(show_text: str) -> str | None:
        """
        Parse john --show lines.
        Common forms:
          hash:password
          user:password
          ?:password
        """
        if not show_text:
            return None
        text = show_text.strip()
        # Prefer last non-empty data line
        for line in reversed(text.splitlines()):
            line = line.strip()
            if not line or line.lower().startswith("0 password") or "cracked" in line.lower():
                continue
            if ":" in line:
                # Take everything after the last colon (passwords can contain ':')
                # Actually john uses first colon as separator for hash:pass - but
                # for safety take after first colon when left side looks like hash/?/user
                left, right = line.split(":", 1)
                pwd = right.strip()
                if pwd and pwd != "?":
                    return pwd
        # Fallback: "password hash cracked" messages without detail
        m = re.search(r":\s*([^\s:]+)\s*$", text, re.MULTILINE)
        if m:
            return m.group(1)
        return None

    # ------------------------------------------------------------------ wordlists
    def _on_wordlist_changed(self, _idx: int):
        is_custom = self.wordlist_box.currentText().startswith("- Custom")
        self.btn_import_wl.setEnabled(True)
        if is_custom and not self._custom_wordlist_path:
            self.custom_wl_label.setText("Click Import... to choose a .txt wordlist from this PC")
        elif is_custom and self._custom_wordlist_path:
            self.custom_wl_label.setText(
                f"Ready: {self._custom_wordlist_path.name}"
                + (f" -> server as {self._custom_wordlist_name}" if self._custom_wordlist_name else "")
            )
        else:
            self.custom_wl_label.setText("Using server wordlist")

    def import_custom_wordlist(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Import wordlist",
            "",
            "Wordlists (*.txt *.lst *.dic);;All files (*.*)",
        )
        if not path:
            return
        p = Path(path)
        try:
            size = p.stat().st_size
        except OSError as e:
            QMessageBox.warning(self, "Import", f"Cannot read file:\n{e}")
            return
        if size <= 0:
            QMessageBox.warning(self, "Import", "File is empty.")
            return
        if size > self.MAX_UPLOAD_BYTES:
            QMessageBox.warning(
                self,
                "Import",
                f"File is too large ({size // (1024*1024)} MB).\n"
                f"Max upload is {self.MAX_UPLOAD_BYTES // (1024*1024)} MB.\n\n"
                "Put large lists on the server under /opt/john-menu/wordlists/ instead.",
            )
            return

        self._custom_wordlist_path = p
        # Select custom entry in combo
        for i in range(self.wordlist_box.count()):
            if self.wordlist_box.itemText(i).startswith("- Custom"):
                self.wordlist_box.setCurrentIndex(i)
                break
        self.custom_wl_label.setText(f"Selected: {p.name} ({size // 1024} KB) - will upload on Start")
        self._append(f"Custom wordlist selected: {p} ({size} bytes)")
        self.wordlist_box.setEnabled(True)

    def _populate_wordlists(self, names: list):
        current = self.wordlist_box.currentText()
        self.wordlist_box.blockSignals(True)
        self.wordlist_box.clear()
        for n in names:
            if n and not str(n).startswith("-"):
                self.wordlist_box.addItem(str(n))
        if self.wordlist_box.count() == 0:
            self.wordlist_box.addItem("rockyou.txt")
            self.wordlist_box.addItem("password.lst")
        self.wordlist_box.addItem("- Custom (from this PC) -")
        # restore selection if possible
        idx = self.wordlist_box.findText(current)
        if idx >= 0:
            self.wordlist_box.setCurrentIndex(idx)
        self.wordlist_box.blockSignals(False)
        self._on_wordlist_changed(self.wordlist_box.currentIndex())

    def _selected_wordlist_name(self) -> str | None:
        text = self.wordlist_box.currentText()
        if text.startswith("- Custom"):
            # Prefer server-side name after upload
            if self._custom_wordlist_name:
                return self._custom_wordlist_name
            if self._custom_wordlist_path:
                return self._custom_wordlist_path.name
            return None
        return text.strip() or None

    def _upload_custom_wordlist_sync(self) -> str | None:
        """Upload local file to server; returns server wordlist filename or None."""
        if not self._custom_wordlist_path or not self._custom_wordlist_path.is_file():
            self._append("No custom wordlist file selected.")
            return None

        token = self._fetch_token_sync()
        if not token:
            return None

        data = self._custom_wordlist_path.read_bytes()
        # JSON upload keeps API simple (no multipart dependency)
        body = {
            "token": token,
            "filename": self._custom_wordlist_path.name,
            "content": data.decode("utf-8", errors="ignore"),
        }
        url = self._server_base() + "/api/john/wordlist"
        self._append(f"Uploading wordlist {self._custom_wordlist_path.name}...")
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(body).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=120, context=ssl_context_for(url)) as resp:
                payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
            if not payload.get("ok"):
                self._append(f"UPLOAD ERROR: {payload.get('reason', payload)}")
                return None
            name = payload.get("filename") or self._custom_wordlist_path.name
            self._custom_wordlist_name = name
            self.custom_wl_label.setText(f"Uploaded on server: {name}")
            self._append(f"Uploaded OK -> {name}")
            # Refresh dropdown so it appears in the list
            if self.wordlist_box.findText(name) < 0:
                # insert before Custom entry
                custom_idx = self.wordlist_box.count() - 1
                self.wordlist_box.insertItem(max(0, custom_idx), name)
            return name
        except urllib.error.HTTPError as e:
            try:
                err = e.read().decode("utf-8", errors="ignore")
            except Exception:
                err = str(e)
            self._append(f"UPLOAD ERROR: {err}")
            if "404" in str(e) or "Not Found" in str(err):
                self._append(
                    "Server is missing /api/john/wordlist - add the upload route on the VPS."
                )
            return None
        except Exception as e:
            self._append(f"UPLOAD ERROR: {e}")
            return None

    # ------------------------------------------------------------------ API callbacks
    def _on_ok(self, data):
        self._set_busy(False)
        action = self._pending_action
        self._pending_action = None

        if not isinstance(data, dict):
            self._append(str(data))
            return

        if data.get("ok") is False and data.get("reason"):
            self._append(f"ERROR: {data.get('reason')}")
            return

        # status
        if "john" in data or action == "status":
            self._append(
                f"John: {data.get('john')}  |  VPN: {data.get('vpn_ip')}  |  "
                f"wordlists: {', '.join(data.get('wordlists') or []) or '(none)'}"
            )
            wls = data.get("wordlists") or []
            if isinstance(wls, list) and wls:
                self._populate_wordlists([str(x) for x in wls])
            job = data.get("job")
            if job:
                self._append(
                    f"Last job: {job.get('session')}  format={job.get('format')}  "
                    f"wl={job.get('wordlist')}  exit={job.get('exit_code')}"
                )
            return

        # start result
        if "session" in data and ("log_tail" in data or "show" in data or action == "start"):
            self._append(f"Session: {data.get('session')}  exit={data.get('exit_code')}")
            if data.get("log_tail"):
                self._append("--- log ---")
                self._append(str(data["log_tail"]))
            show = data.get("show") or ""
            if show:
                self._append("--- show ---")
                self._append(str(show))
                pwd = self._extract_password(str(show))
                self.set_password_display(pwd, str(show))
                if pwd:
                    self._append(f"PASSWORD: {pwd}")
            return

        # show only
        if "show" in data or action == "show":
            show = str(data.get("show") or "")
            self._append(f"Session: {data.get('session', '')}")
            self._append(show or "(empty)")
            pwd = self._extract_password(show)
            self.set_password_display(pwd, show)
            if pwd:
                self._append(f"PASSWORD: {pwd}")
            return

        # CUPP generate
        if action == "cupp" or data.get("filename"):
            name = data.get("filename")
            count = data.get("word_count")
            self._append(
                f"CUPP OK -> {name}"
                + (f" ({count} words)" if count is not None else "")
            )
            if name:
                # Add to dropdown and select it
                if self.wordlist_box.findText(name) < 0:
                    custom_idx = self.wordlist_box.count() - 1
                    self.wordlist_box.insertItem(max(0, custom_idx), name)
                self.wordlist_box.setCurrentText(name)
                self.custom_wl_label.setText(f"Using CUPP list: {name}")
            if data.get("hint"):
                self._append(str(data["hint"]))
            return

        self._append(json.dumps(data, indent=2)[:2000])

    def _on_fail(self, err: str):
        self._set_busy(False)
        self._pending_action = None
        self._append(f"ERROR: {err}")

    # ------------------------------------------------------------------ actions
    def load_hash_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Hash file", "", "Text (*.txt);;All (*.*)"
        )
        if path:
            self.hash_edit.setPlainText(Path(path).read_text(errors="ignore"))

    def detect_local(self):
        raw = self.hash_edit.toPlainText().strip().splitlines()
        if not raw:
            QMessageBox.warning(self, "Detect", "Paste a hash first.")
            return
        value = raw[0].strip()
        detected = self._detect_value(value)
        self._append(f"Detect: {detected}  ←  {value[:64]}")
        # Auto-select format when we know it (skip Auto)
        if detected != "Unknown":
            idx = self.format_box.findText(detected)
            if idx >= 0:
                self.format_box.setCurrentIndex(idx)

    @staticmethod
    def _detect_value(value: str) -> str:
        v = value.strip()
        if v.startswith("$2"):
            return "bcrypt"
        if v.startswith("$6$"):
            return "sha512crypt"
        if v.startswith("$5$"):
            return "sha256crypt"
        if v.startswith("$1$"):
            return "md5crypt"
        if len(v) == 32 and re.fullmatch(r"[0-9a-fA-F]+", v):
            return "Raw-MD5"
        if len(v) == 40 and re.fullmatch(r"[0-9a-fA-F]+", v):
            return "Raw-SHA1"
        if len(v) == 64 and re.fullmatch(r"[0-9a-fA-F]+", v):
            return "Raw-SHA256"
        if len(v) == 128 and re.fullmatch(r"[0-9a-fA-F]+", v):
            return "Raw-SHA512"
        return "Unknown"

    def check_status(self, silent: bool = False):
        note = "" if silent else "Checking John API..."
        self._run_api("GET", "/api/john/status", note=note, action="status", timeout=15)

    def start_john(self):
        if not self._require_login():
            return

        hashes = self.hash_edit.toPlainText().strip()
        if not hashes:
            QMessageBox.warning(self, "John", "Paste or load a hash first.")
            return

        is_custom = self.wordlist_box.currentText().startswith("- Custom")
        wordlist_name = None

        if is_custom:
            if not self._custom_wordlist_path:
                QMessageBox.warning(
                    self,
                    "Custom wordlist",
                    "Choose a file with Import... first.",
                )
                return
            wordlist_name = self._upload_custom_wordlist_sync()
            if not wordlist_name:
                QMessageBox.warning(
                    self,
                    "Upload failed",
                    "Could not upload the wordlist.\n"
                    "Check the Output log.\n\n"
                    "If you see 404, the server needs the /api/john/wordlist route.",
                )
                return
        else:
            wordlist_name = self._selected_wordlist_name()
            if not wordlist_name:
                QMessageBox.warning(self, "John", "Select a wordlist.")
                return

        fmt = self.format_box.currentText().strip() or "Raw-MD5"
        if fmt == "Auto":
            # Soft warning - Auto often mis-detects 32-hex as LM
            self._append("Note: Auto can mis-detect hashes - prefer an explicit format.")

        self._append("Requesting one-time John token...")
        token = self._fetch_token_sync()
        if not token:
            return

        body = {
            "token": token,
            "hash_text": hashes,
            "wordlist": wordlist_name,
            "format": fmt,
        }
        self._run_api(
            "POST",
            "/api/john/start",
            body=body,
            note=f"Starting John ({fmt}) with {wordlist_name}...",
            action="start",
        )

    def show_cracked(self):
        self._run_api("GET", "/api/john/show", note="Fetching cracked...", action="show", timeout=20)

    def run_cupp(self):
        if not self._require_login():
            return
        if not (self.cupp_first.text() or "").strip():
            QMessageBox.warning(self, "CUPP", "First name is required.")
            return

        self._append("Requesting one-time John token for CUPP...")
        token = self._fetch_token_sync()
        if not token:
            return

        body = {
            "token": token,
            "first_name": self.cupp_first.text().strip(),
            "surname": self.cupp_surname.text().strip(),
            "nickname": self.cupp_nick.text().strip(),
            "birthdate": self.cupp_birth.text().strip(),
            "partner_name": self.cupp_partner.text().strip(),
            "partner_nickname": self.cupp_partner_nick.text().strip(),
            "partner_birthdate": self.cupp_partner_birth.text().strip(),
            "child_name": self.cupp_child.text().strip(),
            "child_nickname": self.cupp_child_nick.text().strip(),
            "child_birthdate": self.cupp_child_birth.text().strip(),
            "pet_name": self.cupp_pet.text().strip(),
            "company": self.cupp_company.text().strip(),
            "keywords": self.cupp_keywords.text().strip(),
            "special_chars": self.cupp_special.isChecked(),
            "random_numbers": self.cupp_numbers.isChecked(),
            "leet": self.cupp_leet.isChecked(),
        }
        self._run_api(
            "POST",
            "/api/john/cupp",
            body=body,
            note="Running CUPP on server...",
            action="cupp",
            timeout=150,
        )
