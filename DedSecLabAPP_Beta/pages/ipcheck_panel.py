import json
import ssl
from core.tls import LabTLSError, ssl_context_for
import urllib.error
import urllib.request
from datetime import datetime
from PyQt6.QtCore import QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QBrush
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QMessageBox, QTableWidget, QTableWidgetItem, QHeaderView,
    QAbstractItemView, QSpinBox, QCheckBox, QDialog, QTextEdit, QDialogButtonBox,
)


# TLS via core.tls.ssl_context_for.


def _status_label(raw) -> str:
    s = str(raw or "").lower().strip()
    if s in ("online", "up", "ok", "alive", "reachable"):
        return "ONLINE"
    if s in ("offline", "no_icmp", "down", "fail", "timeout", "unreachable"):
        return "OFFLINE"
    if not s or s in ("unknown", "-", "-", "none"):
        return "-"
    return "OFFLINE" if ("off" in s or "fail" in s) else ("ONLINE" if "on" in s else "-")


def _is_offline_error(err) -> bool:
    text = str(err or "")
    low = text.lower()
    return any(
        token in low
        for token in (
            "10060",
            "10061",
            "10065",
            "timed out",
            "timeout",
            "urlopen error",
            "failed to respond",
            "network is unreachable",
            "no route to host",
            "name or service not known",
            "getaddrinfo failed",
            "connection refused",
        )
    )


class ApiWorker(QThread):
    done = pyqtSignal(dict)
    failed = pyqtSignal(str)

    def __init__(self, method, url, body=None, parent=None, timeout=8):
        super().__init__(parent)
        self.method = method.upper()
        self.url = url
        self.body = body
        self.timeout = timeout

    def run(self):
        try:
            data = None
            headers = {"Content-Type": "application/json", "Accept": "application/json"}
            if self.body is not None:
                data = json.dumps(self.body).encode("utf-8")
            req = urllib.request.Request(self.url, data=data, headers=headers, method=self.method)
            with urllib.request.urlopen(req, timeout=self.timeout, context=ssl_context_for(self.url)) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            self.done.emit(json.loads(raw) if raw else {})
        except urllib.error.HTTPError as e:
            try:
                detail = e.read().decode("utf-8", errors="replace")
            except Exception:
                detail = str(e)
            self.failed.emit(f"HTTP {e.code}: {detail[:500]}")
        except Exception as e:
            self.failed.emit(str(e))


class ResultDialog(QDialog):
    def __init__(self, title: str, body: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumSize(480, 360)
        self.resize(520, 420)
        self.setStyleSheet("""
            QDialog { background: #0a0a0c; color: #e8f0ff; }
            QLabel#Title { font-size: 15px; font-weight: 800; color: #55c7ff; }
            QTextEdit {
                background: #0f141a; color: #dcecff;
                border: 1px solid #2B3545; border-radius: 8px;
                font-family: Consolas, "Courier New", monospace;
                font-size: 13px; padding: 10px;
            }
            QPushButton {
                background: #151D2B; color: #e8f0ff;
                border: 1px solid #55c7ff; border-radius: 8px;
                min-height: 32px; padding: 6px 16px; font-weight: 700;
            }
        """)
        lay = QVBoxLayout(self)
        lab = QLabel(title)
        lab.setObjectName("Title")
        lay.addWidget(lab)
        text = QTextEdit()
        text.setReadOnly(True)
        text.setPlainText(body)
        lay.addWidget(text, 1)
        box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        box.accepted.connect(self.accept)
        lay.addWidget(box)


class NmapWindow(QDialog):
    def __init__(self, panel):
        super().__init__(panel)
        self.panel = panel
        self._spin = 0
        self.setWindowTitle("Nmap scan")
        self.setMinimumSize(560, 420)
        self.resize(620, 480)
        self.setStyleSheet("""
            QDialog { background: #0a0a0c; color: #e8f0ff; }
            QLabel#Title { font-size: 15px; font-weight: 800; color: #f59e0b; }
            QTextEdit {
                background: #0f141a; color: #dcecff;
                border: 1px solid #2B3545; border-radius: 8px;
                font-family: Consolas, "Courier New", monospace;
                font-size: 13px; padding: 10px;
            }
            QPushButton {
                background: #151D2B; color: #e8f0ff;
                border: 1px solid #f59e0b; border-radius: 8px;
                min-height: 32px; padding: 6px 14px; font-weight: 700;
            }
        """)
        lay = QVBoxLayout(self)
        title = QLabel("Nmap port scan")
        title.setObjectName("Title")
        lay.addWidget(title)
        self.status = QLabel("idle")
        self.status.setStyleSheet("font-weight: 800; color: #94A3B8;")
        lay.addWidget(self.status)
        row = QHBoxLayout()
        b1 = QPushButton("Top 1000")
        b2 = QPushButton("10000-65535")
        b3 = QPushButton("Stop")
        b4 = QPushButton("Refresh")
        b1.clicked.connect(lambda: self._start("top1000"))
        b2.clicked.connect(lambda: self._start("high"))
        b3.clicked.connect(self._stop)
        b4.clicked.connect(self.reload)
        row.addWidget(b1)
        row.addWidget(b2)
        row.addWidget(b3)
        row.addWidget(b4)
        lay.addLayout(row)
        self.out = QTextEdit()
        self.out.setReadOnly(True)
        lay.addWidget(self.out, 1)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.reload)
        self._timer.start(2000)
        self.reload()

    def _start(self, mode):
        self.panel.nmap_confirm_and_start(mode)
        self.reload()

    def _stop(self):
        self.panel.nmap_stop()
        self.reload()

    def reload(self):
        def on_ok(data):
            if not data.get("ok"):
                self.status.setText("unavailable")
                self.out.setPlainText(str(data)[:800])
                return
            running = bool(data.get("running"))
            ports = data.get("open_ports") or []
            tgt = data.get("target") or ""
            started = data.get("started") or ""
            est = int(data.get("est_seconds") or 0)
            if running:
                self._spin = (self._spin + 1) % 4
                dots = "." * (self._spin + 1)
                elapsed = ""
                if started:
                    try:
                        t0 = datetime.strptime(started, "%Y-%m-%d %H:%M:%S")
                        sec = max(0, int((datetime.now() - t0).total_seconds()))
                        elapsed = f"  {sec}s elapsed"
                        if est:
                            elapsed += f"  /  ~{est}s est"
                    except Exception:
                        elapsed = ""
                self.status.setText(f"SCANNING{dots}   {tgt}{elapsed}")
                self.status.setStyleSheet("font-weight: 800; color: #f59e0b;")
                live = "\n".join(ports) if ports else "Waiting for first open ports..."
                self.out.setPlainText(
                    f"Mode: {data.get('label') or ''}\nTarget: {tgt}\nStatus: running\n\n{live}"
                )
            else:
                st = data.get("status") or "idle"
                self.status.setText(f"{st.upper()}   {tgt}".strip())
                self.status.setStyleSheet(
                    "font-weight: 800; color: #50ff85;" if ports else "font-weight: 800; color: #94A3B8;"
                )
                body = "\n".join(ports) if ports else "(no open ports reported yet)"
                if data.get("label"):
                    body = f"Mode: {data.get('label')}\nTarget: {tgt}\n\n{body}"
                self.out.setPlainText(body)
        self.panel._run("GET", "/api/ipcheck/nmap/status", None, on_ok, block_ui=False)


class IpCheckPanel(QWidget):
    def __init__(self, app_window):
        super().__init__()
        self.app_window = app_window
        self._workers = []
        self._busy = False
        self._loaded = False

        root = QVBoxLayout(self)
        root.setContentsMargins(12, 10, 12, 10)
        root.setSpacing(8)

        title = QLabel("IP Surveillance / Live Ping")
        title.setObjectName("PageTitle")
        sub = QLabel("VPN-gated · same data as server live-ping-checker")
        sub.setObjectName("StatusLine")
        root.addWidget(title)
        root.addWidget(sub)

        self.status_line = QLabel("Status: waiting for VPN")
        self.status_line.setObjectName("StatusLine")
        root.addWidget(self.status_line)

        add_row = QHBoxLayout()
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("IPv4 to add")
        self.label_input = QLineEdit()
        self.label_input.setPlaceholderText("Label (optional)")
        self.ports_input = QLineEdit()
        self.ports_input.setPlaceholderText("TCP ports e.g. 80,443")
        btn_add = QPushButton("Add IP")
        btn_add.clicked.connect(self.add_ip)
        add_row.addWidget(self.ip_input, 2)
        add_row.addWidget(self.label_input, 2)
        add_row.addWidget(self.ports_input, 1)
        add_row.addWidget(btn_add)
        root.addLayout(add_row)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["", "IP", "Label", "Status", "Last check", "Geo"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        for c in range(1, 6):
            self.table.horizontalHeader().setSectionResizeMode(c, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setMinimumHeight(180)
        root.addWidget(self.table, 1)

        act = QHBoxLayout()
        for text, slot in [
            ("Refresh", self.refresh),
            ("Check selected", self.check_selected),
            ("Check all", self.check_all),
            ("Lookup", self.lookup_selected),
            ("Traceroute", self.traceroute_selected),
            ("Remove", self.remove_selected),
        ]:
            b = QPushButton(text)
            b.clicked.connect(slot)
            act.addWidget(b)
        btn_nmap = QPushButton("Nmap scan...")
        btn_nmap.setStyleSheet(
            "QPushButton{background:#2a1f0a;border:1px solid #f59e0b;border-radius:8px;"
            "padding:8px 14px;color:#fde68a;font-weight:800;}"
        )
        btn_nmap.clicked.connect(self.open_nmap_window)
        act.addWidget(btn_nmap)
        root.addLayout(act)

        live_box = QVBoxLayout()
        live_title = QLabel("LIVE track one IP (until status flips + Discord)")
        live_title.setStyleSheet("font-weight: 800; color: #a78bfa; font-size: 13px;")
        live_box.addWidget(live_title)
        live_row = QHBoxLayout()
        self.live_label = QLabel("LIVE: off")
        self.live_label.setObjectName("StatusLine")
        btn_live = QPushButton("LIVE track selected")
        btn_live_stop = QPushButton("Stop LIVE")
        btn_live.setStyleSheet(
            "QPushButton{background:#1a1530;border:1px solid #a78bfa;border-radius:8px;"
            "padding:8px 14px;color:#e9d5ff;font-weight:800;}"
            "QPushButton:hover{background:#251a40;}"
        )
        btn_live.clicked.connect(self.live_selected)
        btn_live_stop.clicked.connect(self.live_stop)
        live_row.addWidget(self.live_label, 1)
        live_row.addWidget(btn_live)
        live_row.addWidget(btn_live_stop)
        live_box.addLayout(live_row)
        live_hint = QLabel(
            "Tick one IP -> LIVE track selected. Server watches it until it goes "
            "ONLINE->OFFLINE or OFFLINE->ONLINE, then fires Discord once."
        )
        live_hint.setWordWrap(True)
        live_hint.setStyleSheet("color: #7d98b6; font-size: 12px;")
        live_box.addWidget(live_hint)
        root.addLayout(live_box)

        mon_box = QVBoxLayout()
        mon_title = QLabel("Tracking (background monitor - all saved IPs)")
        mon_title.setStyleSheet("font-weight: 800; color: #55c7ff; font-size: 13px;")
        mon_box.addWidget(mon_title)
        mon = QHBoxLayout()
        self.mon_label = QLabel("Status: not running")
        self.mon_label.setObjectName("StatusLine")
        btn_start = QPushButton("Start tracking")
        btn_stop = QPushButton("Stop tracking")
        btn_start.clicked.connect(self.monitor_start)
        btn_stop.clicked.connect(self.monitor_stop)
        mon.addWidget(self.mon_label, 1)
        mon.addWidget(btn_start)
        mon.addWidget(btn_stop)
        mon_box.addLayout(mon)

        set_row = QHBoxLayout()
        how_often = QLabel("How often to check each IP:")
        how_often.setStyleSheet("color: #9aa8bc;")
        set_row.addWidget(how_often)
        self.interval_spin = QSpinBox()
        self.interval_spin.setRange(1, 24)
        self.interval_spin.setValue(3)
        self.interval_spin.setSuffix(" hour(s)")
        self.interval_spin.setMinimumWidth(120)
        set_row.addWidget(self.interval_spin)
        self.change_only = QCheckBox("Only alert when status changes")
        self.change_only.setChecked(True)
        set_row.addWidget(self.change_only)
        set_row.addWidget(QLabel("Fails before OFFLINE:"))
        self.multi_spin = QSpinBox()
        self.multi_spin.setRange(1, 10)
        self.multi_spin.setValue(2)
        set_row.addWidget(self.multi_spin)
        btn_save_set = QPushButton("Save tracking settings")
        btn_save_set.clicked.connect(self.save_settings)
        set_row.addWidget(btn_save_set)
        set_row.addStretch()
        mon_box.addLayout(set_row)
        hint = QLabel(
            "Example: set to 1 hour -> Save tracking settings -> Start tracking. "
            "All saved IPs are checked on that schedule."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #7d98b6; font-size: 12px;")
        mon_box.addWidget(hint)
        root.addLayout(mon_box)

        wh = QHBoxLayout()
        self.webhook_input = QLineEdit()
        self.webhook_input.setPlaceholderText("Discord webhook URL")
        btn_wh = QPushButton("Save webhook")
        btn_wh.clicked.connect(self.save_webhook)
        btn_test = QPushButton("Test webhook")
        btn_test.clicked.connect(self.test_webhook)
        wh.addWidget(self.webhook_input, 1)
        wh.addWidget(btn_wh)
        wh.addWidget(btn_test)
        root.addLayout(wh)

    def showEvent(self, event):
        super().showEvent(event)
        if not self._loaded:
            self._loaded = True
            QTimer.singleShot(0, self.refresh)

    def api_base(self) -> str:
        cfg = getattr(self.app_window, "config", {}) or {}
        url = (cfg.get("server_url") or "https://YOUR_LAB_VPN_IP:8443").rstrip("/")
        if url.startswith("http://") and "10.8.0." in url:
            url = "https://" + url[len("http://"):]
        return url

    def popup(self, title: str, body: str):
        ResultDialog(title, body, self).exec()

    def toast(self, title: str, msg: str):
        QMessageBox.information(self, title, msg)

    def set_busy(self, busy: bool):
        self._busy = busy

    def checked_ips(self) -> list:
        ips = []
        for r in range(self.table.rowCount()):
            w = self.table.cellWidget(r, 0)
            if w is not None and w.isChecked():
                item = self.table.item(r, 1)
                if item and item.text().strip():
                    ips.append(item.text().strip())
        return ips

    def open_nmap_window(self):
        NmapWindow(self).exec()

    def nmap_confirm_and_start(self, mode: str):
        ips = self.checked_ips()
        if not ips:
            self.toast("Nmap", "Tick one saved IP first.")
            return
        target = ips[0]
        if mode == "top1000":
            label = "Top 1000 ports"
            est = "about 30-90 seconds"
        else:
            label = "Ports 10000-65535"
            est = "about 15-30+ minutes"
        box = QMessageBox(self)
        box.setWindowTitle("Start nmap?")
        box.setText(
            f"Scan {target}\n\nMode: {label}\nEstimate: {est}\n\n"
            "You can press Stop while it runs."
        )
        box.setStandardButtons(QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel)
        if box.exec() != QMessageBox.StandardButton.Ok:
            return

        def after(token):
            def on_ok(data):
                if data.get("ok"):
                    self.toast("Nmap", f"Started {label} on {target}")
                else:
                    QMessageBox.warning(self, "Nmap", str(data.get("reason") or data)[:400])
            self._run("POST", "/api/ipcheck/nmap/start",
                      {"token": token, "ip": target, "mode": mode}, on_ok)
        self._with_token(after)

    def nmap_stop(self):
        def after(token):
            def on_ok(data):
                self.toast("Nmap", "Stop requested." if data.get("ok") else str(data)[:300])
            self._run("POST", "/api/ipcheck/nmap/stop", {"token": token, "ip": ""}, on_ok)
        self._with_token(after)

    def _run(self, method, path, body=None, on_ok=None, block_ui=True):
        if block_ui and self._busy:
            return
        if block_ui:
            self.set_busy(True)
        timeout = 8 if method == "GET" else 20
        w = ApiWorker(method, self.api_base() + path, body, self, timeout=timeout)
        self._workers.append(w)

        def _ok(data):
            if block_ui:
                self.set_busy(False)
            if on_ok:
                on_ok(data)

        def _fail(err):
            if block_ui:
                self.set_busy(False)
            if _is_offline_error(err):
                self.status_line.setText("Status: VPN offline - API not reachable")
                return
            QMessageBox.warning(self, "IP Check", str(err)[:400])

        w.done.connect(_ok)
        w.failed.connect(_fail)
        w.start()

    def _with_token(self, after):
        def on_tok(data):
            if not data.get("ok"):
                self.set_busy(False)
                reason = str(data)
                if _is_offline_error(reason) or "whitelisted" in reason.lower() or "vpn" in reason.lower():
                    self.status_line.setText("Status: VPN offline - API not reachable")
                    return
                QMessageBox.warning(self, "IP Check", reason[:400])
                return
            after(data.get("token"))
        self._run("POST", "/api/ipcheck/token", {}, on_tok, block_ui=True)

    def _format_target_box(self, ip, info=None, status=None, label="", ports=None, ptr=""):
        info = info or {}
        st = _status_label(status)
        lines = [
            "╔══════════════════════════════════════════════╗",
            "║ TARGET INFORMATION                           ║",
            "╠══════════════════════════════════════════════╣",
        ]
        if label:
            lines.append(f"║ Label        : {label}")
        lines.append(f"║ IP Address   : {ip}")
        if ptr:
            lines.append(f"║ rDNS         : {ptr}")
        lines.append(f"║ ISP          : {info.get('isp', 'Unknown')}")
        lines.append(f"║ Organization : {info.get('org', 'Unknown')}")
        lines.append(f"║ ASN          : {info.get('asn', 'Unknown')}")
        lines.append(f"║ Country      : {info.get('country', 'Unknown')}")
        lines.append(f"║ Region       : {info.get('region', 'Unknown')}")
        lines.append(f"║ City         : {info.get('city', 'Unknown')}")
        if st != "-":
            lines.append(f"║ Status       : {st}")
        if ports and isinstance(ports, dict):
            bits = [f"{p}:{'open' if ok else 'closed'}" for p, ok in sorted(ports.items())]
            lines.append(f"║ Ports        : {', '.join(bits)}")
        lines.append("╚══════════════════════════════════════════════╝")
        return "\n".join(lines)

    def refresh(self):
        def on_status(data):
            if not data.get("ok"):
                self.status_line.setText("Status: unavailable")
                return
            self.status_line.setText(
                f"VPN {data.get('vpn_ip')} · saved {data.get('saved')} · "
                f"up {data.get('online')} / down {data.get('offline')} · "
                f"tracking {'ON' if data.get('monitor_running') else 'OFF'}"
            )
            self.mon_label.setText(
                f"Status: {'RUNNING - checking on schedule' if data.get('monitor_running') else 'not running'}"
            )
            if data.get("live_running"):
                targets = data.get("live_targets") or []
                ips = ", ".join(t.get("ip", "") for t in targets if isinstance(t, dict)) or "?"
                self.live_label.setText(f"LIVE: ON ({ips})")
                self.live_label.setStyleSheet("color: #50ff85; font-weight: 700;")
            else:
                self.live_label.setText("LIVE: off")
                self.live_label.setStyleSheet("color: #94A3B8;")

        def on_ips(data):
            if not data.get("ok"):
                return
            ips = data.get("ips") or []
            self.table.setRowCount(0)
            for entry in ips:
                r = self.table.rowCount()
                self.table.insertRow(r)
                cb = QCheckBox()
                cb.setStyleSheet("margin-left: 8px;")
                self.table.setCellWidget(r, 0, cb)
                info = entry.get("last_info") or {}
                geo = ""
                if isinstance(info, dict):
                    geo = f"{info.get('city') or ''} {info.get('country') or ''}".strip()
                st = _status_label(entry.get("last_status"))
                vals = [
                    str(entry.get("ip") or ""),
                    str(entry.get("label") or ""),
                    st,
                    str(entry.get("last_check") or ""),
                    geo,
                ]
                for c, v in enumerate(vals):
                    item = QTableWidgetItem(v)
                    if c == 2:
                        if st == "ONLINE":
                            item.setForeground(QBrush(QColor("#50ff85")))
                        elif st == "OFFLINE":
                            item.setForeground(QBrush(QColor("#ff5555")))
                    self.table.setItem(r, c + 1, item)

        def on_settings(data):
            if not data.get("ok"):
                return
            s = data.get("settings") or {}
            self.interval_spin.setValue(int(s.get("interval_hours") or 3))
            self.change_only.setChecked(bool(s.get("change_only", True)))
            self.multi_spin.setValue(int(s.get("multi_fail") or 2))

        def on_wh(data):
            if data.get("configured"):
                self.webhook_input.setPlaceholderText(data.get("url_preview") or "Webhook set")

        self._run("GET", "/api/ipcheck/status", None, on_status, block_ui=False)
        self._run("GET", "/api/ipcheck/ips", None, on_ips, block_ui=False)
        self._run("GET", "/api/ipcheck/settings", None, on_settings, block_ui=False)
        self._run("GET", "/api/ipcheck/webhook", None, on_wh, block_ui=False)

    def add_ip(self):
        target = self.ip_input.text().strip()
        if not target:
            return

        def after(token):
            body = {
                "token": token,
                "ip": target,
                "label": self.label_input.text().strip(),
                "tcp_ports": self.ports_input.text().strip(),
            }

            def on_ok(data):
                if data.get("ok"):
                    self.ip_input.clear()
                    self.toast("IP added", f"{target} was added to surveillance.")
                    self.refresh()
                else:
                    QMessageBox.warning(self, "IP Check", str(data)[:400])
            self._run("POST", "/api/ipcheck/ips", body, on_ok)
        self._with_token(after)

    def remove_selected(self):
        ips = self.checked_ips()
        if not ips:
            self.toast("Remove", "Tick one or more IPs first.")
            return
        queue = list(ips)

        def delete_next():
            if not queue:
                self.toast("Removed", "Selected IP(s) removed.")
                self.refresh()
                return
            target = queue.pop(0)

            def after_token(token):
                def on_ok(data):
                    if not data.get("ok"):
                        QMessageBox.warning(self, "Remove", f"Could not remove {target}:\n{str(data)[:300]}")
                    delete_next()
                self._run("DELETE", "/api/ipcheck/ips", {"token": token, "ip": target}, on_ok)
            self._with_token(after_token)
        delete_next()

    def _parse_check_row(self, row, fallback_ip=""):
        ip = str(row.get("ip") or fallback_ip or "")
        status = row.get("status") or row.get("last_status") or (row.get("ping") or {}).get("status")
        info = row.get("info") or row.get("last_info") or {}
        if not isinstance(info, dict):
            info = {}
        label = str(row.get("label") or "")
        ports = row.get("ports") or row.get("last_ports")
        ptr = str(row.get("ptr") or row.get("rdns") or "")
        return ip, status, info, label, ports, ptr

    def check_selected(self):
        ips = self.checked_ips()
        if not ips:
            self.toast("Check", "Tick one or more IPs first.")
            return
        self._check_ip(ips[0])

    def check_all(self):
        def after(token):
            def on_ok(data):
                if not data.get("ok"):
                    QMessageBox.warning(self, "Check all", str(data)[:400])
                    self.refresh()
                    return
                rows = data.get("results") or []
                if not rows and data.get("status"):
                    rows = [data]
                blocks = []
                for row in rows:
                    ip, status, info, label, ports, ptr = self._parse_check_row(row)
                    blocks.append(self._format_target_box(ip, info, status, label, ports, ptr))
                body = "\n\n".join(blocks) if blocks else str(data)[:800]
                if data.get("discord"):
                    body += "\n\n[+] Discord notification sent."
                self.popup("Check all - results", body)
                self.refresh()
            self._run("POST", "/api/ipcheck/check", {"token": token, "ip": ""}, on_ok)
        self._with_token(after)

    def _check_ip(self, target: str):
        def after(token):
            def on_ok(data):
                if not data.get("ok"):
                    QMessageBox.warning(self, "Check", str(data)[:400])
                    self.refresh()
                    return
                rows = data.get("results") or []
                row = rows[0] if rows else data
                ip, status, info, label, ports, ptr = self._parse_check_row(row, target)
                body = self._format_target_box(ip or target, info, status, label, ports, ptr)
                if data.get("discord"):
                    body += "\n\n[+] Discord notification sent."
                self.popup("TARGET INFORMATION", body)
                self.refresh()
            self._run("POST", "/api/ipcheck/check", {"token": token, "ip": target}, on_ok)
        self._with_token(after)

    def lookup_selected(self):
        ips = self.checked_ips()
        target = ips[0] if ips else self.ip_input.text().strip()
        if not target:
            self.toast("Lookup", "Tick an IP or type one in the add box.")
            return

        def after(token):
            def on_ok(data):
                info = data.get("info") or data.get("geo") or data
                if not isinstance(info, dict):
                    info = {}
                body = self._format_target_box(
                    target, info, data.get("status"), "", None,
                    data.get("ptr") or data.get("rdns") or "",
                )
                self.popup("IP Lookup", body)
            self._run("POST", "/api/ipcheck/lookup", {"token": token, "ip": target}, on_ok)
        self._with_token(after)

    def traceroute_selected(self):
        ips = self.checked_ips()
        target = ips[0] if ips else self.ip_input.text().strip()
        if not target:
            self.toast("Traceroute", "Tick an IP or type one in the add box.")
            return

        def after(token):
            def on_ok(data):
                out = data.get("output") or data.get("traceroute") or str(data)
                self.popup(f"Traceroute - {target}", str(out))
            self._run("POST", "/api/ipcheck/traceroute", {"token": token, "ip": target}, on_ok)
        self._with_token(after)

    def live_selected(self):
        ips = self.checked_ips()
        if not ips:
            self.toast("LIVE track", "Tick one IP first.")
            return
        target = ips[0]

        def after(token):
            def on_ok(data):
                if data.get("ok"):
                    self.toast("LIVE track", data.get("message") or f"Watching {target}. Discord when status flips.")
                else:
                    QMessageBox.warning(self, "LIVE track", str(data)[:400])
                self.refresh()
            self._run("POST", "/api/ipcheck/live/start", {"token": token, "ip": target}, on_ok)
        self._with_token(after)

    def live_stop(self):
        def after(token):
            def on_ok(data):
                self.toast("LIVE track", "Stopped.")
                self.refresh()
            self._run("POST", "/api/ipcheck/live/stop", {"token": token, "ip": ""}, on_ok)
        self._with_token(after)

    def monitor_start(self):
        def after(token):
            def on_ok(data):
                if data.get("ok") or data.get("already_running"):
                    self.toast("Tracking", "Background tracking is RUNNING.")
                else:
                    QMessageBox.warning(self, "Tracking", str(data)[:400])
                self.refresh()
            self._run("POST", "/api/ipcheck/monitor/start", {"token": token, "ip": ""}, on_ok)
        self._with_token(after)

    def monitor_stop(self):
        def after(token):
            def on_ok(data):
                self.toast("Tracking", "Background tracking stopped.")
                self.refresh()
            self._run("POST", "/api/ipcheck/monitor/stop", {"token": token, "ip": ""}, on_ok)
        self._with_token(after)

    def save_settings(self):
        def after(token):
            body = {
                "token": token,
                "interval_hours": self.interval_spin.value(),
                "change_only": self.change_only.isChecked(),
                "multi_fail": self.multi_spin.value(),
                "alert_cooldown_sec": 300,
            }

            def on_ok(data):
                if data.get("ok"):
                    self.toast("Tracking settings", "Saved. Click Start tracking if it is not already running.")
                else:
                    QMessageBox.warning(self, "Tracking settings", str(data)[:400])
            self._run("POST", "/api/ipcheck/settings", body, on_ok)
        self._with_token(after)

    def save_webhook(self):
        url = self.webhook_input.text().strip()
        if not url:
            self.toast("Webhook", "Paste a Discord webhook URL first.")
            return

        def after(token):
            def on_ok(data):
                if data.get("ok"):
                    self.webhook_input.clear()
                    self.toast("Webhook", "Discord webhook was saved.")
                    self.refresh()
                else:
                    QMessageBox.warning(self, "Webhook", str(data)[:400])
            self._run("POST", "/api/ipcheck/webhook", {"token": token, "url": url}, on_ok)
        self._with_token(after)

    def test_webhook(self):
        def after(token):
            def on_ok(data):
                if data.get("ok"):
                    self.toast("Webhook test", "Test message sent to Discord.")
                else:
                    QMessageBox.warning(self, "Webhook test", str(data)[:400])
            self._run("POST", "/api/ipcheck/webhook/test", {"token": token, "ip": ""}, on_ok)
        self._with_token(after)
