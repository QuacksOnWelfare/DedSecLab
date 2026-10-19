"""
Shodan Intelligence panel - Networking tab.
[WEB]  = opens system browser (shodan.io)
[API]  = lab API (Search needs query credits on free plan)
[BOTH] = useful either way
"""
from __future__ import annotations

import json
import traceback
from urllib.parse import quote

import requests
from core.tls import LabTLSError, http_get, http_post
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QUrl
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTextEdit, QComboBox, QFrame, QMessageBox,
    QSpinBox, QTabWidget, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView,
)


PRESET_QUERIES = [
    ("- custom query -", ""),

    # Cameras / DVR style
    ("[WEB] RTSP - any", "port:554"),
    ("[WEB] RTSP - GB", "port:554 country:GB"),
    ("[WEB] RTSP - London", 'port:554 city:"London"'),
    ("[WEB] RTSP - Manchester", 'port:554 city:"Manchester"'),
    ("[WEB] RTSP - Birmingham", 'port:554 city:"Birmingham"'),
    ("[WEB] Network Camera title - GB", 'title:"Network Camera" country:GB'),
    ("[WEB] IP Camera text - GB", '"IP Camera" country:GB'),
    ("[WEB] Hikvision - GB", "Hikvision country:GB"),
    ("[WEB] Dahua - GB", "Dahua country:GB"),
    ("[WEB] Axis - GB", "Axis country:GB"),
    ("[WEB] WebcamXP - GB", 'product:"WebcamXP" country:GB'),
    ("[WEB] YAWCAM - GB", "Server: yawcam country:GB"),
    ("[WEB] IPCAM - GB", "IPCAM country:GB"),
    ("[WEB] Generic screenshot (often PCs) - GB", "has_screenshot:true country:GB"),

    # Ports
    ("[BOTH] Port 22 SSH", "port:22"),
    ("[BOTH] Port 80 HTTP", "port:80"),
    ("[BOTH] Port 443 HTTPS", "port:443"),
    ("[BOTH] Port 21 FTP", "port:21"),
    ("[BOTH] Port 23 Telnet", "port:23"),
    ("[BOTH] Port 25 SMTP", "port:25"),
    ("[BOTH] Port 3389 RDP", "port:3389"),
    ("[BOTH] Port 445 SMB", "port:445"),
    ("[BOTH] Port 8080", "port:8080"),
    ("[BOTH] Port 8443", "port:8443"),
    ("[BOTH] Port 5900 VNC", "port:5900"),

    # Products
    ("[BOTH] Apache", "product:Apache"),
    ("[BOTH] Nginx", "product:nginx"),
    ("[BOTH] OpenSSH", "product:OpenSSH"),
    ("[BOTH] IIS", "product:IIS"),
    ("[BOTH] MySQL", "product:MySQL"),
    ("[BOTH] PostgreSQL", "product:PostgreSQL"),
    ("[BOTH] MongoDB", "product:MongoDB"),
    ("[BOTH] Redis", "product:Redis"),
    ("[BOTH] Elasticsearch", "product:Elastic"),
    ("[BOTH] Kubernetes", "product:Kubernetes"),
    ("[BOTH] Docker", "Docker"),
    ("[BOTH] Grafana", "product:Grafana"),
    ("[BOTH] Jenkins", "product:Jenkins"),

    # Geo
    ("[BOTH] Country GB", "country:GB"),
    ("[BOTH] Country DE", "country:DE"),
    ("[BOTH] Country US", "country:US"),
    ("[BOTH] Country NL", "country:NL"),
    ("[BOTH] City London", 'city:"London"'),
    ("[BOTH] City Manchester", 'city:"Manchester"'),
    ("[BOTH] City Birmingham", 'city:"Birmingham"'),
    ("[BOTH] City Berlin", 'city:"Berlin"'),
    ("[BOTH] City Amsterdam", 'city:"Amsterdam"'),

    # Combined
    ("[WEB] Nginx - GB", "product:nginx country:GB"),
    ("[WEB] OpenSSH - GB", "product:OpenSSH country:GB"),
    ("[WEB] RDP - GB", "port:3389 country:GB"),
    ("[WEB] VNC - GB", "port:5900 country:GB"),
    ("[BOTH] Has hostname", "has_hostname:true"),
    ("[API] SSL cert expired (needs credits)", "ssl.cert.expired:true"),
    ("[API] SSL expired - GB (needs credits)", "ssl.cert.expired:true country:GB"),
]


class ApiWorker(QThread):
    finished_ok = pyqtSignal(dict)
    finished_err = pyqtSignal(str)

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs

    def run(self):
        try:
            result = self._fn(*self._args, **self._kwargs)
            self.finished_ok.emit(result if isinstance(result, dict) else {"ok": True, "data": result})
        except Exception as e:
            self.finished_err.emit(f"{e}\n{traceback.format_exc()[-600:]}")


class ShodanPanel(QFrame):
    def __init__(self, app_window):
        super().__init__()
        self.app_window = app_window
        self.setObjectName("ActionsPanel")
        self._worker = None
        self._last_matches = []

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)

        header = QHBoxLayout()
        title = QLabel("SHODAN INTELLIGENCE")
        title.setObjectName("ActionsPanelTitle")
        self.badge = QLabel("● IDLE")
        self.badge.setObjectName("ActionsLiveBadge")
        self.credits_lbl = QLabel("Credits: -")
        self.credits_lbl.setObjectName("ActionsHeroDetail")
        header.addWidget(title)
        header.addStretch()
        header.addWidget(self.credits_lbl)
        header.addWidget(self.badge)
        root.addLayout(header)

        note = QLabel(
            "[WEB] opens your system browser (use your normal Shodan login). "
            "[API] uses the lab key - Search needs credits on free plan. "
            "Host: Lookup [API] or Open IP on Shodan [WEB]. Authorized research only."
        )
        note.setObjectName("ActionsHeroDetail")
        note.setWordWrap(True)
        root.addWidget(note)

        self.inner = QTabWidget()
        self.inner.setObjectName("NetworkTabs")

        # ---- Search ----
        search_w = QWidget()
        sl = QVBoxLayout(search_w)
        sl.setSpacing(8)

        row = QHBoxLayout()
        self.preset = QComboBox()
        self.preset.setObjectName("EmulatorCombo")
        for name, _q in PRESET_QUERIES:
            self.preset.addItem(name)
        self.preset.currentIndexChanged.connect(self._apply_preset)
        row.addWidget(QLabel("PRESET"))
        row.addWidget(self.preset, 1)
        sl.addLayout(row)

        qrow = QHBoxLayout()
        self.query_edit = QLineEdit()
        self.query_edit.setPlaceholderText('Query - e.g. port:554 country:GB')
        self.query_edit.setObjectName("EmulatorInput")
        self.page_spin = QSpinBox()
        self.page_spin.setRange(1, 20)
        self.page_spin.setValue(1)
        self.page_spin.setPrefix("page ")
        self.limit_spin = QSpinBox()
        self.limit_spin.setRange(5, 50)
        self.limit_spin.setValue(25)
        self.limit_spin.setPrefix("limit ")
        qrow.addWidget(self.query_edit, 1)
        qrow.addWidget(self.page_spin)
        qrow.addWidget(self.limit_spin)
        sl.addLayout(qrow)

        brow = QHBoxLayout()
        self.count_btn = QPushButton("Count only [API]")
        self.count_btn.setObjectName("ActionButton_blue")
        self.count_btn.clicked.connect(self.do_count)
        self.search_btn = QPushButton("Search [API]")
        self.search_btn.setObjectName("ActionButton_cyan")
        self.search_btn.clicked.connect(self.do_search)
        self.web_btn = QPushButton("Open on Shodan [WEB]")
        self.web_btn.setObjectName("ActionButton_green")
        self.web_btn.clicked.connect(self.open_on_shodan_website)
        self.refresh_info_btn = QPushButton("API credits")
        self.refresh_info_btn.setObjectName("ActionButton_blue")
        self.refresh_info_btn.clicked.connect(self.do_info)
        brow.addWidget(self.count_btn)
        brow.addWidget(self.search_btn)
        brow.addWidget(self.web_btn)
        brow.addWidget(self.refresh_info_btn)
        brow.addStretch()
        sl.addLayout(brow)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["IP", "Port", "Org", "Country", "Product", "OS", "Hostname"]
        )
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.doubleClicked.connect(self._table_host_lookup)
        sl.addWidget(self.table, 1)
        self.inner.addTab(search_w, "  Search  ")

        # ---- Host ----
        host_w = QWidget()
        hl = QVBoxLayout(host_w)
        hrow = QHBoxLayout()
        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText("IP - e.g. 8.8.8.8")
        self.host_edit.setObjectName("EmulatorInput")
        self.host_btn = QPushButton("Lookup host [API]")
        self.host_btn.setObjectName("ActionButton_cyan")
        self.host_btn.clicked.connect(self.do_host)
        self.host_web_btn = QPushButton("Open IP on Shodan [WEB]")
        self.host_web_btn.setObjectName("ActionButton_green")
        self.host_web_btn.clicked.connect(self.open_host_on_website)
        hrow.addWidget(self.host_edit, 1)
        hrow.addWidget(self.host_btn)
        hrow.addWidget(self.host_web_btn)
        hl.addLayout(hrow)
        self.host_out = QTextEdit()
        self.host_out.setReadOnly(True)
        hl.addWidget(self.host_out, 1)
        self.inner.addTab(host_w, "  Host  ")

        # ---- DNS ----
        dns_w = QWidget()
        dl = QVBoxLayout(dns_w)
        drow = QHBoxLayout()
        self.dns_edit = QLineEdit()
        self.dns_edit.setPlaceholderText("domain or hosts/IPs")
        self.dns_edit.setObjectName("EmulatorInput")
        self.dns_btn = QPushButton("Domain info [API]")
        self.dns_btn.setObjectName("ActionButton_cyan")
        self.dns_btn.clicked.connect(self.do_dns)
        self.resolve_btn = QPushButton("Resolve [API]")
        self.resolve_btn.setObjectName("ActionButton_blue")
        self.resolve_btn.clicked.connect(self.do_resolve)
        self.reverse_btn = QPushButton("Reverse [API]")
        self.reverse_btn.setObjectName("ActionButton_green")
        self.reverse_btn.clicked.connect(self.do_reverse)
        drow.addWidget(self.dns_edit, 1)
        drow.addWidget(self.dns_btn)
        drow.addWidget(self.resolve_btn)
        drow.addWidget(self.reverse_btn)
        dl.addLayout(drow)
        self.dns_out = QTextEdit()
        self.dns_out.setReadOnly(True)
        dl.addWidget(self.dns_out, 1)
        self.inner.addTab(dns_w, "  DNS  ")

        # ---- Log ----
        log_w = QWidget()
        ll = QVBoxLayout(log_w)
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        ll.addWidget(self.log)
        self.inner.addTab(log_w, "  Log  ")

        root.addWidget(self.inner, 1)
        QTimer.singleShot(500, self.do_info)

    def _base_url(self) -> str:
        server = self.app_window.server
        base = (
            getattr(server, "base_url", None)
            or getattr(server, "url", None)
            or getattr(server, "api_url", None)
            or ""
        )
        base = str(base).rstrip("/")
        if not base:
            base = str(getattr(server, "host", "https://YOUR_LAB_VPN_IP:8443")).rstrip("/")
        return base

    def _api(self, method: str, path: str, json_body=None) -> dict:
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
        url = f"{self._base_url()}{path}"
        if method == "GET":
            r = http_get(url, timeout=60)
        else:
            r = http_post(url, json=json_body or {}, timeout=120)
        try:
            return r.json()
        except Exception:
            return {"ok": False, "reason": (r.text or "")[:400]}

    def _token(self):
        tok = self._api("POST", "/api/shodan/token", {})
        if tok.get("ok") and tok.get("token"):
            return tok["token"]
        self._append(f"Token failed: {tok.get('reason', tok)}")
        return None

    def _set_busy(self, busy: bool, label: str = "WORKING"):
        for b in (
            self.search_btn, self.count_btn, self.refresh_info_btn, self.web_btn,
            self.host_btn, self.host_web_btn,
            self.dns_btn, self.resolve_btn, self.reverse_btn,
        ):
            b.setEnabled(not busy)
        if busy:
            self.badge.setText(f"● {label}")
            self.badge.setStyleSheet("color: #ffcc33;")
        else:
            self.badge.setText("● IDLE")
            self.badge.setStyleSheet("color: #888888;")

    def _append(self, text: str):
        self.log.append(text)
        try:
            self.app_window.add_log(text[:180])
        except Exception:
            pass

    def _apply_preset(self, index: int):
        if index <= 0:
            return
        _name, q = PRESET_QUERIES[index]
        if q:
            self.query_edit.setText(q)

    def _open_url(self, url: str, label: str):
        QDesktopServices.openUrl(QUrl(url))
        self._append(f"[WEB] {label}")

    # ---------- WEB (system browser only) ----------
    def open_on_shodan_website(self):
        q = self.query_edit.text().strip()
        if not q:
            idx = self.preset.currentIndex()
            if 0 < idx < len(PRESET_QUERIES):
                q = PRESET_QUERIES[idx][1]
        if not q:
            QMessageBox.information(self, "Shodan", "Pick a preset or type a query first.")
            return
        url = "https://www.shodan.io/search?query=" + quote(q)
        self._open_url(url, f"search: {q}")

    def open_host_on_website(self):
        ip = self.host_edit.text().strip()
        if not ip:
            row = self.table.currentRow()
            if 0 <= row < len(self._last_matches):
                ip = str(self._last_matches[row].get("ip") or "").strip()
        if not ip:
            QMessageBox.information(self, "Shodan", "Enter an IP (e.g. 8.8.8.8) on the Host tab.")
            return
        url = f"https://www.shodan.io/host/{quote(ip)}"
        self._open_url(url, f"host: {ip}")

    def _fill_table(self, matches: list):
        self._last_matches = matches
        self.table.setRowCount(0)
        for m in matches:
            r = self.table.rowCount()
            self.table.insertRow(r)
            hostnames = m.get("hostnames") or []
            vals = [
                str(m.get("ip") or ""),
                str(m.get("port") or ""),
                str(m.get("org") or ""),
                str(m.get("country") or ""),
                str(m.get("product") or ""),
                str(m.get("os") or ""),
                hostnames[0] if hostnames else "",
            ]
            for c, v in enumerate(vals):
                self.table.setItem(r, c, QTableWidgetItem(v))

    def _table_host_lookup(self):
        row = self.table.currentRow()
        if row < 0 or row >= len(self._last_matches):
            return
        ip = self._last_matches[row].get("ip")
        if ip:
            self.host_edit.setText(str(ip))
            self.inner.setCurrentIndex(1)
            self.do_host()

    # ---------- API ----------
    def do_info(self):
        def work():
            return self._api("GET", "/api/shodan/status")
        self._set_busy(True, "INFO")
        self._worker = ApiWorker(work)
        self._worker.finished_ok.connect(self._on_info)
        self._worker.finished_err.connect(self._on_err)
        self._worker.start()

    def _on_info(self, data: dict):
        self._set_busy(False)
        if not data.get("ok"):
            self._append(f"Status: {data.get('reason', data)}")
            self.credits_lbl.setText("Credits: n/a")
            return
        plan = data.get("plan") or "?"
        credits = data.get("query_credits")
        self.credits_lbl.setText(f"Plan: {plan}  |  Query credits: {credits}")
        self._append(f"Shodan OK - plan={plan} credits={credits}")

    def do_count(self):
        q = self.query_edit.text().strip()
        if not q:
            QMessageBox.warning(self, "Shodan", "Enter a query.")
            return
        def work():
            token = self._token()
            if not token:
                return {"ok": False, "reason": "no token"}
            return self._api("POST", "/api/shodan/count", {"token": token, "query": q})
        self._set_busy(True, "COUNT")
        self._worker = ApiWorker(work)
        self._worker.finished_ok.connect(self._on_count)
        self._worker.finished_err.connect(self._on_err)
        self._worker.start()

    def _on_count(self, data: dict):
        self._set_busy(False)
        if not data.get("ok"):
            self._append(f"Count failed: {data.get('reason')}")
            QMessageBox.warning(self, "Shodan", str(data.get("reason", "failed")))
            return
        self._append(f"[API] Count -> {data.get('total')}")
        QMessageBox.information(
            self, "Shodan count",
            f"Query:\n{data.get('query')}\n\nTotal: {data.get('total')}",
        )

    def do_search(self):
        q = self.query_edit.text().strip()
        if not q:
            QMessageBox.warning(self, "Shodan", "Enter a query.")
            return
        page, limit = int(self.page_spin.value()), int(self.limit_spin.value())
        def work():
            token = self._token()
            if not token:
                return {"ok": False, "reason": "no token"}
            return self._api(
                "POST", "/api/shodan/search",
                {"token": token, "query": q, "page": page, "limit": limit},
            )
        self._set_busy(True, "SEARCH")
        self._append(f"[API] Search: {q}")
        self._worker = ApiWorker(work)
        self._worker.finished_ok.connect(self._on_search)
        self._worker.finished_err.connect(self._on_err)
        self._worker.start()

    def _on_search(self, data: dict):
        self._set_busy(False)
        if not data.get("ok"):
            self._append(f"Search failed: {data.get('reason')}")
            QMessageBox.warning(
                self, "Shodan",
                f"{data.get('reason')}\n\nUse «Open on Shodan [WEB]» instead.",
            )
            return
        matches = data.get("matches") or []
        self._fill_table(matches)
        self._append(f"[API] Returned {len(matches)} / total {data.get('total')}")
        self.badge.setText("● DONE")
        self.badge.setStyleSheet("color: #50ff85;")

    def do_host(self):
        ip = self.host_edit.text().strip()
        if not ip:
            QMessageBox.warning(self, "Shodan", "Enter an IP.")
            return
        def work():
            token = self._token()
            if not token:
                return {"ok": False, "reason": "no token"}
            return self._api("POST", "/api/shodan/host", {"token": token, "ip": ip})
        self._set_busy(True, "HOST")
        self._worker = ApiWorker(work)
        self._worker.finished_ok.connect(self._on_host)
        self._worker.finished_err.connect(self._on_err)
        self._worker.start()

    def _on_host(self, data: dict):
        self._set_busy(False)
        if not data.get("ok"):
            self.host_out.setPlainText(str(data.get("reason", data)))
            return
        lines = [
            f"IP: {data.get('ip')}",
            f"Org: {data.get('org')} | ISP: {data.get('isp')} | ASN: {data.get('asn')}",
            f"OS: {data.get('os')} | {data.get('city')}, {data.get('country')}",
            f"Hostnames: {', '.join(data.get('hostnames') or [])}",
            f"Ports: {data.get('ports')}",
            f"Tags: {data.get('tags')}",
            f"Vulns: {data.get('vulns')}",
            f"Last update: {data.get('last_update')}",
            "", "--- services ---",
        ]
        for s in data.get("services") or []:
            lines.append(
                f"  :{s.get('port')}/{s.get('transport')} {s.get('product') or ''} {s.get('version') or ''}"
            )
            ban = (s.get("banner") or "").strip()
            if ban:
                lines.append(f"    {ban[:300]}")
        self.host_out.setPlainText("\n".join(lines))
        self._append(f"[API] Host {data.get('ip')}")

    def do_dns(self):
        d = self.dns_edit.text().strip()
        if not d:
            return
        def work():
            token = self._token()
            if not token:
                return {"ok": False, "reason": "no token"}
            return self._api("POST", "/api/shodan/dns", {"token": token, "domain": d})
        self._set_busy(True, "DNS")
        self._worker = ApiWorker(work)
        self._worker.finished_ok.connect(lambda data: self._on_json_out(data, self.dns_out))
        self._worker.finished_err.connect(self._on_err)
        self._worker.start()

    def do_resolve(self):
        d = self.dns_edit.text().strip()
        if not d:
            return
        def work():
            token = self._token()
            if not token:
                return {"ok": False, "reason": "no token"}
            return self._api("POST", "/api/shodan/resolve", {"token": token, "hosts": d})
        self._set_busy(True, "RESOLVE")
        self._worker = ApiWorker(work)
        self._worker.finished_ok.connect(lambda data: self._on_json_out(data, self.dns_out))
        self._worker.finished_err.connect(self._on_err)
        self._worker.start()

    def do_reverse(self):
        d = self.dns_edit.text().strip()
        if not d:
            return
        def work():
            token = self._token()
            if not token:
                return {"ok": False, "reason": "no token"}
            return self._api("POST", "/api/shodan/reverse", {"token": token, "ips": d})
        self._set_busy(True, "REVERSE")
        self._worker = ApiWorker(work)
        self._worker.finished_ok.connect(lambda data: self._on_json_out(data, self.dns_out))
        self._worker.finished_err.connect(self._on_err)
        self._worker.start()

    def _on_json_out(self, data: dict, widget: QTextEdit):
        self._set_busy(False)
        widget.setPlainText(json.dumps(data, indent=2, default=str)[:20000])
        self._append(f"[API] DNS ok={data.get('ok')}")

    def _on_err(self, msg: str):
        self._set_busy(False)
        self._append(f"Error: {msg}")
        self.badge.setText("● ERROR")
        self.badge.setStyleSheet("color: #ff5555;")