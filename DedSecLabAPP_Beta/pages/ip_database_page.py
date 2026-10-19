from __future__ import annotations

import ipaddress
import re
from urllib.parse import quote

from PyQt6.QtCore import Qt, QTimer, QUrl, QThread, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtNetwork import QNetworkAccessManager, QNetworkRequest, QNetworkReply
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QPushButton, QLineEdit, QDialog, QApplication,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
)

from ui.widgets import CyberDivider


import os as _os

IPAPI_FIELDS = "country,regionName,city,isp,as,org,countryCode"
IPAPI_URL_TMPL = "https://pro.ip-api.com/line/{ip}?fields=" + IPAPI_FIELDS + "&key={key}"


def _ipapi_key() -> str:
    """Key from env IPAPI_KEY, then config.json ipapi_key. Never hardcoded."""
    env = (_os.environ.get("IPAPI_KEY") or "").strip()
    if env:
        return env
    try:
        from core.config import ConfigManager
        return str(ConfigManager.peek().get("ipapi_key") or "").strip()
    except Exception:
        return ""


def _ipapi_url(ip: str):
    key = _ipapi_key()
    if not key:
        return None
    return IPAPI_URL_TMPL.format(ip=quote(ip, safe=""), key=quote(key, safe=""))

_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)


def is_valid_ip(value: str) -> bool:
    value = (value or "").strip()
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return _IPV4_RE.match(value) is not None


def is_public_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address((value or "").strip())
        return addr.is_global
    except ValueError:
        return is_valid_ip(value)


def country_flag(code: str) -> str:
    if not code or len(code) != 2 or not code.isalpha():
        return "🌍"
    return "".join(chr(ord(c) + 127397) for c in code.upper())


def parse_ipapi_line(raw: str) -> dict:
    lines = [ln.strip() for ln in (raw or "").replace("\r", "").split("\n")]
    while len(lines) < 7:
        lines.append("")

    first = lines[0].lower()
    if first in ("fail", "error") or first.startswith("invalid") or first.startswith("reserved"):
        raise RuntimeError(lines[0] or "Lookup failed")

    country, region, city, isp, asn, org, code = lines[:7]
    if not country and not isp and not asn:
        raise RuntimeError(raw.strip() or "Empty lookup response")

    geo_parts = [p for p in (city, region, country) if p and p not in ("-", "null")]
    geo = ", ".join(geo_parts) if geo_parts else country

    network_parts = []
    if asn and asn not in ("-", "null"):
        network_parts.append(asn)
    if isp and isp not in ("-", "null") and isp not in network_parts:
        network_parts.append(isp)
    elif org and org not in ("-", "null") and org not in network_parts:
        network_parts.append(org)
    network = " · ".join(network_parts)

    return {
        "country": geo,
        "country_only": country,
        "region": region,
        "city": city,
        "isp": isp,
        "asn": asn,
        "org": org,
        "country_code": code if len(code) == 2 else "",
        "network": network,
    }


class _FetchDb(QThread):
    done = pyqtSignal(list)
    failed = pyqtSignal(str)

    def __init__(self, getter, parent=None):
        super().__init__(parent)
        self._getter = getter

    def run(self):
        try:
            rows = self._getter() or []
            if not isinstance(rows, list):
                rows = list(rows)
            self.done.emit(rows)
        except Exception as exc:
            self.failed.emit(str(exc))


_LIGHT_INK = {
    "#55c7ff": "#0369a1", "#f5c451": "#8a5a00", "#ff6b81": "#b42334",
    "#50ff85": "#11733a", "#aaaaaa": "#4a6178",
}


def _ink(color: str) -> str:
    """Table item colours: bright on dark, darker variants on the light theme."""
    try:
        from ui.styles import current_theme
        if current_theme() == "light":
            return _LIGHT_INK.get(color, color)
        from ui.styles import theme_color
        return theme_color(color)
    except Exception:
        pass
    return color


class IPDatabasePage(QWidget):
    def __init__(self, app_window):
        super().__init__()
        self.app_window = app_window
        self.all_entries = []
        self.view_entries = []
        self.page = 0
        self.page_size = 25
        self._enriching = False
        self._loaded_once = False
        self._fetching = False
        self._fetch_thread = None
        self._net = QNetworkAccessManager(self)

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 14)
        root.setSpacing(12)

        header = QHBoxLayout()
        title_box = QVBoxLayout()
        title_box.setSpacing(3)

        title = QLabel("IP DATABASE")
        title.setObjectName("PageTitle")

        subtitle = QLabel("Threat intelligence  ·  auto geo / ASN enrichment  ·  network recon")
        subtitle.setObjectName("StatusLine")

        title_box.addWidget(title)
        title_box.addWidget(subtitle)

        self.total_pill = QLabel("●  Total: 0")
        self.total_pill.setObjectName("ActionsLiveBadge")
        self.total_pill.setStyleSheet("color: #55c7ff;")

        self.unresolved_pill = QLabel("●  Unresolved: 0")
        self.unresolved_pill.setObjectName("ActionsLiveBadge")
        self.unresolved_pill.setStyleSheet("color: #ff6b6b;")

        self.status_pill = QLabel("●  Idle")
        self.status_pill.setObjectName("ActionsLiveBadge")
        self.status_pill.setStyleSheet("color: #7a8a99;")

        header.addLayout(title_box)
        header.addStretch()
        header.addWidget(self.total_pill)
        header.addSpacing(10)
        header.addWidget(self.unresolved_pill)
        header.addSpacing(10)
        header.addWidget(self.status_pill)
        root.addLayout(header)

        top_panel = QFrame()
        top_panel.setObjectName("ActionsPanel")
        top_layout = QHBoxLayout(top_panel)
        top_layout.setContentsMargins(16, 12, 16, 12)
        top_layout.setSpacing(12)

        self.search_input = QLineEdit()
        self.search_input.setObjectName("LoginInput")
        self.search_input.setPlaceholderText("Type a full IP or name, then Search / Enter")
        self.search_input.setMinimumHeight(40)
        # Never search while typing or deleting.
        self.search_input.returnPressed.connect(self.apply_search)

        self.search_btn = QPushButton("Search")
        self.search_btn.setObjectName("ActionButton_cyan")
        self.search_btn.setMinimumHeight(40)
        self.search_btn.setFixedWidth(110)
        self.search_btn.clicked.connect(self.apply_search)

        self.clear_search_btn = QPushButton("Clear")
        self.clear_search_btn.setObjectName("ActionButton_cyan")
        self.clear_search_btn.setMinimumHeight(40)
        self.clear_search_btn.setFixedWidth(90)
        self.clear_search_btn.clicked.connect(self.clear_search)

        self.refresh_btn = QPushButton("↻   Refresh")
        self.refresh_btn.setObjectName("ActionButton_cyan")
        self.refresh_btn.setMinimumHeight(40)
        self.refresh_btn.setFixedWidth(120)
        self.refresh_btn.clicked.connect(self.reload_from_server)

        self.load_db_btn = QPushButton("Load database")
        self.load_db_btn.setObjectName("ActionButton_green")
        self.load_db_btn.setMinimumHeight(40)
        self.load_db_btn.setFixedWidth(150)
        self.load_db_btn.setStyleSheet(
            "QPushButton { background: #163d28; color: #50ff85; font-weight: 700; "
            "border: 1px solid #50ff85; border-radius: 8px; }"
            "QPushButton:hover { background: #1e5436; }"
        )
        self.load_db_btn.clicked.connect(self.reload_from_server)

        top_layout.addWidget(self.search_input, 1)
        top_layout.addWidget(self.search_btn)
        top_layout.addWidget(self.clear_search_btn)
        top_layout.addWidget(self.refresh_btn)
        top_layout.addWidget(self.load_db_btn)
        root.addWidget(top_panel)

        page_bar = QFrame()
        page_bar.setObjectName("ActionsPanel")
        page_row = QHBoxLayout(page_bar)
        page_row.setContentsMargins(16, 8, 16, 8)
        self.prev_page_btn = QPushButton("< Prev")
        self.prev_page_btn.setMinimumHeight(34)
        self.prev_page_btn.clicked.connect(self.prev_page)
        self.next_page_btn = QPushButton("Next >")
        self.next_page_btn.setMinimumHeight(34)
        self.next_page_btn.clicked.connect(self.next_page)
        self.page_label = QLabel("Page 1")
        self.page_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        page_row.addWidget(self.prev_page_btn)
        page_row.addWidget(self.page_label, 1)
        page_row.addWidget(self.next_page_btn)
        root.addWidget(page_bar)

        self.table = QTableWidget(0, 6)
        self.table.setObjectName("IpDatabaseTable")
        self.table.setHorizontalHeaderLabels(
            ["IP Address", "Hits", "Rockstar ID", "Geo / Country", "Network / ISP", "Copy"]
        )
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.table.setSortingEnabled(False)
        self.table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        hh = self.table.horizontalHeader()
        hh.setStretchLastSection(False)
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        hh.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(0, 160)
        self.table.setColumnWidth(1, 56)
        self.table.setColumnWidth(5, 58)
        self.table.verticalHeader().setDefaultSectionSize(36)
        root.addWidget(self.table, 1)

        # Do not fetch 900 rows during widget construction.
        QTimer.singleShot(0, self.ensure_loaded)

    def filter_entries(self, text=""):
        return

    def ensure_loaded(self):
        if not self._loaded_once and not self._fetching:
            self.reload_from_server()

    def refresh(self):
        """Called by the main window on tab changes. Must stay cheap."""
        if self._enriching or self._fetching:
            return
        if not self._loaded_once:
            self.reload_from_server()

    def load_data(self):
        # Back-compat for older callers.
        self.reload_from_server()

    def _normalize_rows(self, raw):
        if raw is None:
            return []
        if isinstance(raw, dict):
            for key in ("entries", "ips", "items", "data", "records", "database"):
                val = raw.get(key)
                if isinstance(val, list):
                    return val
            if raw.get("ok") and isinstance(raw.get("result"), list):
                return raw["result"]
            return []
        if isinstance(raw, list):
            return raw
        try:
            return list(raw)
        except TypeError:
            return []

    def reload_from_server(self):
        if self._enriching or self._fetching:
            return
        getter = getattr(self.app_window.server, "get_ip_database", None)
        if not callable(getter):
            self.status_pill.setText("●  No API")
            self.status_pill.setStyleSheet("color: #ff6b6b;")
            return

        keep_page = self.page
        keep_query = self.search_input.text().strip()
        self.status_pill.setText("●  Loading...")
        self.status_pill.setStyleSheet("color: #55c7ff;")
        QApplication.processEvents()

        try:
            raw = getter()
            rows = self._normalize_rows(raw)
        except Exception as exc:
            print("ip database load:", exc)
            self.status_pill.setText("●  DB Error")
            self.status_pill.setStyleSheet("color: #ff6b6b;")
            return

        self._loaded_once = True
        self.all_entries = rows
        self.status_pill.setText(f"●  DB Connected  ({len(rows)})")
        self.status_pill.setStyleSheet("color: #50ff85;")
        self.update_stats()
        if keep_query:
            self.apply_search(reset_page=False)
            self.page = min(keep_page, self.page_count() - 1)
            self.render_page()
        else:
            self.view_entries = list(self.all_entries)
            self.page = min(keep_page, self.page_count() - 1)
            self.render_page()

    def update_stats(self):
        total = len(self.all_entries)
        unresolved = 0
        for e in self.all_entries:
            country = str(e.get("country") or "").strip()
            network = str(e.get("network") or "").strip()
            if country in ("", "--", "-") and network in ("", "--", "-"):
                unresolved += 1
        self.total_pill.setText(f"●  Total: {total}")
        self.unresolved_pill.setText(f"●  Unresolved: {unresolved}")
        self.unresolved_pill.setStyleSheet(
            "color: #ff6b6b;" if unresolved else "color: #50ff85;"
        )

    def clear_search(self):
        self.search_input.clear()
        self.view_entries = list(self.all_entries)
        self.page = 0
        self.render_page()

    def apply_search(self, reset_page=True):
        q = self.search_input.text().strip().lower()
        if not q:
            self.view_entries = list(self.all_entries)
            if reset_page:
                self.page = 0
            self.render_page()
            return

        exact = []
        prefix = []
        for e in self.all_entries:
            ip = str(e.get("ip", "") or "").strip().lower()
            label = str(e.get("label", "") or "").strip().lower()
            if q == ip or q == label:
                exact.append(e)
            elif ip.startswith(q) or label.startswith(q):
                prefix.append(e)

        self.view_entries = exact if exact else prefix[:50]
        if reset_page:
            self.page = 0
        self.render_page()

    def page_count(self):
        if not self.view_entries:
            return 1
        return max(1, (len(self.view_entries) + self.page_size - 1) // self.page_size)

    def prev_page(self):
        if self.page > 0:
            self.page -= 1
            self.render_page()

    def next_page(self):
        if self.page < self.page_count() - 1:
            self.page += 1
            self.render_page()

    def render_page(self):
        pages = self.page_count()
        if self.page >= pages:
            self.page = pages - 1
        if self.page < 0:
            self.page = 0

        start = self.page * self.page_size
        chunk = self.view_entries[start:start + self.page_size]
        shown = f"{start + 1}-{start + len(chunk)}" if chunk else "0"
        total = len(self.view_entries)
        self.page_label.setText(f"Page {self.page + 1} / {pages}    ({shown} of {total})")
        self.prev_page_btn.setEnabled(self.page > 0)
        self.next_page_btn.setEnabled(self.page < pages - 1)
        self._fill_table(chunk)

    def _fill_table(self, entries):
        self.table.setUpdatesEnabled(False)
        self.table.clearContents()
        self.table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            ip_text = str(entry.get("ip", "--") or "--")
            hits = str(entry.get("hits", 0) if entry.get("hits") is not None else 0)
            raw_label = entry.get("label", "") or ""
            country = str(entry.get("country") or "").strip()
            code = str(entry.get("country_code") or "").strip()
            if country and country not in ("--", "-"):
                flag = country_flag(code) if code else "🌍"
                geo_text = f"{flag}  {country}"
            else:
                geo_text = "Unresolved"
            network_val = str(entry.get("network") or "").strip()
            network_text = network_val if network_val and network_val not in ("--", "-") else "--"

            cells = [
                (ip_text, "#55c7ff"),
                (hits, "#f5c451"),
                (raw_label if raw_label else "--", "#ff6b81"),
                (geo_text, "#50ff85"),
                (network_text, "#aaaaaa"),
            ]
            for col, (text, color) in enumerate(cells):
                item = QTableWidgetItem(text)
                item.setForeground(Qt.GlobalColor.white)
                item.setToolTip(text)
                if col == 0:
                    item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
                elif col == 1:
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.table.setItem(row, col, item)
                item.setForeground(QColor(_ink(color)))

            btn = QPushButton("Copy")
            btn.setFixedSize(48, 24)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setStyleSheet(
                "QPushButton { background: #12303a; color: #55c7ff; font-size: 11px; "
                "border: 1px solid #55c7ff; border-radius: 4px; padding: 0; }"
                "QPushButton:hover { background: #1b4452; }"
            )
            btn.clicked.connect(lambda _=False, v=ip_text: QApplication.clipboard().setText(v))
            self.table.setCellWidget(row, 5, btn)
        self.table.setUpdatesEnabled(True)

    def on_theme_changed(self):
        # Only the visible page of rows is re-filled (cheap).
        try:
            if self.table.rowCount():
                self.render_page()
        except Exception:
            pass

    def lookup_ip(self, ip: str, on_done, on_error=None):
        ip = (ip or "").strip()
        if not is_valid_ip(ip):
            if on_error:
                on_error("Invalid IP address")
            return

        if not is_public_ip(ip):
            on_done({
                "country": "Private / reserved",
                "country_only": "",
                "region": "",
                "city": "",
                "isp": "LAN",
                "asn": "",
                "org": "",
                "country_code": "",
                "network": "Private network",
            })
            return

        built = _ipapi_url(ip)
        if not built:
            msg = ("IP enrichment disabled: set env IPAPI_KEY or config "
                   "ipapi_key (never store the key in source).")
            try:
                self.app_window.add_log(f"[IPDB] {msg}")
            except Exception:
                pass
            if on_error:
                on_error(msg)
            return

        url = QUrl(built)
        req = QNetworkRequest(url)
        req.setHeader(QNetworkRequest.KnownHeaders.UserAgentHeader, "DedSecLab/1.0")
        reply = self._net.get(req)

        def finished():
            try:
                if reply.error() != QNetworkReply.NetworkError.NoError:
                    if on_error:
                        on_error(reply.errorString())
                    return
                raw = bytes(reply.readAll()).decode("utf-8", errors="replace")
                on_done(parse_ipapi_line(raw))
            except Exception as exc:
                if on_error:
                    on_error(str(exc))
            finally:
                reply.deleteLater()

        reply.finished.connect(finished)

    def _persist(self, data: dict):
        server = self.app_window.server
        try:
            if hasattr(server, "update_ip"):
                server.update_ip(data)
            else:
                server.add_ip(data)
        except Exception as exc:
            print("persist IP record:", exc)

    def enrich_missing(self):
        if self._enriching:
            return
        pending = []
        for e in self.all_entries:
            country = str(e.get("country") or "").strip()
            network = str(e.get("network") or "").strip()
            if country in ("", "--", "-") or network in ("", "--", "-"):
                if e.get("ip"):
                    pending.append(e)
        if not pending:
            self.status_pill.setText("●  All records enriched")
            self.status_pill.setStyleSheet("color: #50ff85;")
            return

        self._enriching = True
        self.refresh_btn.setEnabled(False)
        total = len(pending)
        idx = {"i": 0}

        def finish_all():
            self._enriching = False
            self.refresh_btn.setEnabled(True)
            self.status_pill.setText("●  Enrich complete")
            self.status_pill.setStyleSheet("color: #50ff85;")
            self.reload_from_server()

        def step():
            if idx["i"] >= total:
                finish_all()
                return
            entry = pending[idx["i"]]
            idx["i"] += 1
            self.status_pill.setText(f"●  Enriching {idx['i']}/{total}")
            self.status_pill.setStyleSheet("color: #55c7ff;")

            def done(info):
                self._persist({
                    "ip": entry.get("ip"),
                    "label": entry.get("label") or "",
                    "country": info.get("country") or entry.get("country") or "",
                    "network": info.get("network") or entry.get("network") or "",
                })
                QTimer.singleShot(250, step)

            def err(msg):
                print("lookup error", entry.get("ip"), msg)
                QTimer.singleShot(250, step)

            self.lookup_ip(entry.get("ip"), done, err)

        step()

    def show_add_popup(self):
        AddIPDialog(self, on_saved=self._after_save).exec()

    def _after_save(self):
        self.reload_from_server()


class AddIPDialog(QDialog):
    def __init__(self, page: IPDatabasePage, on_saved=None):
        super().__init__(page)
        self.page = page
        self.on_saved = on_saved
        self._resolved = {}

        self.setWindowTitle("Add IP Record")
        self.setFixedSize(500, 520)
        self.setObjectName("ActionsPanel")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        title = QLabel("ADD IP RECORD")
        title.setObjectName("ActionsPanelTitle")
        layout.addWidget(title)

        hint = QLabel("Geo / country and network / ASN fill in automatically.")
        hint.setObjectName("ActionsHeroDetail")
        layout.addWidget(hint)
        layout.addWidget(CyberDivider())

        def make_input(placeholder):
            inp = QLineEdit()
            inp.setObjectName("LoginInput")
            inp.setPlaceholderText(placeholder)
            inp.setMinimumHeight(42)
            return inp

        self.ip_input = make_input("IP Address (required)")
        self.label_input = make_input("Label / Tag")
        self.country_input = make_input("Country / Geo  (auto)")
        self.network_input = make_input("Network / ASN  (auto)")
        layout.addWidget(self.ip_input)
        layout.addWidget(self.label_input)
        layout.addWidget(self.country_input)
        layout.addWidget(self.network_input)

        self.status = QLabel("Enter an IP to auto-resolve geo + network")
        self.status.setObjectName("ActionsHeroDetail")
        self.status.setStyleSheet("color: #7a8a99;")
        layout.addWidget(self.status)
        layout.addStretch()

        btn_row = QHBoxLayout()
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setObjectName("ActionButton_red")
        cancel_btn.setMinimumHeight(42)
        cancel_btn.clicked.connect(self.reject)
        self.add_btn = QPushButton("+   Add Record")
        self.add_btn.setObjectName("ActionButton_green")
        self.add_btn.setMinimumHeight(42)
        self.add_btn.clicked.connect(self.submit)
        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(self.add_btn)
        layout.addLayout(btn_row)

        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(400)
        self._debounce.timeout.connect(self._auto_lookup)
        self.ip_input.textChanged.connect(self._on_ip_changed)

    def _on_ip_changed(self, _text):
        ip = self.ip_input.text().strip()
        self._resolved = {}
        if not is_valid_ip(ip):
            self.status.setText("Enter a valid IPv4 / IPv6 address")
            self.status.setStyleSheet("color: #7a8a99;")
            return
        self.status.setText("Resolving geo / ASN...")
        self.status.setStyleSheet("color: #55c7ff;")
        self._debounce.start()

    def _auto_lookup(self):
        ip = self.ip_input.text().strip()
        if not is_valid_ip(ip):
            return

        def done(info):
            if self.ip_input.text().strip() != ip:
                return
            self._resolved = info
            self.country_input.setText(info.get("country") or "")
            self.network_input.setText(info.get("network") or "")
            self.status.setText("Resolved")
            self.status.setStyleSheet("color: #50ff85;")

        def err(msg):
            if self.ip_input.text().strip() != ip:
                return
            self.status.setText(f"Lookup failed - {msg}. You can fill fields manually.")
            self.status.setStyleSheet("color: #ff6b6b;")

        self.page.lookup_ip(ip, done, err)

    def submit(self):
        ip = self.ip_input.text().strip()
        if not ip:
            self.status.setText("IP Address is required")
            self.status.setStyleSheet("color: #ff5555;")
            return
        if not is_valid_ip(ip):
            self.status.setText("That is not a valid IP address")
            self.status.setStyleSheet("color: #ff5555;")
            return

        def commit(country, network):
            data = {
                "ip": ip,
                "label": self.label_input.text().strip(),
                "country": country,
                "network": network,
            }
            try:
                self.page.app_window.server.add_ip(data)
                if self.on_saved:
                    self.on_saved()
                self.accept()
            except Exception as e:
                self.status.setText(str(e))
                self.status.setStyleSheet("color: #ff5555;")

        country = self.country_input.text().strip()
        network = self.network_input.text().strip()
        if country or network or self._resolved:
            commit(
                country or (self._resolved.get("country") if self._resolved else ""),
                network or (self._resolved.get("network") if self._resolved else ""),
            )
            return

        self.status.setText("Resolving before save...")
        self.status.setStyleSheet("color: #55c7ff;")

        def done(info):
            commit(info.get("country") or "", info.get("network") or "")

        def err(_msg):
            commit("", "")

        self.page.lookup_ip(ip, done, err)
