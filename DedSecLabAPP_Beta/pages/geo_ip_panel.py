import json
import ssl
from core.tls import LabTLSError, ssl_context_for
import urllib.error
import urllib.request
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel,
    QLineEdit, QPushButton, QMessageBox, QFrame, QScrollArea,
)


# TLS via core.tls.ssl_context_for.


class GeoCard(QFrame):
    def __init__(self, title, value="-", hint="", accent="#55c7ff"):
        super().__init__()
        self.setObjectName("ActionsPanel")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(4)
        t = QLabel(title.upper())
        t.setObjectName("EmulatorFieldLabel")
        t.setStyleSheet(f"color: {accent}; font-weight: 700; letter-spacing: 1px;")
        self.value = QLabel(value)
        self.value.setObjectName("ActionsHeroState")
        self.value.setWordWrap(True)
        self.value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        h = QLabel(hint)
        h.setObjectName("ActionsHeroDetail")
        lay.addWidget(t)
        lay.addWidget(self.value)
        if hint:
            lay.addWidget(h)

    def set_value(self, text):
        self.value.setText(text or "-")


class GeoIpPanel(QWidget):
    def __init__(self, app_window):
        super().__init__()
        self.app_window = app_window
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 8, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        inner = QWidget()
        root = QVBoxLayout(inner)
        root.setContentsMargins(4, 4, 12, 8)
        root.setSpacing(12)

        head = QFrame()
        head.setObjectName("ActionsPanel")
        hl = QVBoxLayout(head)
        hl.setContentsMargins(16, 14, 16, 14)
        hl.setSpacing(8)
        row = QHBoxLayout()
        title = QLabel("GEO IP LOOKUP")
        title.setObjectName("ActionsPanelTitle")
        self.badge = QLabel("● Ready")
        self.badge.setObjectName("ActionsLiveBadge")
        row.addWidget(title)
        row.addStretch()
        row.addWidget(self.badge)
        hl.addLayout(row)
        sub = QLabel("VPN-gated lookup through the DedSec API.")
        sub.setObjectName("ActionsHeroDetail")
        hl.addWidget(sub)
        search = QHBoxLayout()
        self.ip_input = QLineEdit()
        self.ip_input.setObjectName("EmulatorInput")
        self.ip_input.setPlaceholderText("IPv4 address  e.g. 8.8.8.8")
        self.ip_input.returnPressed.connect(self.lookup)
        btn = QPushButton("Lookup")
        btn.setObjectName("ActionButton_cyan")
        btn.setMinimumHeight(34)
        btn.setMinimumWidth(110)
        btn.clicked.connect(self.lookup)
        search.addWidget(self.ip_input, 1)
        search.addWidget(btn)
        hl.addLayout(search)
        root.addWidget(head)

        grid = QGridLayout()
        grid.setSpacing(12)
        self.card_ip = GeoCard("Target IP", "-", "Queried address", "#55c7ff")
        self.card_rdns = GeoCard("Reverse DNS", "-", "PTR record", "#50ff85")
        self.card_loc = GeoCard("Location", "-", "City / region / country", "#b86cff")
        self.card_coords = GeoCard("Coordinates", "-", "Latitude / longitude", "#ffcc33")
        self.card_isp = GeoCard("ISP", "-", "Network provider", "#55c7ff")
        self.card_org = GeoCard("Organization", "-", "Registered org", "#50ff85")
        self.card_asn = GeoCard("ASN", "-", "Autonomous system", "#ff8833")
        self.card_country = GeoCard("Country", "-", "Geo country", "#b86cff")
        grid.addWidget(self.card_ip, 0, 0)
        grid.addWidget(self.card_rdns, 0, 1)
        grid.addWidget(self.card_loc, 1, 0)
        grid.addWidget(self.card_coords, 1, 1)
        grid.addWidget(self.card_isp, 2, 0)
        grid.addWidget(self.card_org, 2, 1)
        grid.addWidget(self.card_asn, 3, 0)
        grid.addWidget(self.card_country, 3, 1)
        root.addLayout(grid)
        root.addStretch()
        scroll.setWidget(inner)
        outer.addWidget(scroll)

    def api_base(self) -> str:
        cfg = getattr(self.app_window, "config", {}) or {}
        return str(cfg.get("server_url") or "https://YOUR_LAB_VPN_IP:8443").rstrip("/")

    def _post(self, path, body):
        url = self.api_base() + path
        data = json.dumps(body or {}).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30, context=ssl_context_for(url)) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        return json.loads(raw) if raw else {}

    def _set_badge(self, text, color="#888888"):
        self.badge.setText(f"● {text}")
        self.badge.setStyleSheet(f"color: {color};")

    def lookup(self):
        target = self.ip_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Geo IP", "Enter an IPv4 address.")
            return
        self._set_badge("Looking up...", "#ffcc33")
        try:
            tok = self._post("/api/ipcheck/token", {})
            if not tok.get("ok"):
                self._set_badge("Error", "#ff5555")
                QMessageBox.warning(self, "Geo IP", str(tok)[:400])
                return
            data = self._post(
                "/api/ipcheck/lookup",
                {"token": tok.get("token"), "ip": target},
            )
        except Exception as e:
            self._set_badge("Error", "#ff5555")
            QMessageBox.warning(self, "Geo IP", str(e)[:400])
            return
        if not data.get("ok"):
            self._set_badge("Error", "#ff5555")
            QMessageBox.warning(self, "Geo IP", str(data)[:400])
            return
        info = data.get("info") or {}
        city = info.get("city") or "-"
        region = info.get("region") or info.get("regionName") or "-"
        country = info.get("country") or "-"
        lat = info.get("lat")
        lon = info.get("lon")
        coords = f"{lat}, {lon}" if lat not in (None, "", "-") and lon not in (None, "", "-") else "-"
        self.card_ip.set_value(str(data.get("ip") or target))
        self.card_rdns.set_value(str(data.get("rdns") or "-"))
        self.card_loc.set_value(f"{city}, {region}")
        self.card_coords.set_value(coords)
        self.card_isp.set_value(str(info.get("isp") or "-"))
        self.card_org.set_value(str(info.get("org") or "-"))
        self.card_asn.set_value(str(info.get("asn") or info.get("as") or "-"))
        self.card_country.set_value(country)
        self._set_badge("Done", "#50ff85")