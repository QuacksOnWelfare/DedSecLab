from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QFrame, QPushButton
)
from ui.widgets import MiniGraphWidget, StatusRingWidget, TrafficBarsWidget, CyberDivider


class GraphStatCard(QFrame):
    def __init__(self, title, value="--", subtitle="", accent="#55c7ff"):
        super().__init__()
        self.setObjectName("DashGraphCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(4)

        self.title_label = QLabel(title)
        self.title_label.setObjectName("DashCardTitle")

        self.value_label = QLabel(value)
        self.value_label.setStyleSheet(f"color: {accent}; font-size: 22px; font-weight: 800;")

        self.graph = MiniGraphWidget(accent=accent)
        self.graph.setMinimumHeight(34)
        self.graph.setMaximumHeight(38)

        self.subtitle_label = QLabel(subtitle)
        self.subtitle_label.setObjectName("DashCardSub")

        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)
        layout.addWidget(self.graph)
        layout.addWidget(self.subtitle_label)

    def set_value(self, value):
        self.value_label.setText(str(value))
        clean = str(value).replace("%", "").strip()
        try:
            self.graph.set_value(clean)
        except Exception:
            pass


class SecurityRow(QFrame):
    def __init__(self, title, detail, ok=True):
        super().__init__()
        self.setObjectName("SecurityRow")
        self.setStyleSheet("""
            QFrame#SecurityRow {
                background: rgba(255, 255, 255, 0.03);
                border: 1px solid rgba(85, 199, 255, 0.10);
                border-radius: 10px;
            }
        """)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 11, 12, 11)
        layout.setSpacing(10)

        dot = QLabel("●")
        dot.setFixedWidth(14)
        dot.setAlignment(Qt.AlignmentFlag.AlignTop)
        dot.setStyleSheet(
            f"color: {'#50ff85' if ok else '#ff4d5f'}; font-size: 13px; font-weight: 700;"
        )

        text_box = QVBoxLayout()
        text_box.setSpacing(2)
        text_box.setContentsMargins(0, 0, 0, 0)

        self.title_label = QLabel(title)
        self.title_label.setStyleSheet(
            "color: #e8f0ff; font-size: 13px; font-weight: 700;"
        )

        self.detail_label = QLabel(detail)
        self.detail_label.setStyleSheet("color: #8a96aa; font-size: 11px;")
        self.detail_label.setWordWrap(True)

        text_box.addWidget(self.title_label)
        text_box.addWidget(self.detail_label)

        layout.addWidget(dot, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(text_box, 1)

    def set_detail(self, text):
        self.detail_label.setText(text)

    def set_title(self, text):
        self.title_label.setText(text)


class DashboardPage(QWidget):
    def __init__(self, app_window):
        super().__init__()
        self.app_window = app_window

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 14, 18, 12)
        root.setSpacing(10)

        # ========== HEADER ==========
        header = QHBoxLayout()
        title_box = QVBoxLayout()
        title_box.setSpacing(2)

        title = QLabel("DASHBOARD")
        title.setObjectName("PageTitle")

        self.connection_label = QLabel("Real-time overview of your system, VPN, and client activity.")
        self.connection_label.setObjectName("StatusLine")

        title_box.addWidget(title)
        title_box.addWidget(self.connection_label)

        self.server_pill = QLabel("● Server: Unknown")
        self.server_pill.setObjectName("StatusPill")
        self.vpn_pill = QLabel("● VPN: --")
        self.vpn_pill.setObjectName("StatusPill")
        self.uptime_pill = QLabel("◷ Uptime: Active")
        self.uptime_pill.setObjectName("StatusPill")

        header.addLayout(title_box)
        header.addStretch()
        header.addWidget(self.server_pill)
        header.addSpacing(6)
        header.addWidget(self.vpn_pill)
        header.addSpacing(6)
        header.addWidget(self.uptime_pill)
        root.addLayout(header)

        # ========== HERO ==========
        hero = QHBoxLayout()
        hero.setSpacing(10)

        system_panel = QFrame()
        system_panel.setObjectName("HeroPanel")
        system_layout = QHBoxLayout(system_panel)
        system_layout.setContentsMargins(16, 12, 16, 12)
        system_layout.setSpacing(14)

        self.status_ring = StatusRingWidget("ONLINE", "#50ff85")

        system_text = QVBoxLayout()
        system_text.setSpacing(3)

        system_title = QLabel("SYSTEM STATUS")
        system_title.setObjectName("HeroSmall")
        self.system_value = QLabel("ONLINE")
        self.system_value.setObjectName("HeroValueGreen")
        self.system_detail = QLabel("Backend Node: DSEC-LON-02")
        self.system_detail.setObjectName("HeroDetail")
        self.user_detail = QLabel("Current User: --")
        self.user_detail.setObjectName("HeroDetail")

        system_text.addWidget(system_title)
        system_text.addWidget(self.system_value)
        system_text.addWidget(CyberDivider())
        system_text.addWidget(self.system_detail)
        system_text.addWidget(self.user_detail)
        system_text.addStretch()

        system_layout.addWidget(self.status_ring)
        system_layout.addLayout(system_text, 1)

        vpn_panel = QFrame()
        vpn_panel.setObjectName("HeroPanel")
        vpn_layout = QVBoxLayout(vpn_panel)
        vpn_layout.setContentsMargins(16, 12, 16, 12)
        vpn_layout.setSpacing(4)

        vpn_title = QLabel("VPN CONNECTION")
        vpn_title.setObjectName("HeroSmall")
        self.vpn_value = QLabel("--")
        self.vpn_value.setObjectName("HeroValueGreen")
        self.vpn_detail = QLabel("VPN IP: --")
        self.vpn_detail.setObjectName("HeroDetail")
        self.vpn_protocol = QLabel("Protocol: OpenVPN")
        self.vpn_protocol.setObjectName("HeroDetail")
        self.vpn_bars = TrafficBarsWidget("#50ff85")
        self.vpn_bars.setMinimumHeight(32)

        vpn_layout.addWidget(vpn_title)
        vpn_layout.addWidget(self.vpn_value)
        vpn_layout.addWidget(CyberDivider())
        vpn_layout.addWidget(self.vpn_detail)
        vpn_layout.addWidget(self.vpn_protocol)
        vpn_layout.addWidget(self.vpn_bars)

        hero.addWidget(system_panel, 1)
        hero.addWidget(vpn_panel, 1)
        root.addLayout(hero)

        # ========== STAT CARDS ==========
        grid = QGridLayout()
        grid.setSpacing(10)

        self.cpu_card = GraphStatCard("CPU USAGE", "--", "System load", "#55c7ff")
        self.ram_card = GraphStatCard("RAM USAGE", "--", "Memory usage", "#b86cff")
        self.disk_card = GraphStatCard("DISK USAGE", "--", "Storage usage", "#ffcc33")
        self.api_card = GraphStatCard("API LATENCY", "Healthy", "Backend API", "#50ff85")

        grid.addWidget(self.cpu_card, 0, 0)
        grid.addWidget(self.ram_card, 0, 1)
        grid.addWidget(self.disk_card, 0, 2)
        grid.addWidget(self.api_card, 0, 3)
        root.addLayout(grid)

        # ========== MIDDLE ==========
        middle = QHBoxLayout()
        middle.setSpacing(10)

        # ----- ACCESS & SECURITY -----
        security_panel = QFrame()
        security_panel.setObjectName("DashPanel")
        security_layout = QVBoxLayout(security_panel)
        security_layout.setContentsMargins(16, 15, 16, 15)
        security_layout.setSpacing(10)

        security_header = QHBoxLayout()
        security_title = QLabel("ACCESS & SECURITY")
        security_title.setObjectName("DashPanelTitle")

        lock_badge = QLabel("PROTECTED")
        lock_badge.setStyleSheet(
            "color: #50ff85; font-size: 11px; font-weight: 800; "
            "padding: 3px 10px; border-radius: 6px; "
            "border: 1px solid rgba(80, 255, 133, 0.35); "
            "background: rgba(80, 255, 133, 0.08);"
        )

        security_header.addWidget(security_title)
        security_header.addStretch()
        security_header.addWidget(lock_badge)
        security_layout.addLayout(security_header)
        security_layout.addWidget(CyberDivider())

        # Short lines so they always fit
        self.sec_vpn = SecurityRow(
            "VPN Tunnel Required",
            "Login & API only over OpenVPN.",
        )
        self.sec_token = SecurityRow(
            "Terminal One-Time Token",
            "90s token bound to your VPN IP.",
        )
        self.sec_api = SecurityRow(
            "API Restricted",
            "Non-VPN clients are rejected.",
        )
        self.sec_logs = SecurityRow(
            "No Connection Logs",
            "Traffic is not stored on server.",
        )
        self.sec_role = SecurityRow(
            "Role-Based Access",
            "Role: --  ·  Auth: API + VPN",
        )

        for row in [self.sec_vpn, self.sec_token, self.sec_api, self.sec_logs, self.sec_role]:
            security_layout.addWidget(row)

        security_layout.addStretch()

        #footer_hint = QLabel("Hardened · VPN-gated · Token terminal")
        #footer_hint.setStyleSheet("color: #6a7588; font-size: 11px;")
        #footer_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        #security_layout.addWidget(footer_hint)

        # ----- NETWORK TOPOLOGY -----
        network_panel = QFrame()
        network_panel.setObjectName("DashPanel")
        network_layout = QVBoxLayout(network_panel)
        network_layout.setContentsMargins(14, 12, 14, 12)
        network_layout.setSpacing(8)

        network_title = QLabel("NETWORK TOPOLOGY")
        network_title.setObjectName("DashPanelTitle")

        topology = QLabel(
            "YOU  ━━━━━━━  VPN GATEWAY  ━━━━━━━  DEDSEC BACKEND\n\n"
            "Tunnel Encryption: AES-256-GCM\n"
            "Route Status: Protected • Access Mode: VPN restricted"
        )
        topology.setObjectName("TopologyText")
        topology.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.network_bars = TrafficBarsWidget("#55c7ff")
        self.network_bars.setMinimumHeight(34)

        network_layout.addWidget(network_title)
        network_layout.addWidget(topology, 1)
        network_layout.addWidget(self.network_bars)

        # ----- SESSION INFO -----
        session_panel = QFrame()
        session_panel.setObjectName("DashPanel")
        session_layout = QVBoxLayout(session_panel)
        session_layout.setContentsMargins(14, 12, 14, 12)
        session_layout.setSpacing(5)

        session_title = QLabel("SESSION INFO")
        session_title.setObjectName("DashPanelTitle")

        self.role_info = QLabel("Role: --")
        self.auth_info = QLabel("Authentication: API + VPN")
        self.ip_info = QLabel("VPN IP: --")
        self.terminal_info = QLabel("Terminal: Token + VPN IP")
        self.last_info = QLabel("Last Activity: Live")

        session_layout.addWidget(session_title)
        for label in [self.role_info, self.auth_info, self.ip_info, self.terminal_info, self.last_info]:
            label.setObjectName("SessionInfo")
            session_layout.addWidget(label)

        #self.details_button = QPushButton("View Full Session Details ->")
        #self.details_button.setObjectName("DashButton")
        #self.details_button.setMinimumHeight(34)
        #session_layout.addStretch()
        #session_layout.addWidget(self.details_button)

        # Slightly wider security column
        middle.addWidget(security_panel, 5)
        middle.addWidget(network_panel, 6)
        middle.addWidget(session_panel, 4)
        root.addLayout(middle, 1)

    def refresh(self):
        status = self.app_window.server.get_status()
        user = self.app_window.server.user or {}

        online = bool(status.get("online"))
        vpn_status = status.get("vpn", "--")
        cpu = status.get("cpu", "--")
        ram = status.get("ram", "--")
        disk = status.get("disk", "--")
        display_name = user.get("display_name", "--")
        role = str(user.get("role", "--")).upper()
        vpn_ip = user.get("vpn_ip", "10.8.0.2")

        self.connection_label.setText(
            "Server status: Online" if online else "Server status: Offline"
        )
        self.server_pill.setText(f"● Server: {'Online' if online else 'Offline'}")
        self.vpn_pill.setText(f"● VPN: {vpn_status}")

        if online:
            self.system_value.setText("ONLINE")
            self.system_value.setObjectName("HeroValueGreen")
            self.status_ring.set_status("ONLINE", "#50ff85")
            self.system_detail.setText("Backend Node: DSEC-LON-02")
            self.api_card.set_value("Healthy")
        else:
            self.system_value.setText("OFFLINE")
            self.system_value.setObjectName("HeroValueRed")
            self.status_ring.set_status("OFFLINE", "#ff4d5f")
            self.system_detail.setText("Backend Node: Unreachable")
            self.api_card.set_value("Offline")

        self.system_value.style().unpolish(self.system_value)
        self.system_value.style().polish(self.system_value)

        self.user_detail.setText(f"Current User: {display_name}")
        self.vpn_value.setText(str(vpn_status).upper())
        self.vpn_detail.setText(f"VPN IP: {vpn_ip}")
        self.cpu_card.set_value(f"{cpu}%")
        self.ram_card.set_value(f"{ram}%")
        self.disk_card.set_value(f"{disk}%")
        self.role_info.setText(f"Role: {role}")
        self.ip_info.setText(f"VPN IP: {vpn_ip}")

        self.sec_role.set_title("Role-Based Access")
        self.sec_role.set_detail(f"{role}  ·  API + VPN  ·  {vpn_ip}")