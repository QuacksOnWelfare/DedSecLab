from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QFrame
)

from ui.widgets import StatusRingWidget, MiniGraphWidget, TrafficBarsWidget, CyberDivider


class AboutInfoCard(QFrame):
    def __init__(self, title_text, body_text, accent="#55c7ff"):
        super().__init__()
        self.setObjectName("AboutInfoCard")
        self.setMinimumHeight(210)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(8)

        title = QLabel(title_text)
        title.setObjectName("AboutCardTitle")

        graph = MiniGraphWidget(accent)
        graph.setMinimumHeight(34)
        graph.setMaximumHeight(38)

        body = QLabel(body_text)
        body.setObjectName("AboutText")
        body.setWordWrap(True)
        body.setAlignment(Qt.AlignmentFlag.AlignTop)

        layout.addWidget(title)
        layout.addWidget(CyberDivider())
        layout.addWidget(graph)
        layout.addWidget(body)
        layout.addStretch()


class AboutPage(QWidget):
    def __init__(self):
        super().__init__()

        root = QVBoxLayout(self)
        root.setContentsMargins(28, 22, 28, 20)
        root.setSpacing(12)

        # Header
        header = QHBoxLayout()

        title_box = QVBoxLayout()
        title_box.setSpacing(4)

        title = QLabel("About DedSec-Lab")
        title.setObjectName("PageTitle")

        subtitle = QLabel(
            "Secure remote access platform for DEDSEC infrastructure, tools, VPN management, and terminal operations."
        )
        subtitle.setObjectName("StatusLine")
        subtitle.setWordWrap(True)

        title_box.addWidget(title)
        title_box.addWidget(subtitle)

        self.version_badge = QLabel("● Client v1.0.0")
        self.version_badge.setObjectName("AboutVersionBadge")

        header.addLayout(title_box)
        header.addStretch()
        header.addWidget(self.version_badge)

        root.addLayout(header)

        # Top hero row
        hero_row = QHBoxLayout()
        hero_row.setSpacing(12)

        brand_panel = QFrame()
        brand_panel.setObjectName("AboutHeroPanel")
        brand_panel.setMaximumHeight(150)

        brand_layout = QHBoxLayout(brand_panel)
        brand_layout.setContentsMargins(16, 12, 16, 12)
        brand_layout.setSpacing(16)

        logo = QLabel()
        logo.setObjectName("AboutLogo")
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo.setFixedSize(110, 110)

        logo_path = self.find_logo()
        if logo_path and logo_path.exists():
            pixmap = QPixmap(str(logo_path))
            logo.setPixmap(
                pixmap.scaled(
                    110,
                    110,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation
                )
            )
        else:
            logo.setText("☠")

        brand_text = QVBoxLayout()
        brand_text.setSpacing(5)

        brand_title = QLabel("DEDSEC-LAB CLIENT")
        brand_title.setObjectName("AboutHeroState")

        brand_subtitle = QLabel("Secure Infrastructure Access Platform")
        brand_subtitle.setObjectName("AboutHeroDetail")

        brand_detail = QLabel(
            "A managed Windows client for VPN-restricted API login, secure WebSocket terminal access, and live system monitoring."
        )
        brand_detail.setObjectName("AboutHeroDetail")
        brand_detail.setWordWrap(True)

        brand_text.addWidget(brand_title)
        brand_text.addWidget(brand_subtitle)
        brand_text.addWidget(CyberDivider())
        brand_text.addWidget(brand_detail)

        brand_layout.addWidget(logo)
        brand_layout.addLayout(brand_text, 1)

        system_panel = QFrame()
        system_panel.setObjectName("AboutHeroPanel")
        system_panel.setMaximumHeight(150)

        system_layout = QHBoxLayout(system_panel)
        system_layout.setContentsMargins(16, 12, 16, 12)
        system_layout.setSpacing(16)

        self.about_ring = StatusRingWidget("LAB", "#55c7ff")
        self.about_ring.setMaximumSize(96, 96)

        system_text = QVBoxLayout()
        system_text.setSpacing(5)

        system_title = QLabel("SYSTEM PROFILE")
        system_title.setObjectName("AboutPanelTitle")

        system_state = QLabel("SECURE")
        system_state.setObjectName("AboutHeroState")

        system_detail = QLabel("VPN-only access, API authentication, role-based terminal operations.")
        system_detail.setObjectName("AboutHeroDetail")
        system_detail.setWordWrap(True)

        system_text.addWidget(system_title)
        system_text.addWidget(system_state)
        system_text.addWidget(CyberDivider())
        system_text.addWidget(system_detail)

        system_layout.addWidget(self.about_ring)
        system_layout.addLayout(system_text, 1)

        hero_row.addWidget(brand_panel, 2)
        hero_row.addWidget(system_panel, 1)

        root.addLayout(hero_row)

        # Telemetry strip
        telemetry_panel = QFrame()
        telemetry_panel.setObjectName("AboutTelemetryPanel")
        telemetry_panel.setMaximumHeight(92)

        telemetry_layout = QHBoxLayout(telemetry_panel)
        telemetry_layout.setContentsMargins(16, 10, 16, 10)
        telemetry_layout.setSpacing(14)

        telemetry_title = QLabel("CLIENT CAPABILITIES")
        telemetry_title.setObjectName("AboutPanelTitle")

        self.platform_graph = MiniGraphWidget("#55c7ff")
        self.platform_graph.setMinimumHeight(45)
        self.platform_graph.setMaximumHeight(48)

        self.security_bars = TrafficBarsWidget("#50ff85")
        self.security_bars.setMinimumHeight(36)
        self.security_bars.setMaximumHeight(40)

        telemetry_layout.addWidget(telemetry_title)
        telemetry_layout.addWidget(self.platform_graph, 1)
        telemetry_layout.addWidget(self.security_bars, 1)

        root.addWidget(telemetry_panel)

        # Cards grid
        grid = QGridLayout()
        grid.setSpacing(12)

        overview = AboutInfoCard(
            "Platform Overview",
            (
                "DedSec-Lab is a custom Windows client built for secure access to DEDSEC Linux infrastructure.\n\n"
                "It detects VPN access, authenticates users through the DEDSEC API, and provides a managed terminal session connected to the backend tool environment."
            ),
            "#55c7ff"
        )

        features = AboutInfoCard(
            "Client Features",
            (
                "✓ Automatic VPN detection\n"
                "✓ OpenVPN install + config setup\n"
                "✓ Secure API-based login\n"
                "✓ Real-time terminal access\n"
                "✓ Live system and connection logs\n"
                "✓ Role-based access control\n"
                "✓ Router VPN and OpenVPN GUI support"
            ),
            "#50ff85"
        )

        security = AboutInfoCard(
            "Security Model",
            (
                "✓ VPN-restricted access only\n"
                "✓ IP whitelist validation\n"
                "✓ API authentication system\n"
                "✓ Secure WebSocket terminal transport\n"
                "✓ Terminal session auditing\n"
                "✓ Live session tracking\n"
                "✓ Discord event logging integration"
            ),
            "#ffcc33"
        )

        terminal = self.terminal_card()

        grid.addWidget(overview, 0, 0)
        grid.addWidget(features, 0, 1)
        grid.addWidget(security, 1, 0)
        grid.addWidget(terminal, 1, 1)

        root.addLayout(grid, 1)

        footer = QLabel("DEDSEC-LAB CLIENT  •  Secure Infrastructure Access Platform  •  v1.0.0")
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        footer.setObjectName("Hint")

        root.addWidget(footer)

    def find_logo(self):
        project_root = Path(__file__).resolve().parents[1]
        candidates = [
            project_root / "assets" / "dedsec_logo.png",
            project_root / "assets" / "dedsec_logo.jpg",
            project_root / "assets" / "dedsec_logo.jpeg",
        ]

        for candidate in candidates:
            if candidate.exists():
                return candidate

        return None

    def terminal_card(self):
        card = QFrame()
        card.setObjectName("AboutInfoCard")
        card.setMinimumHeight(210)

        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(8)

        title = QLabel("Terminal Tool System")
        title.setObjectName("AboutCardTitle")

        graph = MiniGraphWidget("#b86cff")
        graph.setMinimumHeight(34)
        graph.setMaximumHeight(38)

        intro = QLabel(
            "The integrated terminal connects users directly into the DEDSEC backend menu system. "
            "Available tools depend on authenticated role."
        )
        intro.setObjectName("AboutText")
        intro.setWordWrap(True)

        roles = QHBoxLayout()
        roles.setSpacing(10)

        standard = QLabel(
            "<b style='color:#7cff8b;'>Standard Users</b><br>"
            "• VPN utilities<br>"
            "• Network tools<br>"
            "• OSINT tools<br>"
            "• Recon utilities<br>"
            "• Help systems"
        )
        standard.setObjectName("AboutRoleStandard")
        standard.setWordWrap(True)

        admin = QLabel(
            "<b style='color:#c084fc;'>Administrators</b><br>"
            "• Admin tool categories<br>"
            "• Session monitoring<br>"
            "• Infrastructure tools<br>"
            "• Audit utilities<br>"
            "• Backend maintenance"
        )
        admin.setObjectName("AboutRoleAdmin")
        admin.setWordWrap(True)

        roles.addWidget(standard)
        roles.addWidget(admin)

        layout.addWidget(title)
        layout.addWidget(CyberDivider())
        layout.addWidget(graph)
        layout.addWidget(intro)
        layout.addLayout(roles)
        layout.addStretch()

        return card