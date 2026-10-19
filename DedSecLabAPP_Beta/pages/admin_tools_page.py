from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QFrame
)


class AdminToolCard(QFrame):
    def __init__(self, title, desc, button_text="Open", accent="blue"):
        super().__init__()
        self.setObjectName(f"AdminToolCard_{accent}")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(8)

        title_label = QLabel(title)
        title_label.setObjectName("AdminToolTitle")

        desc_label = QLabel(desc)
        desc_label.setObjectName("AdminToolDesc")
        desc_label.setWordWrap(True)

        self.button = QPushButton(button_text)
        self.button.setObjectName("AdminToolButton")

        layout.addWidget(title_label)
        layout.addWidget(desc_label)
        layout.addStretch()
        layout.addWidget(self.button)


class AdminToolsPage(QWidget):
    def __init__(self, app_window):
        super().__init__()
        self.app_window = app_window

        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 22)
        root.setSpacing(14)

        header = QHBoxLayout()

        title_box = QVBoxLayout()

        title = QLabel("Admin Tools")
        title.setObjectName("PageTitle")

        subtitle = QLabel("Admin-only controls for users, services, backups, sessions, and server maintenance.")
        subtitle.setObjectName("StatusLine")
        subtitle.setWordWrap(True)

        title_box.addWidget(title)
        title_box.addWidget(subtitle)

        self.admin_badge = QLabel("● Admin Access")
        self.admin_badge.setObjectName("AdminBadge")

        header.addLayout(title_box)
        header.addStretch()
        header.addWidget(self.admin_badge)

        root.addLayout(header)

        overview = QFrame()
        overview.setObjectName("AdminPanel")

        overview_layout = QVBoxLayout(overview)
        overview_layout.setContentsMargins(18, 16, 18, 16)
        overview_layout.setSpacing(10)

        overview_title = QLabel("ADMIN CONTROL CENTER")
        overview_title.setObjectName("AdminPanelTitle")

        self.overview_text = QLabel(
            "This page is visible only to admin accounts. "
            "Next we can connect these cards to real backend endpoints for sessions, logs, backups, VPN users, and service control."
        )
        self.overview_text.setObjectName("AdminText")
        self.overview_text.setWordWrap(True)

        overview_layout.addWidget(overview_title)
        overview_layout.addWidget(self.overview_text)

        root.addWidget(overview)

        grid = QGridLayout()
        grid.setSpacing(12)

        self.sessions_card = AdminToolCard(
            "Active Sessions",
            "View connected users, VPN IPs, roles, and last-seen timestamps.",
            "View Sessions",
            "green"
        )

        self.users_card = AdminToolCard(
            "User Management",
            "Manage whitelisted VPN users, roles, expiry dates, and account status.",
            "Manage Users",
            "blue"
        )

        self.backups_card = AdminToolCard(
            "Backups",
            "Create and view backups of access rules, configs, and important server files.",
            "Open Backups",
            "purple"
        )

        self.logs_card = AdminToolCard(
            "Server Logs",
            "Review API logs, SSH security logs, tool usage, admin audit logs, and errors.",
            "View Logs",
            "orange"
        )

        self.services_card = AdminToolCard(
            "Service Control",
            "Check or restart DEDSEC API, OpenVPN, SSH, and related services.",
            "Service Status",
            "red"
        )

        self.vpn_card = AdminToolCard(
            "VPN Admin",
            "Inspect OpenVPN status, connected clients, node health, and tunnel activity.",
            "VPN Admin",
            "cyan"
        )

        cards = [
            self.sessions_card,
            self.users_card,
            self.backups_card,
            self.logs_card,
            self.services_card,
            self.vpn_card,
        ]

        for i, card in enumerate(cards):
            grid.addWidget(card, i // 3, i % 3)

        root.addLayout(grid)

        note = QLabel(
            "Safe mode: these buttons are placeholders for now. "
            "We will wire each one to backend endpoints one at a time."
        )
        note.setObjectName("Hint")
        note.setWordWrap(True)

        root.addWidget(note)
        root.addStretch()

    def refresh(self):
        user = self.app_window.server.user or {}
        role = str(user.get("role", "standard")).upper()
        self.admin_badge.setText(f"● {role} ACCESS")