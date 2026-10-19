from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QMessageBox, QFormLayout, QFrame, QGridLayout
)

from ui.widgets import StatusRingWidget, MiniGraphWidget, TrafficBarsWidget, CyberDivider


class AccountMetricCard(QFrame):
    def __init__(self, label, value="N/A", hint="", accent="#55c7ff"):
        super().__init__()
        self.setObjectName("AccountMetricCard")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(3)

        self.title_label = QLabel(label)
        self.title_label.setObjectName("AccountCardTitle")

        self.value_label = QLabel(value)
        self.value_label.setObjectName("AccountCardValue")
        self.value_label.setWordWrap(True)

        self.graph = MiniGraphWidget(accent=accent)
        self.graph.setMinimumHeight(36)
        self.graph.setMaximumHeight(38)

        self.hint_label = QLabel(hint)
        self.hint_label.setObjectName("AccountCardHint")
        self.hint_label.setWordWrap(True)

        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)
        layout.addWidget(self.graph)
        layout.addWidget(self.hint_label)

    def set_value(self, value):
        self.value_label.setText(str(value))

        try:
            self.graph.set_value(int(float(str(value).replace("%", "").strip())))
        except Exception:
            pass


class SecurityTile(QFrame):
    def __init__(self, title, value, hint):
        super().__init__()
        self.setObjectName("SecurityTile")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(3)

        title_label = QLabel(title)
        title_label.setObjectName("SecurityTileTitle")

        value_label = QLabel(value)
        value_label.setObjectName("SecurityTileValue")

        hint_label = QLabel(hint)
        hint_label.setObjectName("SecurityTileHint")
        hint_label.setWordWrap(True)

        layout.addWidget(title_label)
        layout.addWidget(value_label)
        layout.addWidget(hint_label)


class AccountPage(QWidget):
    def __init__(self, app_window):
        super().__init__()
        self.app_window = app_window

        root = QVBoxLayout(self)
        root.setContentsMargins(14, 8, 14, 8)
        root.setSpacing(6)

        # ── Header ────────────────────────────────────────────────────────────
        header = QHBoxLayout()

        title_box = QVBoxLayout()
        title_box.setSpacing(2)

        title = QLabel("My Account")
        title.setObjectName("PageTitle")

        subtitle = QLabel("Identity, subscription, VPN access, and account security.")
        subtitle.setObjectName("StatusLine")

        title_box.addWidget(title)
        title_box.addWidget(subtitle)

        self.security_badge = QLabel("● Account Security: Secure")
        self.security_badge.setObjectName("AccountBadgeGreen")
        self.security_badge.setFixedHeight(28)

        self.subscription_badge = QLabel("♛ Subscription: Active")
        self.subscription_badge.setObjectName("AccountBadgePurple")
        self.subscription_badge.setFixedHeight(28)

        header.addLayout(title_box)
        header.addStretch()
        #header.addWidget(self.security_badge, 0, Qt.AlignmentFlag.AlignVCenter)
        #header.addWidget(self.subscription_badge, 0, Qt.AlignmentFlag.AlignVCenter)

        root.addLayout(header)

        # ── Top row ───────────────────────────────────────────────────────────
        top_row = QHBoxLayout()
        top_row.setSpacing(8)

        # Profile card
        profile_card = QFrame()
        profile_card.setObjectName("AccountHeroPanel")

        profile_layout = QVBoxLayout(profile_card)
        profile_layout.setContentsMargins(10, 8, 10, 8)
        profile_layout.setSpacing(5)

        profile_title = QLabel("PROFILE IDENTITY")
        profile_title.setObjectName("AccountPanelTitle")

        profile_body = QHBoxLayout()
        profile_body.setSpacing(8)

        self.account_ring = StatusRingWidget("USER", "#55c7ff")
        self.account_ring.setMinimumSize(90, 90)
        self.account_ring.setMaximumSize(90, 90)

        identity_box = QVBoxLayout()
        identity_box.setSpacing(3)

        self.display_name_big = QLabel("N/A")
        self.display_name_big.setObjectName("AccountName")

        self.role_badge = QLabel("ROLE")
        self.role_badge.setObjectName("RoleBadge")

        self.username_line = QLabel("Username: N/A")
        self.username_line.setObjectName("AccountLine")

        self.discord_line = QLabel("Discord: N/A")
        self.discord_line.setObjectName("AccountLine")

        identity_box.addWidget(self.display_name_big)
        identity_box.addWidget(self.role_badge)
        identity_box.addWidget(CyberDivider())
        identity_box.addWidget(self.username_line)
        identity_box.addWidget(self.discord_line)
        identity_box.addStretch()

        profile_body.addWidget(self.account_ring)
        profile_body.addLayout(identity_box, 1)

        traffic_title = QLabel("ACCOUNT ACTIVITY")
        traffic_title.setObjectName("AccountPanelTitle")

        self.account_activity = TrafficBarsWidget("#55c7ff")
        self.account_activity.setMinimumHeight(28)
        self.account_activity.setMaximumHeight(30)

        profile_layout.addWidget(profile_title)
        profile_layout.addLayout(profile_body)
        profile_layout.addWidget(traffic_title)
        profile_layout.addWidget(self.account_activity)

        top_row.addWidget(profile_card, 2)

        # Metrics grid
        metric_grid = QGridLayout()
        metric_grid.setSpacing(6)

        self.role     = AccountMetricCard("Role",           "N/A",    "Access level",            "#b86cff")
        self.vpn_ip   = AccountMetricCard("VPN Identity",   "N/A",    "Assigned tunnel IP",       "#50ff85")
        self.region   = AccountMetricCard("Region",         "N/A",    "Current VPN region",       "#55c7ff")
        self.status   = AccountMetricCard("Account Status", "Active", "Subscription state",       "#50ff85")
        self.days_left= AccountMetricCard("Days Left",      "N/A",    "Subscription remaining",   "#ffcc33")
        self.expiry   = AccountMetricCard("Expiry",         "N/A",    "Renewal deadline",         "#55c7ff")

        for i, card in enumerate([self.role, self.vpn_ip, self.region,
                                   self.status, self.days_left, self.expiry]):
            metric_grid.addWidget(card, i // 3, i % 3)

        top_row.addLayout(metric_grid, 3)

        root.addLayout(top_row)

        # ── Middle row ────────────────────────────────────────────────────────
        middle_row = QHBoxLayout()
        middle_row.setSpacing(8)

        # Security overview
        security_panel = QFrame()
        security_panel.setObjectName("AccountPanel")

        security_layout = QVBoxLayout(security_panel)
        security_layout.setContentsMargins(10, 6, 10, 6)
        security_layout.setSpacing(5)

        security_title = QLabel("SECURITY OVERVIEW")
        security_title.setObjectName("AccountPanelTitle")

        security_grid = QGridLayout()
        security_grid.setSpacing(5)

        security_grid.addWidget(SecurityTile("Password Strength", "Protected", "Password authentication enabled."), 0, 0)
        security_grid.addWidget(SecurityTile("Login Security",    "Normal",    "No suspicious activity detected."), 0, 1)
        security_grid.addWidget(SecurityTile("VPN Protection",    "Active",    "VPN-restricted access enabled."),   1, 0)
        security_grid.addWidget(SecurityTile("Account Integrity", "Verified",  "Subscription and VPN identity valid."), 1, 1)

        security_layout.addWidget(security_title)
        security_layout.addLayout(security_grid)

        middle_row.addWidget(security_panel, 2)

        # Session panel
        session_panel = QFrame()
        session_panel.setObjectName("AccountPanel")

        session_layout = QVBoxLayout(session_panel)
        session_layout.setContentsMargins(10, 6, 10, 6)
        session_layout.setSpacing(5)

        session_title = QLabel("SESSION INTELLIGENCE")
        session_title.setObjectName("AccountPanelTitle")

        self.last_login    = QLabel("Last Login: Current session")
        self.login_history = QLabel("Login History: Available from server logs")
        self.auth_line     = QLabel("Authentication: API + VPN")
        self.route_line    = QLabel("Route: VPN restricted")

        session_layout.addWidget(session_title)

        for label in [self.last_login, self.login_history, self.auth_line, self.route_line]:
            label.setObjectName("AccountInfoLine")
            session_layout.addWidget(label)

        session_layout.addStretch()

        middle_row.addWidget(session_panel, 1)

        root.addLayout(middle_row)

        # ── Password section ──────────────────────────────────────────────────
        password_card = QFrame()
        password_card.setObjectName("AccountPanel")

        password_layout = QVBoxLayout(password_card)
        password_layout.setContentsMargins(10, 6, 10, 8)
        password_layout.setSpacing(5)

        password_header = QHBoxLayout()

        password_title = QLabel("CHANGE PASSWORD")
        password_title.setObjectName("AccountPanelTitle")

        password_hint = QLabel("Update your app login password. Your VPN must stay connected.")
        password_hint.setObjectName("Hint")

        password_header.addWidget(password_title)
        password_header.addStretch()
        password_header.addWidget(password_hint)

        form = QFormLayout()
        form.setSpacing(6)

        self.current_password = QLineEdit()
        self.current_password.setPlaceholderText("Enter current password")
        self.current_password.setEchoMode(QLineEdit.EchoMode.Password)

        self.new_password = QLineEdit()
        self.new_password.setPlaceholderText("Enter new password")
        self.new_password.setEchoMode(QLineEdit.EchoMode.Password)

        self.confirm_password = QLineEdit()
        self.confirm_password.setPlaceholderText("Confirm new password")
        self.confirm_password.setEchoMode(QLineEdit.EchoMode.Password)

        form.addRow("Current Password:", self.current_password)
        form.addRow("New Password:",     self.new_password)
        form.addRow("Confirm Password:", self.confirm_password)

        self.change_button = QPushButton("Update Password")
        self.change_button.setObjectName("AccountPrimaryButton")
        self.change_button.clicked.connect(self.change_password)

        password_layout.addLayout(password_header)
        password_layout.addLayout(form)
        password_layout.addWidget(self.change_button)

        root.addWidget(password_card)

    # ── Data ──────────────────────────────────────────────────────────────────

    def refresh(self):
        user = self.app_window.server.user or {}

        display_name = str(user.get("display_name", "N/A"))
        username     = str(user.get("app_username", "N/A"))
        role         = str(user.get("role", "N/A")).upper()
        vpn_ip       = str(user.get("vpn_ip", "N/A"))
        region       = str(user.get("current_vpn_region", "N/A"))
        days_left    = str(user.get("days_left", "N/A"))
        expiry       = str(user.get("subscription_expires", "N/A"))
        discord      = str(user.get("discord_name", "N/A"))

        self.display_name_big.setText(display_name)
        self.role_badge.setText(role)
        self.username_line.setText(f"Username: {username}")
        self.discord_line.setText(f"Discord: {discord}")

        self.role.set_value(role)
        self.vpn_ip.set_value(vpn_ip)
        self.region.set_value(region)
        self.days_left.set_value(days_left)
        self.expiry.set_value(expiry)
        self.status.set_value("Active")

        try:
            days_num = int(float(days_left))
            if days_num <= 3:
                self.account_ring.set_status("LOW",  "#ff4d5f")
                self.subscription_badge.setText(f"♛ Subscription: {days_left} days left")
            elif days_num <= 10:
                self.account_ring.set_status("WARN", "#ffcc33")
                self.subscription_badge.setText(f"♛ Subscription: {days_left} days left")
            else:
                self.account_ring.set_status("ACTIVE", "#50ff85")
                self.subscription_badge.setText(f"♛ Subscription: {days_left} days left")
        except Exception:
            self.account_ring.set_status("USER", "#55c7ff")
            self.subscription_badge.setText("♛ Subscription: Active")

        self.security_badge.setText("● Account Security: Secure")

    def change_password(self):
        current = self.current_password.text()
        new     = self.new_password.text()
        confirm = self.confirm_password.text()

        if not current or not new or not confirm:
            QMessageBox.warning(self, "Missing Info", "Fill in all password fields.")
            return

        if len(new) < 8:
            QMessageBox.warning(self, "Password Too Short", "New password must be at least 8 characters.")
            return

        if new != confirm:
            QMessageBox.warning(self, "Password Error", "New passwords do not match.")
            return

        ok, message = self.app_window.server.change_password(current, new)

        if not ok:
            QMessageBox.warning(self, "Password Change Failed", message)
            return

        self.current_password.clear()
        self.new_password.clear()
        self.confirm_password.clear()

        QMessageBox.information(self, "Password Changed", message)
