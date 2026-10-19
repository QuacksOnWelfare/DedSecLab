from datetime import datetime

from PyQt6.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QFileDialog,
    QMessageBox,
    QFrame,
)

from ui.widgets import MiniGraphWidget, TrafficBarsWidget, CyberDivider


class LogStatCard(QFrame):
    def __init__(self, title, value="0", hint="", accent="#55c7ff"):
        super().__init__()
        self.setObjectName("LogStatCard")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(5)

        self.title_label = QLabel(title)
        self.title_label.setObjectName("LogStatTitle")

        self.value_label = QLabel(value)
        self.value_label.setObjectName("LogStatValue")

        self.graph = MiniGraphWidget(accent)
        self.graph.setMinimumHeight(34)
        self.graph.setMaximumHeight(38)

        self.hint_label = QLabel(hint)
        self.hint_label.setObjectName("LogStatHint")

        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)
        layout.addWidget(self.graph)
        layout.addWidget(self.hint_label)

    def set_value(self, value):
        self.value_label.setText(str(value))

        try:
            self.graph.set_value(int(value))
        except Exception:
            pass


class LogsPage(QWidget):
    def __init__(self, app_window):
        super().__init__()
        self.app_window = app_window

        self.total_logs = 0
        self.vpn_logs = 0
        self.terminal_logs = 0
        self.error_logs = 0
        self.paused = False

        root = QVBoxLayout(self)
        root.setContentsMargins(28, 22, 28, 20)
        root.setSpacing(12)

        header = QHBoxLayout()

        title_box = QVBoxLayout()
        title_box.setSpacing(4)

        title = QLabel("System Logs")
        title.setObjectName("PageTitle")

        subtitle = QLabel(
            "Monitor client activity, VPN events, terminal events, API activity, and security messages in real time."
        )
        subtitle.setObjectName("StatusLine")
        subtitle.setWordWrap(True)

        title_box.addWidget(title)
        title_box.addWidget(subtitle)

        self.status_label = QLabel("● Status: Ready")
        self.status_label.setObjectName("LogsLiveBadge")

        header.addLayout(title_box)
        header.addStretch()
        header.addWidget(self.status_label)

        root.addLayout(header)

        overview_row = QHBoxLayout()
        overview_row.setSpacing(12)

        monitor_panel = QFrame()
        monitor_panel.setObjectName("LogsHeroPanel")
        monitor_panel.setMaximumHeight(125)

        monitor_layout = QHBoxLayout(monitor_panel)
        monitor_layout.setContentsMargins(14, 10, 14, 10)
        monitor_layout.setSpacing(14)

        monitor_spacer = QLabel("")
        monitor_spacer.setFixedWidth(10)

        monitor_text = QVBoxLayout()
        monitor_text.setSpacing(5)

        monitor_title = QLabel("LOG MONITOR")
        monitor_title.setObjectName("LogsSideTitle")

        self.monitor_state = QLabel("LIVE")
        self.monitor_state.setObjectName("LogsHeroState")

        self.monitor_detail = QLabel("Receiving client activity and security events.")
        self.monitor_detail.setObjectName("LogsHeroDetail")
        self.monitor_detail.setWordWrap(True)

        monitor_text.addWidget(monitor_title)
        monitor_text.addWidget(self.monitor_state)
        monitor_text.addWidget(CyberDivider())
        monitor_text.addWidget(self.monitor_detail)

        monitor_layout.addWidget(monitor_spacer)
        monitor_layout.addLayout(monitor_text, 1)

        telemetry_panel = QFrame()
        telemetry_panel.setObjectName("LogsHeroPanel")
        telemetry_panel.setMaximumHeight(125)

        telemetry_layout = QVBoxLayout(telemetry_panel)
        telemetry_layout.setContentsMargins(14, 10, 14, 10)
        telemetry_layout.setSpacing(5)

        telemetry_title = QLabel("LOG TELEMETRY")
        telemetry_title.setObjectName("LogsSideTitle")

        self.telemetry_graph = MiniGraphWidget("#55c7ff")
        self.telemetry_graph.setMinimumHeight(45)
        self.telemetry_graph.setMaximumHeight(48)

        self.telemetry_bars = TrafficBarsWidget("#50ff85")
        self.telemetry_bars.setMinimumHeight(28)
        self.telemetry_bars.setMaximumHeight(32)

        telemetry_layout.addWidget(telemetry_title)
        telemetry_layout.addWidget(self.telemetry_graph)
        telemetry_layout.addWidget(self.telemetry_bars)

        overview_row.addWidget(monitor_panel, 1)
        overview_row.addWidget(telemetry_panel, 1)

        root.addLayout(overview_row)

        main = QHBoxLayout()
        main.setSpacing(12)

        left = QVBoxLayout()
        left.setSpacing(10)

        filter_bar = QHBoxLayout()
        filter_bar.setSpacing(8)

        self.all_button = QPushButton("All Logs")
        self.vpn_button = QPushButton("VPN")
        self.terminal_button = QPushButton("Terminal")
        self.api_button = QPushButton("API")
        self.security_button = QPushButton("Security")
        self.warning_button = QPushButton("Warnings")
        self.error_button = QPushButton("Errors")

        for btn in [
            self.all_button,
            self.vpn_button,
            self.terminal_button,
            self.api_button,
            self.security_button,
            self.warning_button,
            self.error_button,
        ]:
            btn.setObjectName("LogFilterButton")
            filter_bar.addWidget(btn)

        filter_bar.addStretch()

        self.pause_button = QPushButton("Pause Live")
        self.pause_button.setObjectName("LogToolButton")
        self.pause_button.clicked.connect(self.toggle_pause)
        filter_bar.addWidget(self.pause_button)

        left.addLayout(filter_bar)

        self.log_card = QFrame()
        self.log_card.setObjectName("LogsConsolePanel")

        card_layout = QVBoxLayout(self.log_card)
        card_layout.setContentsMargins(14, 14, 14, 14)
        card_layout.setSpacing(10)

        self.logs = QTextEdit()
        self.logs.setReadOnly(True)
        self.logs.setObjectName("LogsTextConsole")

        card_layout.addWidget(self.logs)

        left.addWidget(self.log_card, 1)

        button_row = QHBoxLayout()
        button_row.setSpacing(10)

        clear_button = QPushButton("Clear Logs")
        clear_button.setObjectName("LogDangerButton")
        clear_button.clicked.connect(self.clear_logs)

        save_button = QPushButton("Export Logs")
        save_button.setObjectName("LogSuccessButton")
        save_button.clicked.connect(self.export_logs)

        copy_button = QPushButton("Copy Logs")
        copy_button.setObjectName("LogPrimaryButton")
        copy_button.clicked.connect(self.copy_logs)

        button_row.addWidget(clear_button)
        button_row.addWidget(save_button)
        button_row.addWidget(copy_button)
        button_row.addStretch()

        self.note = QLabel("Logs are stored only in memory unless exported manually.")
        self.note.setObjectName("Hint")
        self.note.setWordWrap(True)

        left.addLayout(button_row)
        left.addWidget(self.note)

        main.addLayout(left, 3)

        right = QVBoxLayout()
        right.setSpacing(12)

        stats_panel = QFrame()
        stats_panel.setObjectName("LogsSidePanel")

        stats_layout = QVBoxLayout(stats_panel)
        stats_layout.setContentsMargins(16, 14, 16, 14)
        stats_layout.setSpacing(8)

        stats_title = QLabel("LOG STATISTICS")
        stats_title.setObjectName("LogsSideTitle")

        self.total_card = LogStatCard("Total Logs", "0", "Current session", "#55c7ff")
        self.vpn_card = LogStatCard("VPN Events", "0", "Tunnel activity", "#50ff85")
        self.terminal_card = LogStatCard("Terminal Events", "0", "Shell/session activity", "#b86cff")
        self.error_card = LogStatCard("Errors", "0", "Warnings and errors", "#ff4d5f")

        stats_layout.addWidget(stats_title)
        stats_layout.addWidget(self.total_card)
        stats_layout.addWidget(self.vpn_card)
        stats_layout.addWidget(self.terminal_card)
        stats_layout.addWidget(self.error_card)

        activity_panel = QFrame()
        activity_panel.setObjectName("LogsSidePanel")

        activity_layout = QVBoxLayout(activity_panel)
        activity_layout.setContentsMargins(16, 14, 16, 14)
        activity_layout.setSpacing(8)

        activity_title = QLabel("LOG ACTIVITY")
        activity_title.setObjectName("LogsSideTitle")

        self.side_graph = MiniGraphWidget("#55c7ff")
        self.side_graph.setMinimumHeight(70)

        self.side_bars = TrafficBarsWidget("#50ff85")
        self.side_bars.setMinimumHeight(55)

        activity_layout.addWidget(activity_title)
        activity_layout.addWidget(self.side_graph)
        activity_layout.addWidget(self.side_bars)

        preview_panel = QFrame()
        preview_panel.setObjectName("LogsSidePanel")

        preview_layout = QVBoxLayout(preview_panel)
        preview_layout.setContentsMargins(16, 14, 16, 14)
        preview_layout.setSpacing(8)

        preview_title = QLabel("LATEST LOG PREVIEW")
        preview_title.setObjectName("LogsSideTitle")

        self.latest_preview = QLabel("No logs yet.")
        self.latest_preview.setObjectName("LogsPreviewText")
        self.latest_preview.setWordWrap(True)

        preview_layout.addWidget(preview_title)
        preview_layout.addWidget(self.latest_preview)
        preview_layout.addStretch()

        right.addWidget(stats_panel)
        right.addWidget(activity_panel)
        right.addWidget(preview_panel, 1)

        main.addLayout(right, 1)

        root.addLayout(main, 1)

    def toggle_pause(self):
        self.paused = not self.paused

        if self.paused:
            self.pause_button.setText("Resume Live")
            self.status_label.setText("● Status: Paused")
            self.monitor_state.setText("PAUSED")
            self.monitor_detail.setText("Live log display is paused.")
        else:
            self.pause_button.setText("Pause Live")
            self.status_label.setText("● Status: Receiving logs")
            self.monitor_state.setText("LIVE")
            self.monitor_detail.setText("Receiving client activity and security events.")

    def add_log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{timestamp}] {message}"

        self.total_logs += 1

        lower = str(message).lower()

        if "vpn" in lower:
            self.vpn_logs += 1

        if "terminal" in lower or "ssh" in lower:
            self.terminal_logs += 1

        if "error" in lower or "failed" in lower or "warning" in lower:
            self.error_logs += 1

        self.total_card.set_value(self.total_logs)
        self.vpn_card.set_value(self.vpn_logs)
        self.terminal_card.set_value(self.terminal_logs)
        self.error_card.set_value(self.error_logs)

        self.telemetry_graph.set_value(80)
        self.side_graph.set_value(72)

        self.latest_preview.setText(line)

        if self.error_logs > 0 and ("error" in lower or "failed" in lower):
            self.monitor_state.setText("WARNING")
            self.monitor_detail.setText("A warning or error event was detected.")
        elif not self.paused:
            self.monitor_state.setText("LIVE")
            self.monitor_detail.setText("Receiving client activity and security events.")

        if self.paused:
            return

        self.logs.append(line)

        scrollbar = self.logs.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

        self.status_label.setText("● Status: Receiving logs")

    def clear_logs(self):
        self.logs.clear()

        self.total_logs = 0
        self.vpn_logs = 0
        self.terminal_logs = 0
        self.error_logs = 0

        self.total_card.set_value(0)
        self.vpn_card.set_value(0)
        self.terminal_card.set_value(0)
        self.error_card.set_value(0)

        self.latest_preview.setText("Logs cleared.")
        self.status_label.setText("● Status: Logs cleared")

        self.monitor_state.setText("CLEARED")
        self.monitor_detail.setText("Session log buffer has been cleared.")

    def copy_logs(self):
        QApplication.clipboard().setText(self.logs.toPlainText())

        self.status_label.setText("● Status: Logs copied")
        self.monitor_state.setText("COPIED")
        self.monitor_detail.setText("Logs copied to clipboard.")

    def export_logs(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Logs",
            "dedsec_logs.txt",
            "Text Files (*.txt)",
        )

        if not file_path:
            return

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(self.logs.toPlainText())

            self.status_label.setText("● Status: Logs exported")
            self.monitor_state.setText("EXPORTED")
            self.monitor_detail.setText("Logs exported successfully.")

            QMessageBox.information(
                self,
                "Export Complete",
                f"Logs exported successfully:\n\n{file_path}",
            )

        except Exception as error:
            self.status_label.setText("● Status: Export failed")
            self.monitor_state.setText("ERROR")
            self.monitor_detail.setText("Could not export logs.")

            QMessageBox.warning(
                self,
                "Export Failed",
                f"Could not export logs:\n{error}",
            )