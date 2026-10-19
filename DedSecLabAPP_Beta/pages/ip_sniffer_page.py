"""
IP Sniffer page - UI front for lab IP Tools:
  Terminal -> IP Tools -> VPN Puller
  Terminal -> IP Tools -> VPN Puller v2

Scripts stay on the VPS. This page does not remove terminal access.
API start/stop can be wired after the CLI options are confirmed.
"""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QComboBox, QLineEdit, QTextEdit, QTableWidget,
    QTableWidgetItem, QHeaderView, QAbstractItemView, QScrollArea,
    QSizePolicy, QMessageBox,
)


class IPSnifferPage(QWidget):
    TOOLS = (
        ("vpn_puller", "VPN Puller", "Original puller (IP Tools menu)"),
        ("vpn_puller_v2", "VPN Puller v2", "Updated puller (IP Tools menu)"),
    )

    def __init__(self, app_window=None):
        super().__init__()
        self.app_window = app_window
        self._tool = "vpn_puller"
        self._running = False
        self._build_ui()

    def _card(self, title: str) -> tuple[QFrame, QVBoxLayout]:
        frame = QFrame(self)
        frame.setObjectName("ActionsPanel")
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(10)
        t = QLabel(title.upper())
        t.setObjectName("ActionsPanelTitle")
        lay.addWidget(t)
        return frame, lay

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        outer.addWidget(scroll)

        body = QWidget()
        scroll.setWidget(body)
        root = QVBoxLayout(body)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(12)

        header = QLabel("IP SNIFFER  ·  VPN PULLER")
        header.setObjectName("PageTitle")
        sub = QLabel(
            "Same tools as Terminal -> IP Tools. "
            "Use only on systems you are authorized to test."
        )
        sub.setObjectName("StatusLine")
        sub.setWordWrap(True)
        root.addWidget(header)
        root.addWidget(sub)

        pick, pl = self._card("Tool")
        row = QHBoxLayout()
        self.tool_box = QComboBox(pick)
        self.tool_box.setObjectName("EmulatorCombo")
        for key, label, _hint in self.TOOLS:
            self.tool_box.addItem(label, key)
        self.tool_box.currentIndexChanged.connect(self._on_tool_changed)
        self.tool_hint = QLabel(self.TOOLS[0][2])
        self.tool_hint.setObjectName("ActionsHeroDetail")
        self.tool_hint.setWordWrap(True)
        row.addWidget(self.tool_box, 1)
        pl.addLayout(row)
        pl.addWidget(self.tool_hint)
        root.addWidget(pick)

        opts, ol = self._card("Session")
        grid = QHBoxLayout()
        self.filter_edit = QLineEdit(opts)
        self.filter_edit.setPlaceholderText("Optional filter (IP, host, or label)")
        self.note_edit = QLineEdit(opts)
        self.note_edit.setPlaceholderText("Note saved with results")
        grid.addWidget(self.filter_edit, 1)
        grid.addWidget(self.note_edit, 1)
        ol.addLayout(grid)

        btns = QHBoxLayout()
        self.btn_start = QPushButton("Start")
        self.btn_start.setObjectName("ActionButton_green")
        self.btn_stop = QPushButton("Stop")
        self.btn_stop.setObjectName("ActionButton_blue")
        self.btn_clear = QPushButton("Clear results")
        self.btn_clear.setObjectName("ActionButton_cyan")
        self.btn_terminal = QPushButton("Open in Terminal")
        self.btn_terminal.setObjectName("ActionButton_cyan")
        self.btn_start.clicked.connect(self.start_tool)
        self.btn_stop.clicked.connect(self.stop_tool)
        self.btn_clear.clicked.connect(self.clear_results)
        self.btn_terminal.clicked.connect(self.open_terminal)
        for b in (self.btn_start, self.btn_stop, self.btn_clear, self.btn_terminal):
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setMinimumHeight(36)
        self.btn_stop.setEnabled(False)
        btns.addWidget(self.btn_start)
        btns.addWidget(self.btn_stop)
        btns.addWidget(self.btn_clear)
        btns.addWidget(self.btn_terminal)
        btns.addStretch()
        ol.addLayout(btns)

        self.status = QLabel("Idle - pick a tool")
        self.status.setObjectName("StatusLine")
        ol.addWidget(self.status)
        root.addWidget(opts)

        hits, hl = self._card("Results")
        self.table = QTableWidget(0, 5, hits)
        self.table.setHorizontalHeaderLabels(["Time", "Tool", "IP", "Port", "Note"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setMinimumHeight(180)
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        hl.addWidget(self.table)
        root.addWidget(hits, 1)

        log_card, ll = self._card("Output")
        self.log = QTextEdit(log_card)
        self.log.setReadOnly(True)
        self.log.setMinimumHeight(120)
        self.log.setStyleSheet(
            "background:#070a10; color:#50ff85; font-family: Consolas, monospace;"
        )
        self.log.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        ll.addWidget(self.log)
        root.addWidget(log_card)

        self._append("Page ready. Terminal path is unchanged: IP Tools -> VPN Puller / v2.")
        self._append("Start is disabled until the VPS script options are mapped.")

    def _on_tool_changed(self, _idx: int):
        key = self.tool_box.currentData()
        self._tool = key or "vpn_puller"
        for k, _label, hint in self.TOOLS:
            if k == self._tool:
                self.tool_hint.setText(hint)
                break
        self.status.setText(f"Selected {self.tool_box.currentText()}")

    def _append(self, text: str):
        self.log.append(text)
        if self.app_window and hasattr(self.app_window, "add_log"):
            try:
                self.app_window.add_log(f"[Sniffer] {text[:120]}")
            except Exception:
                pass

    def start_tool(self):
        if self._running:
            return
        name = self.tool_box.currentText()
        filt = self.filter_edit.text().strip()
        self._running = True
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.status.setText(f"{name} - waiting for API hook")
        self._append(f"Start requested: {name}" + (f" filter={filt}" if filt else ""))
        self._append("No API route yet. Use Terminal -> IP Tools for a live run.")
        QMessageBox.information(
            self,
            "IP Sniffer",
            f"{name} still runs from Terminal -> IP Tools until the API is added.\n\n"
            "This tab is the front-end. Terminal access is unchanged.",
        )

    def stop_tool(self):
        self._running = False
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.status.setText("Stopped")
        self._append("Stop requested.")

    def clear_results(self):
        self.table.setRowCount(0)
        self._append("Results cleared.")

    def add_result(self, when: str, ip: str, port: str = "", note: str = ""):
        r = self.table.rowCount()
        self.table.insertRow(r)
        vals = [
            when,
            self.tool_box.currentText(),
            ip,
            port,
            note or self.note_edit.text().strip(),
        ]
        for c, val in enumerate(vals):
            item = QTableWidgetItem(str(val))
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(r, c, item)

    def open_terminal(self):
        main = getattr(self.app_window, "main_page", None) or getattr(self.app_window, "main_app", None)
        if main is None:
            parent = self.parent()
            while parent is not None:
                if hasattr(parent, "show_page") and hasattr(parent, "terminal_page"):
                    main = parent
                    break
                parent = parent.parent()
        if main and hasattr(main, "show_page") and hasattr(main, "terminal_page"):
            main.show_page(main.terminal_page)
            self._append("Switched to Terminal. Open IP Tools -> VPN Puller / v2.")
            return
        QMessageBox.information(
            self,
            "Terminal",
            "Open the Terminal tab, then IP Tools -> VPN Puller or VPN Puller v2.",
        )
