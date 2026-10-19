from __future__ import annotations

import subprocess
from pathlib import Path

from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QMessageBox,
)


def _run(cmd, timeout=8):
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return r.stdout or ""
    except Exception:
        return ""


class TcpScanWorker(QThread):
    done = pyqtSignal(list)
    failed = pyqtSignal(str)

    def run(self):
        try:
            rows = []
            out = _run(["netstat", "-ano"])
            procs = {}
            task = _run(["tasklist", "/FO", "CSV", "/NH"])
            for line in task.splitlines():
                parts = [p.strip().strip('"') for p in line.split(",")]
                if len(parts) >= 2 and parts[1].isdigit():
                    procs[int(parts[1])] = parts[0]

            seen = set()
            for raw in out.splitlines():
                line = raw.strip()
                if not line.startswith("TCP"):
                    continue
                bits = line.split()
                if len(bits) < 5:
                    continue
                local, remote, state, pid_s = bits[1], bits[2], bits[3], bits[4]
                if not pid_s.isdigit():
                    continue
                pid = int(pid_s)
                key = (local, remote, state, pid)
                if key in seen:
                    continue
                seen.add(key)
                local_ip, local_port = (local.rsplit(":", 1) + [""])[:2]
                remote_ip, remote_port = (remote.rsplit(":", 1) + [""])[:2]
                rows.append({
                    "pid": pid,
                    "exe": procs.get(pid, "Unknown"),
                    "state": state,
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                })
            self.done.emit(rows)
        except Exception as e:
            self.failed.emit(str(e))


class TcpMonitorPanel(QWidget):
    def __init__(self, app_window=None):
        super().__init__()
        self.app_window = app_window
        self.worker = None
        self._all_rows = []

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(10)

        title = QLabel("TCP CONNECTIONS")
        title.setObjectName("PageTitle")
        hint = QLabel("Tick one or more rows, then End process or Open file location.")
        hint.setObjectName("Hint")
        root.addWidget(title)
        root.addWidget(hint)

        bar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter EXE, PID, IP or port...")
        self.search.textChanged.connect(self._apply_filter)
        self.count_label = QLabel("0 connections")
        self.count_label.setObjectName("Hint")

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh)
        self.all_btn = QPushButton("Tick visible")
        self.all_btn.clicked.connect(lambda: self._tick_visible(True))
        self.none_btn = QPushButton("Clear ticks")
        self.none_btn.clicked.connect(lambda: self._tick_visible(False))
        self.folder_btn = QPushButton("Open file location")
        self.folder_btn.clicked.connect(self.open_location)
        self.kill_btn = QPushButton("End process")
        self.kill_btn.setObjectName("DangerButton")
        self.kill_btn.clicked.connect(self.end_process)

        bar.addWidget(self.search, 1)
        bar.addWidget(self.count_label)
        bar.addWidget(self.refresh_btn)
        bar.addWidget(self.all_btn)
        bar.addWidget(self.none_btn)
        bar.addWidget(self.folder_btn)
        bar.addWidget(self.kill_btn)
        root.addLayout(bar)

        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels([
            "", "PID", "Process", "State", "Local IP", "Local Port", "Remote IP", "Remote Port"
        ])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        root.addWidget(self.table, 1)

        note = QLabel("End process stops the EXE and drops its sockets. System PIDs (0, 4) are skipped.")
        note.setObjectName("Hint")
        root.addWidget(note)
        QTimer.singleShot(250, self.refresh)

    def refresh(self):
        if self.worker and self.worker.isRunning():
            return
        self.refresh_btn.setEnabled(False)
        self.refresh_btn.setText("Scanning...")
        self.worker = TcpScanWorker(self)
        self.worker.done.connect(self._on_rows)
        self.worker.failed.connect(self._on_fail)
        self.worker.start()

    def _on_rows(self, rows):
        self._all_rows = rows
        self._apply_filter()
        self.refresh_btn.setEnabled(True)
        self.refresh_btn.setText("Refresh")

    def _on_fail(self, err):
        self.refresh_btn.setEnabled(True)
        self.refresh_btn.setText("Refresh")
        QMessageBox.warning(self, "TCP scan", err)

    def _apply_filter(self):
        q = self.search.text().strip().lower()
        self.table.setRowCount(0)
        shown = 0
        for row in self._all_rows:
            blob = " ".join(str(v) for v in row.values()).lower()
            if q and q not in blob:
                continue
            r = self.table.rowCount()
            self.table.insertRow(r)

            chk = QTableWidgetItem()
            chk.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            chk.setCheckState(Qt.CheckState.Unchecked)
            chk.setData(Qt.ItemDataRole.UserRole, row)
            self.table.setItem(r, 0, chk)

            vals = [
                str(row["pid"]), row["exe"], row["state"],
                row["local_ip"], row["local_port"],
                row["remote_ip"], row["remote_port"],
            ]
            for c, val in enumerate(vals, start=1):
                item = QTableWidgetItem(val)
                if row["state"] == "ESTABLISHED":
                    item.setForeground(QColor("#50ff85"))
                else:
                    item.setForeground(QColor("#55c7ff"))
                self.table.setItem(r, c, item)
            shown += 1
        self.count_label.setText(f"{shown} connections")

    def _tick_visible(self, on: bool):
        state = Qt.CheckState.Checked if on else Qt.CheckState.Unchecked
        for r in range(self.table.rowCount()):
            item = self.table.item(r, 0)
            if item:
                item.setCheckState(state)

    def _checked_rows(self):
        out = []
        for r in range(self.table.rowCount()):
            item = self.table.item(r, 0)
            if item and item.checkState() == Qt.CheckState.Checked:
                data = item.data(Qt.ItemDataRole.UserRole)
                if data:
                    out.append(data)
        return out

    def end_process(self):
        rows = self._checked_rows()
        if not rows:
            QMessageBox.information(self, "End process", "Tick one or more rows first.")
            return
        pids = sorted({int(r["pid"]) for r in rows})
        skip = [p for p in pids if p in (0, 4)]
        pids = [p for p in pids if p not in (0, 4)]
        if not pids:
            QMessageBox.warning(self, "End process", "Only system PIDs were ticked (0 or 4).")
            return
        names = ", ".join(sorted({r["exe"] for r in rows if int(r["pid"]) in pids}))
        yes = QMessageBox.question(
            self,
            "End process",
            f"Stop {len(pids)} process(es)?\n{names}\nPIDs: {', '.join(map(str, pids))}",
        )
        if yes != QMessageBox.StandardButton.Yes:
            return
        ok, fail = [], []
        for pid in pids:
            r = subprocess.run(
                ["taskkill", "/PID", str(pid), "/F"],
                capture_output=True,
                text=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            (ok if r.returncode == 0 else fail).append(str(pid))
        msg = f"Stopped: {', '.join(ok) or 'none'}"
        if fail:
            msg += f"\nFailed: {', '.join(fail)}"
        if skip:
            msg += f"\nSkipped system: {', '.join(map(str, skip))}"
        QMessageBox.information(self, "End process", msg)
        self.refresh()

    def open_location(self):
        rows = self._checked_rows()
        if not rows:
            QMessageBox.information(self, "Open location", "Tick one or more rows first.")
            return
        opened = set()
        missing = []
        for row in rows:
            pid = int(row["pid"])
            if pid in opened:
                continue
            path = self._exe_path(pid)
            if path:
                subprocess.Popen(["explorer", "/select,", path])
                opened.add(pid)
            else:
                missing.append(f"{row['exe']} ({pid})")
        if missing:
            QMessageBox.warning(self, "Open location", "No path for:\n" + "\n".join(missing[:12]))

    def _exe_path(self, pid: int) -> str:
        ps = f"$p = Get-Process -Id {pid} -ErrorAction SilentlyContinue; if ($p) {{ $p.Path }}"
        out = _run(["powershell", "-NoProfile", "-Command", ps], timeout=6).strip().strip('"')
        return out if out and Path(out).exists() else ""
