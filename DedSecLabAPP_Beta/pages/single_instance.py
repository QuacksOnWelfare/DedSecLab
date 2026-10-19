from PyQt6.QtCore import QSharedMemory, Qt
from PyQt6.QtNetwork import QLocalServer, QLocalSocket
from PyQt6.QtWidgets import QMessageBox, QDialog

APP_KEY = "DedSecLabAPP_Beta_single"


class SingleInstance:
    def __init__(self, app):
        self.app = app
        self.mem = QSharedMemory(APP_KEY)
        self.server = None

    def already_running(self) -> bool:
        if self.mem.attach():
            return True
        if self.mem.create(1):
            self._listen()
            return False
        return True

    def warn_and_raise(self):
        sock = QLocalSocket()
        sock.connectToServer(APP_KEY)
        if sock.waitForConnected(400):
            sock.write(b"raise")
            sock.flush()
            sock.waitForBytesWritten(400)
        sock.close()
        QMessageBox.information(None, "DedSec Lab", "DedSec Lab is already running.")

    def _listen(self):
        QLocalServer.removeServer(APP_KEY)
        self.server = QLocalServer()
        self.server.newConnection.connect(self._on_conn)
        self.server.listen(APP_KEY)

    def _on_conn(self):
        conn = self.server.nextPendingConnection()
        if conn:
            conn.readyRead.connect(self._raise_main_only)

    def _is_main(self, w) -> bool:
        title = (w.windowTitle() or "")
        name = w.objectName() or ""
        if name in ("MainWindow", "AppWindow"):
            return True
        if "DedSec-Lab Client" in title:
            return True
        if "DedSec Lab" in title and w.width() >= 800:
            return True
        return False

    def _raise_main_only(self):
        main = None
        others = []
        for w in self.app.topLevelWidgets():
            if not w.isWindow():
                continue
            if isinstance(w, QDialog) or isinstance(w, QMessageBox):
                continue
            if self._is_main(w):
                main = w
            else:
                others.append(w)
        if main is None:
            cands = [
                w for w in self.app.topLevelWidgets()
                if w.isWindow() and w.parent() is None and w.width() * w.height() > 20000
            ]
            if cands:
                main = max(cands, key=lambda w: w.width() * w.height())
                others = [w for w in others if w is not main]
        for w in others:
            try:
                w.hide()
            except Exception:
                pass
        if main is None:
            return
        main.show()
        main.setWindowState(main.windowState() & ~Qt.WindowState.WindowMinimized)
        main.raise_()
        main.activateWindow()