import sys
from PySide6.QtCore import QObject, QThread, Signal
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QFormLayout, QGroupBox, QHBoxLayout, QLabel,
    QLineEdit, QMainWindow, QMessageBox, QPushButton, QRadioButton,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget
)
from core.models import ConnectionState
from connections.connection_registry import ConnectionRegistry


class ConnectionWorker(QObject):
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, mode, url, username, password, verify_tls):
        super().__init__()
        self.mode, self.url = mode, url
        self.username, self.password = username, password
        self.verify_tls = verify_tls

    def run(self):
        try:
            registry = ConnectionRegistry(verify_tls=self.verify_tls)
            if self.mode == "enterprise":
                result = registry.connect_enterprise(self.url, self.username, self.password)
            else:
                result = registry.connect_standalone(self.url, self.username, self.password)
            self.completed.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ArcGIS Enterprise Hardening Utility v2 - Milestone 1")
        self.resize(1050, 700)
        self.thread = None
        self.worker = None

        root = QWidget()
        layout = QVBoxLayout(root)
        self.setCentralWidget(root)

        title = QLabel("Connection and Target Discovery")
        title.setStyleSheet("font-size: 22px; font-weight: 700;")
        layout.addWidget(title)

        target_box = QGroupBox("Target Type")
        target_layout = QVBoxLayout(target_box)
        self.enterprise_radio = QRadioButton("ArcGIS Enterprise (Portal + all federated servers)")
        self.standalone_radio = QRadioButton("ArcGIS Server (standalone / non-federated)")
        self.enterprise_radio.setChecked(True)
        target_layout.addWidget(self.enterprise_radio)
        target_layout.addWidget(self.standalone_radio)
        layout.addWidget(target_box)

        connection_box = QGroupBox("Connection")
        form = QFormLayout(connection_box)
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://host/portal")
        self.username_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.verify_tls = QCheckBox("Verify TLS certificate")
        self.verify_tls.setChecked(True)
        form.addRow("Portal URL:", self.url_input)
        form.addRow("Administrator username:", self.username_input)
        form.addRow("Password:", self.password_input)
        form.addRow("", self.verify_tls)
        layout.addWidget(connection_box)
        self.connection_box = connection_box
        self.form = form

        buttons = QHBoxLayout()
        self.connect_button = QPushButton("Connect & Discover")
        self.connect_button.clicked.connect(self.connect)
        buttons.addWidget(self.connect_button)
        buttons.addStretch()
        layout.addLayout(buttons)

        self.summary = QLabel("Belum terhubung.")
        self.summary.setWordWrap(True)
        layout.addWidget(self.summary)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels([
            "Target", "Component", "Role", "Version", "State", "Admin URL", "Detail"
        ])
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)

        self.enterprise_radio.toggled.connect(self.update_mode)
        self.standalone_radio.toggled.connect(self.update_mode)
        self.update_mode()

    def update_mode(self):
        enterprise = self.enterprise_radio.isChecked()
        label = self.form.labelForField(self.url_input)
        label.setText("Portal URL:" if enterprise else "Server URL:")
        self.url_input.setPlaceholderText(
            "https://host/portal" if enterprise else "https://host/server"
        )
        self.connect_button.setText("Connect & Discover" if enterprise else "Connect Standalone Server")
        self.table.setRowCount(0)
        self.summary.setText("Belum terhubung.")

    def connect(self):
        url = self.url_input.text().strip()
        username = self.username_input.text().strip()
        password = self.password_input.text()
        if not url or not username or not password:
            QMessageBox.warning(self, "Data belum lengkap", "URL, username, dan password wajib diisi.")
            return
        mode = "enterprise" if self.enterprise_radio.isChecked() else "standalone"
        self.connect_button.setEnabled(False)
        self.summary.setText("Menghubungkan dan menemukan target...")
        self.thread = QThread(self)
        self.worker = ConnectionWorker(mode, url, username, password, self.verify_tls.isChecked())
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.completed.connect(self.on_completed)
        self.worker.failed.connect(self.on_failed)
        self.worker.completed.connect(self.thread.quit)
        self.worker.failed.connect(self.thread.quit)
        self.thread.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    def on_completed(self, result):
        self.connect_button.setEnabled(True)
        items = ([result.portal] if result.portal else []) + result.servers
        self.table.setRowCount(len(items))
        for row, target in enumerate(items):
            values = [
                target.target_name, target.component_type,
                ", ".join(target.roles) if target.roles else "-",
                target.version or "-", target.connection_state.value,
                target.effective_admin_url or "-", target.error or "-",
            ]
            for column, value in enumerate(values):
                self.table.setItem(row, column, QTableWidgetItem(str(value)))
        connected = sum(1 for item in items if item.connection_state == ConnectionState.CONNECTED)
        self.summary.setText(f"Discovery selesai. {connected} dari {len(items)} target dapat diakses.")
        self.password_input.clear()

    def on_failed(self, message):
        self.connect_button.setEnabled(True)
        self.summary.setText("Connection gagal.")
        self.password_input.clear()
        QMessageBox.critical(self, "Connection gagal", message)


def run_app():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
