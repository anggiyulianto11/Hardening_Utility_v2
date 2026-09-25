from pathlib import Path

from PySide6.QtWidgets import (
    QFileDialog, QHBoxLayout, QLabel, QMessageBox, QPushButton,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from remediation.models import RemediationState
from remediation.registry import RemediationRegistry


class HardeningWidget(QWidget):
    HEADERS = ["Target", "Component", "Control ID", "Control", "Current", "Target", "Status", "Risk", "Actions"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.connection_registry = None
        self.remediation_registry = None
        self.rows = []
        self.last_backups = {}

        layout = QVBoxLayout(self)
        title = QLabel("ArcGIS Enterprise Hardening Controls")
        title.setStyleSheet("font-size: 22px; font-weight: 700;")
        layout.addWidget(title)
        note = QLabel(
            "Milestone 3A Batch 1 mengaktifkan AS-B23 per ArcGIS Server site. "
            "Workflow: Preview, scoped backup, GET latest, merge existing values, Apply, live Verify, dan Rollback."
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        self.summary = QLabel("Jalankan Connect Discover untuk memuat target server.")
        layout.addWidget(self.summary)
        self.table = QTableWidget(0, len(self.HEADERS))
        self.table.setHorizontalHeaderLabels(self.HEADERS)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.table)

    def set_connection_registry(self, registry):
        self.connection_registry = registry
        self.remediation_registry = RemediationRegistry(registry)
        self.load_targets()

    def load_targets(self):
        targets = self.remediation_registry.server_targets() if self.remediation_registry else []
        self.rows = [{"target": target, "preview": None} for target in targets]
        self.table.setRowCount(len(self.rows))
        for row, record in enumerate(self.rows):
            target = record["target"]
            role = str(getattr(target, "role", "") or getattr(target, "server_role", "") or "").strip()
            service_url = str(getattr(target, "service_url", "") or "").strip()
            display_target = target.target_name
            if role:
                display_target = f"{display_target} [{role}]"
            if service_url:
                display_target = f"{display_target}\n{service_url}"
            values = [display_target, "ArcGIS Server", "AS-B23", "Disable JSONP Callback Functions", "Not previewed", "false", "PREVIEW REQUIRED", "Warning"]
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if col == 0:
                    item.setToolTip(
                        f"Role: {role or '-'}\n"
                        f"Service URL: {service_url or '-'}\n"
                        f"Registered Admin URL: {getattr(target, 'registered_admin_url', '') or '-'}\n"
                        f"Effective Admin URL: {getattr(target, 'effective_admin_url', '') or '-'}"
                    )
                self.table.setItem(row, col, item)
            self.table.setCellWidget(row, 8, self._actions(row))
        self.table.resizeColumnsToContents()
        self.summary.setText(f"{len(targets)} ArcGIS Server target siap untuk preview AS-B23.")

    def _actions(self, row):
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(2, 2, 2, 2)
        for text, callback in (
            ("Preview", self.preview_row),
            ("Apply", self.apply_row),
            ("Verify", self.verify_row),
            ("Rollback", self.rollback_row),
        ):
            button = QPushButton(text)
            button.clicked.connect(lambda _checked=False, r=row, c=callback: c(r))
            layout.addWidget(button)
        return widget

    def _handler(self):
        return self.remediation_registry.get("AS-B23")

    def preview_row(self, row):
        target = self.rows[row]["target"]
        try:
            preview = self._handler().preview(target)
            self.rows[row]["preview"] = preview
            self.table.item(row, 4).setText(str(preview.current_value))
            self.table.item(row, 6).setText(preview.state.value)
            QMessageBox.information(
                self, "Preview AS-B23",
                f"Target: {preview.target_name}\nEndpoint: {preview.endpoint}\n\n"
                f"Current: {preview.current_value}\nTarget: false\nState: {preview.state.value}\n\n"
                f"Impact:\n{preview.impact}\n\nReason:\n{preview.reason}\n\n"
                "Apply tidak melakukan string replacement. Utility membaca object live terbaru, "
                "mempertahankan scalar property existing, lalu hanya mengubah callbackFunctionsEnabled."
            )
        except Exception as exc:
            QMessageBox.critical(self, "Preview AS-B23 gagal", str(exc))

    def apply_row(self, row):
        target = self.rows[row]["target"]
        preview = self.rows[row].get("preview")
        if preview is None:
            self.preview_row(row)
            preview = self.rows[row].get("preview")
        if preview is None or preview.state == RemediationState.BLOCKED:
            return
        if preview.state == RemediationState.ALREADY_COMPLIANT:
            QMessageBox.information(self, "AS-B23", "Target sudah compliant. Tidak ada perubahan yang dikirim.")
            return
        answer = QMessageBox.warning(
            self, "Apply AS-B23",
            f"Target: {target.target_name}\n\nJSONP callback functions akan dinonaktifkan. "
            "Aplikasi legacy berbasis JSONP dapat terdampak. Backup dibuat sebelum POST.\n\nLanjutkan?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            outcome = self._handler().apply(target)
            self.table.item(row, 4).setText(str(outcome.verified_value))
            self.table.item(row, 6).setText(outcome.state.value)
            if outcome.backup_file:
                self.last_backups[target.target_id] = outcome.backup_file
            QMessageBox.information(
                self, "AS-B23 selesai",
                f"{outcome.message}\n\nBackup: {outcome.backup_file or '-'}"
            )
        except Exception as exc:
            QMessageBox.critical(self, "Apply AS-B23 gagal", str(exc))

    def verify_row(self, row):
        target = self.rows[row]["target"]
        try:
            preview = self._handler().preview(target)
            self.rows[row]["preview"] = preview
            self.table.item(row, 4).setText(str(preview.current_value))
            self.table.item(row, 6).setText(preview.state.value)
            QMessageBox.information(self, "Verify AS-B23", f"Live value: {preview.current_value}\nState: {preview.state.value}")
        except Exception as exc:
            QMessageBox.critical(self, "Verify AS-B23 gagal", str(exc))

    def rollback_row(self, row):
        target = self.rows[row]["target"]
        backup = self.last_backups.get(target.target_id)
        if not backup:
            backup, _ = QFileDialog.getOpenFileName(self, "Pilih backup AS-B23", "", "JSON Files (*.json)")
        if not backup:
            return
        answer = QMessageBox.warning(
            self, "Rollback AS-B23",
            f"Target: {target.target_name}\nBackup: {backup}\n\n"
            "Utility akan membaca konfigurasi live terbaru dan hanya mengembalikan callbackFunctionsEnabled. Lanjutkan?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            outcome = self._handler().rollback(target, backup)
            self.table.item(row, 4).setText(str(outcome.verified_value))
            self.table.item(row, 6).setText(outcome.state.value)
            QMessageBox.information(self, "Rollback AS-B23", outcome.message)
        except Exception as exc:
            QMessageBox.critical(self, "Rollback AS-B23 gagal", str(exc))

