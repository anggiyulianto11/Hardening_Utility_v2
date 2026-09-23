import json

from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from analysis.models import AssessmentStatus
from analysis.semi_automatic import EvidenceReference, SemiAutomaticWorkspace
from controls.registry import ControlRegistry


class SemiAutomaticEvidenceWidget(QWidget):
    HEADERS = ["Control ID", "Profile", "Area", "Control Name", "Risk", "Status", "Evidence Count", "Updated"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.workspace = SemiAutomaticWorkspace(ControlRegistry())
        self.assessment_results = []
        self.selected_control_id = None

        layout = QVBoxLayout(self)
        title = QLabel("Semi-Automatic Evidence Review")
        title.setStyleSheet("font-size: 22px; font-weight: 700;")
        layout.addWidget(title)
        intro = QLabel(
            "Kontrol semi otomatis menggabungkan bukti teknis dengan keputusan assessor. "
            "File bukti tidak disalin ke aplikasi; hanya referensi lokasi yang disimpan dan disanitasi."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        actions = QHBoxLayout()
        self.save_button = QPushButton("Save Evidence Workspace")
        self.load_button = QPushButton("Load Evidence Workspace")
        self.save_button.clicked.connect(self.save_workspace)
        self.load_button.clicked.connect(self.load_workspace)
        actions.addWidget(self.save_button)
        actions.addWidget(self.load_button)
        actions.addStretch()
        layout.addLayout(actions)

        self.summary = QLabel()
        layout.addWidget(self.summary)

        self.table = QTableWidget(0, len(self.HEADERS))
        self.table.setHorizontalHeaderLabels(self.HEADERS)
        self.table.setAlternatingRowColors(True)
        self.table.cellClicked.connect(self.select_row)
        layout.addWidget(self.table, 2)

        editor = QGroupBox("Reviewer Decision and Evidence Reference")
        form = QFormLayout(editor)
        self.control_label = QLabel("Pilih kontrol pada tabel.")
        self.status = QComboBox()
        self.status.addItems([
            AssessmentStatus.NEEDS_REVIEW.value,
            AssessmentStatus.COMPLIANT.value,
            AssessmentStatus.NON_COMPLIANT.value,
            AssessmentStatus.WARNING.value,
            AssessmentStatus.NOT_APPLICABLE.value,
            AssessmentStatus.NOT_ASSESSABLE.value,
        ])
        self.notes = QTextEdit()
        self.notes.setPlaceholderText("Catatan keputusan assessor, scope bukti, exception, dan tindak lanjut...")
        self.evidence_label = QLineEdit()
        self.evidence_label.setPlaceholderText("Contoh: WAF policy export 2026-09-23")
        self.evidence_location = QLineEdit()
        self.evidence_location.setPlaceholderText("Lokasi dokumen, ticket, URL internal, atau reference ID")
        self.evidence_type = QComboBox()
        self.evidence_type.addItems(["document", "ticket", "screenshot", "configuration", "external-system", "other"])
        self.apply_button = QPushButton("Save Reviewer Decision")
        self.add_evidence_button = QPushButton("Add Evidence Reference")
        self.apply_button.clicked.connect(self.apply_decision)
        self.add_evidence_button.clicked.connect(self.add_evidence)
        form.addRow("Selected control:", self.control_label)
        form.addRow("Decision:", self.status)
        form.addRow("Reviewer notes:", self.notes)
        form.addRow("Evidence label:", self.evidence_label)
        form.addRow("Evidence location:", self.evidence_location)
        form.addRow("Evidence type:", self.evidence_type)
        form.addRow(self.apply_button, self.add_evidence_button)
        layout.addWidget(editor, 1)
        self.refresh()

    def set_assessment_results(self, results):
        self.assessment_results = list(results or [])
        self.workspace.merge_assessment_results(self.assessment_results)
        self.refresh()

    def refresh(self):
        items = self.workspace.all()
        self.table.setRowCount(len(items))
        for row, item in enumerate(items):
            values = [
                item.control_id, item.profile, item.area, item.control_name,
                item.security_risk, item.status, len(item.evidence_references), item.updated_at,
            ]
            for column, value in enumerate(values):
                cell = QTableWidgetItem(str(value))
                cell.setToolTip(str(value))
                self.table.setItem(row, column, cell)
        counts = {}
        for item in items:
            counts[item.status] = counts.get(item.status, 0) + 1
        detail = ", ".join(f"{key}: {value}" for key, value in counts.items())
        self.summary.setText(f"{len(items)} semi-automatic controls. {detail}")
        self.table.resizeColumnsToContents()

    def select_row(self, row, _column):
        control_id = self.table.item(row, 0).text()
        review = self.workspace.get(control_id)
        if review is None:
            return
        self.selected_control_id = control_id
        self.control_label.setText(f"{review.control_id} - {review.control_name}")
        index = self.status.findText(review.status)
        if index >= 0:
            self.status.setCurrentIndex(index)
        self.notes.setPlainText(review.reviewer_notes)

    def apply_decision(self):
        review = self.workspace.get(self.selected_control_id)
        if review is None:
            QMessageBox.warning(self, "Evidence Review", "Pilih kontrol terlebih dahulu.")
            return
        review.set_decision(self.status.currentText(), self.notes.toPlainText())
        self.refresh()

    def add_evidence(self):
        review = self.workspace.get(self.selected_control_id)
        if review is None:
            QMessageBox.warning(self, "Evidence Review", "Pilih kontrol terlebih dahulu.")
            return
        label = self.evidence_label.text().strip()
        location = self.evidence_location.text().strip()
        if not label or not location:
            QMessageBox.warning(self, "Evidence Review", "Evidence label dan location wajib diisi.")
            return
        review.add_evidence(EvidenceReference(label=label, location=location, evidence_type=self.evidence_type.currentText()))
        self.evidence_label.clear()
        self.evidence_location.clear()
        self.refresh()

    def save_workspace(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Evidence Workspace", "semi_automatic_evidence.json", "JSON Files (*.json)")
        if path:
            self.workspace.save(path)
            QMessageBox.information(self, "Evidence Review", f"Workspace tersimpan:\n{path}")

    def load_workspace(self):
        path, _ = QFileDialog.getOpenFileName(self, "Load Evidence Workspace", "", "JSON Files (*.json)")
        if path:
            self.workspace.load(path)
            self.refresh()
            QMessageBox.information(self, "Evidence Review", "Workspace berhasil dimuat.")
