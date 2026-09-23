from PySide6.QtCore import QDate
from PySide6.QtWidgets import (
    QComboBox,
    QDateEdit,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from controls.registry import ControlRegistry
from manual_review.models import (
    ALLOWED_DECISIONS,
    ManualEvidenceReference,
    NOT_REVIEWED,
)
from manual_review.workspace import ManualReviewWorkspace


class ManualReviewWidget(QWidget):
    HEADERS = [
        "Control ID",
        "Profile",
        "Area",
        "Control Name",
        "Responsible Role",
        "Security Risk",
        "Privacy Risk",
        "Status",
        "Evidence",
        "Reviewer",
        "Updated",
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.workspace = ManualReviewWorkspace(ControlRegistry())
        self.selected_control_id = None

        layout = QVBoxLayout(self)
        title = QLabel("Manual Review Workflow")
        title.setStyleSheet("font-size: 22px; font-weight: 700;")
        layout.addWidget(title)

        actions = QHBoxLayout()
        self.save_button = QPushButton("Save Manual Review Workspace")
        self.load_button = QPushButton("Load Manual Review Workspace")
        self.save_button.clicked.connect(self.save_workspace)
        self.load_button.clicked.connect(self.load_workspace)
        actions.addWidget(self.save_button)
        actions.addWidget(self.load_button)
        actions.addStretch()
        layout.addLayout(actions)

        self.summary = QLabel()
        self.summary.setWordWrap(True)
        layout.addWidget(self.summary)

        splitter = QSplitter()
        self.table = QTableWidget(0, len(self.HEADERS))
        self.table.setHorizontalHeaderLabels(self.HEADERS)
        self.table.setAlternatingRowColors(True)
        self.table.cellClicked.connect(self.select_row)
        splitter.addWidget(self.table)

        editor = QWidget()
        editor_layout = QVBoxLayout(editor)
        self.requirement = QTextEdit()
        self.requirement.setReadOnly(True)
        self.requirement.setMinimumHeight(170)
        editor_layout.addWidget(self.requirement)

        form_box = QGroupBox("Assessor Decision")
        form = QFormLayout(form_box)
        self.status = QComboBox()
        ordered = [
            NOT_REVIEWED,
            "PERLU TINJAUAN",
            "SESUAI",
            "TIDAK SESUAI",
            "PERINGATAN",
            "TIDAK BERLAKU",
            "TIDAK DAPAT DINILAI",
        ]
        self.status.addItems([item for item in ordered if item in ALLOWED_DECISIONS])
        self.reviewer_name = QLineEdit()
        self.responsible_team = QLineEdit()
        self.target_date = QDateEdit()
        self.target_date.setCalendarPopup(True)
        self.target_date.setDate(QDate.currentDate())
        self.applicability_reason = QTextEdit()
        self.business_exception = QTextEdit()
        self.compensating_control = QTextEdit()
        self.reviewer_notes = QTextEdit()
        self.save_decision_button = QPushButton("Save Manual Decision")
        self.save_decision_button.clicked.connect(self.save_decision)
        form.addRow("Status:", self.status)
        form.addRow("Reviewer:", self.reviewer_name)
        form.addRow("Responsible team:", self.responsible_team)
        form.addRow("Target remediation date:", self.target_date)
        form.addRow("Applicability reason:", self.applicability_reason)
        form.addRow("Business exception:", self.business_exception)
        form.addRow("Compensating control:", self.compensating_control)
        form.addRow("Reviewer notes:", self.reviewer_notes)
        form.addRow(self.save_decision_button)
        editor_layout.addWidget(form_box)

        evidence_box = QGroupBox("Evidence Reference")
        evidence_form = QFormLayout(evidence_box)
        self.evidence_label = QLineEdit()
        self.evidence_location = QLineEdit()
        self.evidence_type = QComboBox()
        self.evidence_type.addItems(
            [
                "document",
                "ticket",
                "screenshot",
                "configuration",
                "interview",
                "policy",
                "procedure",
                "external-system",
                "other",
            ]
        )
        self.evidence_notes = QLineEdit()
        self.add_evidence_button = QPushButton("Add Manual Evidence Reference")
        self.add_evidence_button.clicked.connect(self.add_evidence)
        evidence_form.addRow("Label:", self.evidence_label)
        evidence_form.addRow("Location/reference:", self.evidence_location)
        evidence_form.addRow("Type:", self.evidence_type)
        evidence_form.addRow("Notes:", self.evidence_notes)
        evidence_form.addRow(self.add_evidence_button)
        editor_layout.addWidget(evidence_box)
        splitter.addWidget(editor)
        splitter.setSizes([950, 650])
        layout.addWidget(splitter)
        self.refresh()

    def refresh(self):
        records = self.workspace.all()
        self.table.setRowCount(len(records))
        for row, record in enumerate(records):
            values = [
                record.control_id,
                record.profile,
                record.area,
                record.control_name,
                ", ".join(record.responsible_roles) or "-",
                record.security_risk,
                record.privacy_risk,
                record.status,
                len(record.evidence_references),
                record.reviewer_name or "-",
                record.updated_at,
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setToolTip(str(value))
                self.table.setItem(row, column, item)
        completion = self.workspace.completion()
        dirty = "Unsaved changes" if self.workspace.dirty else "Saved"
        source = self.workspace.source_path or "new workspace"
        self.summary.setText(
            f"Manual controls: {completion['total']} | Decided: "
            f"{completion['decided']} | Not reviewed: "
            f"{completion['not_reviewed']} | Completion: "
            f"{completion['percent']}% | {dirty} | Source: {source}"
        )
        self.table.resizeColumnsToContents()

    def select_row(self, row, _column):
        control_id = self.table.item(row, 0).text()
        record = self.workspace.get(control_id)
        if record is None:
            return
        self.selected_control_id = control_id
        detail = (
            f"{record.control_id} - {record.control_name}\n\n"
            f"Expected condition:\n{record.expected_condition or '-'}\n\n"
            f"Recommendation:\n{record.recommendation or '-'}\n\n"
            f"Verification guidance:\n{record.verification_guidance or '-'}\n\n"
            f"Prerequisites:\n{', '.join(record.prerequisites) or '-'}\n\n"
            f"Business impact:\n{record.business_impact or '-'}\n\n"
            f"Responsible roles:\n{', '.join(record.responsible_roles) or '-'}\n\n"
            f"Official documentation:\n{record.official_documentation or '-'}"
        )
        self.requirement.setPlainText(detail)
        self.status.setCurrentText(record.status)
        self.reviewer_name.setText(record.reviewer_name)
        self.responsible_team.setText(record.responsible_team)
        self.applicability_reason.setPlainText(record.applicability_reason)
        self.business_exception.setPlainText(record.business_exception)
        self.compensating_control.setPlainText(record.compensating_control)
        self.reviewer_notes.setPlainText(record.reviewer_notes)
        if record.target_remediation_date:
            date = QDate.fromString(record.target_remediation_date, "yyyy-MM-dd")
            if date.isValid():
                self.target_date.setDate(date)

    def save_decision(self):
        record = self.workspace.get(self.selected_control_id)
        if record is None:
            QMessageBox.warning(self, "Manual Review", "Pilih kontrol terlebih dahulu.")
            return
        record.set_decision(
            self.status.currentText(),
            reviewer_name=self.reviewer_name.text(),
            reviewer_notes=self.reviewer_notes.toPlainText(),
            applicability_reason=self.applicability_reason.toPlainText(),
            business_exception=self.business_exception.toPlainText(),
            compensating_control=self.compensating_control.toPlainText(),
            responsible_team=self.responsible_team.text(),
            target_remediation_date=self.target_date.date().toString("yyyy-MM-dd"),
        )
        self.workspace.mark_dirty()
        self.refresh()

    def add_evidence(self):
        record = self.workspace.get(self.selected_control_id)
        if record is None:
            QMessageBox.warning(self, "Manual Review", "Pilih kontrol terlebih dahulu.")
            return
        label = self.evidence_label.text().strip()
        location = self.evidence_location.text().strip()
        if not label or not location:
            QMessageBox.warning(self, "Manual Review", "Label dan location wajib diisi.")
            return
        record.add_evidence(
            ManualEvidenceReference(
                label=label,
                location=location,
                evidence_type=self.evidence_type.currentText(),
                notes=self.evidence_notes.text().strip(),
            )
        )
        self.workspace.mark_dirty()
        self.evidence_label.clear()
        self.evidence_location.clear()
        self.evidence_notes.clear()
        self.refresh()

    def save_workspace(self):
        default = self.workspace.source_path or "manual_review_workspace.json"
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Manual Review Workspace", default, "JSON Files (*.json)"
        )
        if path:
            self.workspace.save(path)
            self.refresh()
            QMessageBox.information(self, "Manual Review", f"Workspace tersimpan:\n{path}")

    def load_workspace(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Load Manual Review Workspace", "", "JSON Files (*.json)"
        )
        if path:
            self.workspace.load(path)
            self.refresh()
            QMessageBox.information(self, "Manual Review", "Workspace berhasil dimuat.")

    def has_unsaved_changes(self):
        return self.workspace.dirty
