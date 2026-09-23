from PySide6.QtWidgets import (
    QFileDialog, QFormLayout, QGroupBox, QLabel, QLineEdit,
    QMessageBox, QPushButton, QVBoxLayout, QWidget,
)

from controls.registry import ControlRegistry
from reporting.excel_export import AssessmentExcelExporter


class ReportingWidget(QWidget):
    def __init__(self, semi_workspace=None, manual_workspace=None, parent=None):
        super().__init__(parent)
        self.results = []
        self.assessment_run = None
        self.semi_workspace = semi_workspace
        self.manual_workspace = manual_workspace

        layout = QVBoxLayout(self)
        title = QLabel("Assessment Reporting")
        title.setStyleSheet("font-size: 22px; font-weight: 700;")
        layout.addWidget(title)
        description = QLabel(
            "Ekspor workbook Excel mengikuti struktur assessment: Ringkasan, "
            "Detail Kontrol, Perlu Bukti, Peringatan, Kesiapan Implementasi, "
            "Bukti Teknis, dan Informasi Pemeriksaan."
        )
        description.setWordWrap(True)
        layout.addWidget(description)

        form_box = QGroupBox("Report Information")
        form = QFormLayout(form_box)
        self.organization_name = QLineEdit()
        self.assessor_name = QLineEdit()
        form.addRow("Organization:", self.organization_name)
        form.addRow("Assessor:", self.assessor_name)
        layout.addWidget(form_box)

        self.summary = QLabel("Belum ada hasil assessment otomatis pada sesi ini.")
        self.summary.setWordWrap(True)
        layout.addWidget(self.summary)

        self.export_button = QPushButton("Export Assessment Workbook")
        self.export_button.clicked.connect(self.export_workbook)
        layout.addWidget(self.export_button)
        layout.addStretch()

    def set_assessment_results(self, results):
        self.results = list(results or [])
        self.summary.setText(
            f"{len(self.results)} hasil assessment otomatis siap digabungkan "
            "dengan Evidence Review dan Manual Review."
        )

    def set_assessment_run(self, run):
        self.assessment_run = run

    def export_workbook(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Assessment Workbook",
            "arcgis_enterprise_hardening_assessment.xlsx",
            "Excel Workbook (*.xlsx)",
        )
        if not path:
            return
        try:
            exporter = AssessmentExcelExporter(ControlRegistry())
            exporter.export(
                path,
                assessment_results=self.results,
                semi_workspace=self.semi_workspace,
                manual_workspace=self.manual_workspace,
                assessment_run=self.assessment_run,
                organization_name=self.organization_name.text().strip(),
                assessor_name=self.assessor_name.text().strip(),
            )
            QMessageBox.information(
                self, "Assessment Reporting", f"Workbook berhasil dibuat:\n{path}"
            )
        except Exception as exc:
            QMessageBox.critical(
                self, "Assessment Reporting", f"Export gagal:\n{exc}"
            )
