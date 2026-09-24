import json
from collections import Counter, defaultdict

from PySide6.QtCore import QObject, QThread, Signal, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QDialog, QDialogButtonBox, QFileDialog,
    QFormLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox,
    QPushButton, QSplitter, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
    QTextEdit,
)

from analysis.orchestrator import AssessmentOrchestrator
from controls.registry import ControlRegistry
from manual_review.workspace import ManualReviewWorkspace
from manual_review.models import ManualEvidenceReference
from analysis.semi_automatic import EvidenceReference, SemiAutomaticWorkspace
try:
    from remediation.registry import RemediationRegistry
    from remediation.models import RemediationState
except ImportError:
    RemediationRegistry = None
    RemediationState = None


ESSENTIAL_CONTROL_IDS = ['AS-A4', 'AS-B10', 'AS-B12', 'AS-B14', 'AS-B16', 'AS-B23', 'AS-B5', 'AS-B7', 'AS-B8', 'AS-B9', 'DP-B2', 'DP-B3', 'IA-B10', 'IA-B13', 'IA-B24']
ESSENTIAL_NAME_RULES = {'automatic enterprise account creation': ['automatic', 'enterprise', 'account', 'creation'], 'anonymous access': ['anonymous', 'access'], 'services directory': ['services', 'directory'], 'allowed origins': ['allowed', 'origins']}

def is_essential_control(control):
    if control.control_id in ESSENTIAL_CONTROL_IDS:
        return True
    normalized = ' '.join(str(control.control_name).lower().replace('-', ' ').split())
    return any(all(token in normalized for token in tokens) for tokens in ESSENTIAL_NAME_RULES.values())

STATUS_LABELS = {
    "SESUAI": "Sesuai", "TIDAK SESUAI": "Perlu Hardening",
    "PERINGATAN": "Peringatan", "PERLU TINJAUAN": "Perlu Bukti",
    "TIDAK DAPAT DINILAI": "Tidak Dapat Dinilai", "TIDAK BERLAKU": "Tidak Berlaku",
    "ERROR": "Error", "BELUM DIPERIKSA": "Belum Diperiksa",
}
STATUS_COLORS = {
    "SESUAI": "#2e7d32", "TIDAK SESUAI": "#c62828", "PERINGATAN": "#ef6c00",
    "PERLU TINJAUAN": "#b26a00", "ERROR": "#c62828", "BELUM DIPERIKSA": "#616161",
    "TIDAK DAPAT DINILAI": "#546e7a", "TIDAK BERLAKU": "#607d8b",
}


class AssessmentWorker(QObject):
    completed = Signal(object, object, int)
    failed = Signal(str)
    finished = Signal()

    def __init__(self, connection_registry, control_registry):
        super().__init__()
        self.connection_registry = connection_registry
        self.control_registry = control_registry

    def run(self):
        try:
            run, results, requests = AssessmentOrchestrator(
                self.connection_registry, self.control_registry
            ).analyze()
            self.completed.emit(run, results, requests)
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            self.finished.emit()


class UnifiedControlWorkspace(QWidget):
    assessment_completed = Signal(object)
    assessment_run_completed = Signal(object)
    log_message = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.control_registry = ControlRegistry()
        self.connection_registry = None
        self.remediation_registry = None
        self.results = []
        self.run_record = None
        self.thread = None
        self.worker = None
        self.result_map = defaultdict(list)
        self.previewed = set()
        self.last_backups = {}
        self.manual_workspace = ManualReviewWorkspace(self.control_registry)
        self.semi_workspace = SemiAutomaticWorkspace(self.control_registry)
        self._build_ui()
        self.refresh_tree()

    def _build_ui(self):
        root = QVBoxLayout(self)
        header = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("Unified Control Workspace")
        title.setStyleSheet("font-size: 23px; font-weight: 700;")
        note = QLabel("Katalog 118 kontrol menjadi pusat Analyze, Review, Hardening, Verify, dan Rollback.")
        note.setWordWrap(True)
        title_box.addWidget(title)
        title_box.addWidget(note)
        header.addLayout(title_box, 1)
        self.analyze_button = QPushButton("Analyze Environment")
        self.analyze_button.setEnabled(False)
        self.analyze_button.clicked.connect(self.run_assessment)
        # Analyze button is placed in the filter row below.
        root.addLayout(header)

        filters = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Cari ID atau nama kontrol...")
        self.search.textChanged.connect(self.refresh_tree)
        self.profile = QComboBox(); self.profile.addItems(["Semua Profil", "Essentials", "Basic", "Advanced"])
        self.profile.currentTextChanged.connect(self.refresh_tree)
        self.status_filter = QComboBox(); self.status_filter.addItems([
            "Semua Status", "Perlu Hardening", "Perlu Bukti", "Manual Review",
            "Error", "Sesuai", "Belum Diperiksa", "Remediation Available",
        ])
        self.status_filter.currentTextChanged.connect(self.refresh_tree)
        self.target_filter = QComboBox(); self.target_filter.addItem("Semua Target")
        self.target_filter.currentTextChanged.connect(self.refresh_tree)
        filters.addWidget(QLabel("Cari")); filters.addWidget(self.search, 1)
        filters.addWidget(self.profile); filters.addWidget(self.status_filter); filters.addWidget(self.target_filter); filters.addWidget(self.analyze_button)
        root.addLayout(filters)

        self.summary = QLabel("Hubungkan environment untuk memulai assessment.")
        self.summary.setWordWrap(True)
        root.addWidget(self.summary)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Kontrol / Target", "Profil", "Metode", "Status", "Affected", "Remediation"])
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tree.itemSelectionChanged.connect(self.show_selected)
        self.tree.setAlternatingRowColors(True)
        self.tree.setUniformRowHeights(False)
        self.tree.setIndentation(22)
        self.tree.header().setDefaultAlignment(Qt.AlignmentFlag.AlignCenter)
        self.tree.header().setMinimumSectionSize(90)
        splitter.addWidget(self.tree)

        details = QWidget(); detail_layout = QVBoxLayout(details)
        self.detail_title = QLabel("Pilih kontrol untuk melihat detail.")
        self.detail_title.setStyleSheet("font-size: 18px; font-weight: 700;")
        detail_layout.addWidget(self.detail_title)
        self.detail = QTextEdit(); self.detail.setReadOnly(True)
        detail_layout.addWidget(self.detail, 1)
        self.action_bar = QHBoxLayout()
        self.preview_btn = QPushButton("Preview")
        self.apply_btn = QPushButton("Apply")
        self.verify_btn = QPushButton("Verify")
        self.rollback_btn = QPushButton("Rollback")
        self.review_btn = QPushButton("Review / Evidence")
        self.preview_btn.clicked.connect(self.preview_selected)
        self.apply_btn.clicked.connect(self.apply_selected)
        self.verify_btn.clicked.connect(self.verify_selected)
        self.rollback_btn.clicked.connect(self.rollback_selected)
        self.review_btn.clicked.connect(self.review_selected)
        for button in (self.review_btn, self.preview_btn, self.apply_btn, self.verify_btn, self.rollback_btn):
            self.action_bar.addWidget(button)
        detail_layout.addLayout(self.action_bar)
        splitter.addWidget(details)
        splitter.setSizes([1050, 650])
        root.addWidget(splitter, 1)
        self._set_actions(False, False, False, False, False)

    def set_connection_registry(self, registry):
        self.connection_registry = registry
        self.remediation_registry = RemediationRegistry(registry) if RemediationRegistry else None
        targets = registry.get_connected_targets()
        self.target_filter.blockSignals(True)
        self.target_filter.clear(); self.target_filter.addItem("Semua Target")
        for target in targets:
            label = self._target_label(target)
            self.target_filter.addItem(label, target.target_id)
        self.target_filter.blockSignals(False)
        self.analyze_button.setEnabled(bool(targets))
        self.summary.setText(f"{len(targets)} target terhubung. Klik Analyze Environment.")
        self.log_message.emit(f"Discovery diterima: {len(targets)} target terhubung.")
        self.refresh_tree()

    @staticmethod
    def _target_label(target):
        role = str(getattr(target, "role", "") or getattr(target, "server_role", "") or "").strip()
        service_url = str(getattr(target, "service_url", "") or "").strip()
        name = role or target.target_name
        return f"{name} | {service_url}" if service_url else name

    def run_assessment(self):
        if not self.connection_registry or self.thread is not None:
            return
        self.analyze_button.setEnabled(False)
        self.analyze_button.setText("Analyzing...")
        self.log_message.emit("Analyze Environment dimulai.")
        self.thread = QThread()
        self.worker = AssessmentWorker(self.connection_registry, self.control_registry)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.completed.connect(self.on_assessment_completed)
        self.worker.failed.connect(self.on_assessment_failed)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.finished.connect(self.on_worker_finished)
        self.thread.start()

    def on_assessment_completed(self, run, results, requests):
        self.run_record = run
        self.results = list(results)
        self.result_map = defaultdict(list)
        for result in self.results:
            self.result_map[result.control_id].append(result)
        self.semi_workspace.merge_assessment_results(self.results)
        self.assessment_completed.emit(self.results)
        self.assessment_run_completed.emit(run)
        self.log_message.emit(f"Analyze selesai: {len(results)} hasil, {requests} request.")
        self.refresh_tree()

    def on_assessment_failed(self, message):
        self.log_message.emit(f"Analyze gagal: {message}")
        QMessageBox.critical(self, "Analyze Environment gagal", message)

    def on_worker_finished(self):
        self.worker = None; self.thread = None
        self.analyze_button.setText("Analyze Environment")
        self.analyze_button.setEnabled(self.connection_registry is not None)

    def _effective_status(self, control):
        manual = self.manual_workspace.get(control.control_id)
        if manual:
            return manual.status
        semi = self.semi_workspace.get(control.control_id)
        if semi:
            return semi.status
        results = self.result_map.get(control.control_id, [])
        if not results:
            return "BELUM DIPERIKSA"
        statuses = [r.status.value for r in results]
        for value in ("ERROR", "TIDAK SESUAI", "PERINGATAN", "PERLU TINJAUAN", "TIDAK DAPAT DINILAI", "SESUAI"):
            if value in statuses:
                return value
        return statuses[0]

    def _has_remediation(self, control_id):
        return bool(self.remediation_registry and self.remediation_registry.get(control_id))

    def refresh_tree(self):
        selected_id = None
        current = self.tree.currentItem()
        if current:
            selected_id = current.data(0, Qt.ItemDataRole.UserRole)
        self.tree.clear()
        search = self.search.text().strip().lower() if hasattr(self, "search") else ""
        profile = self.profile.currentText() if hasattr(self, "profile") else "Semua Profil"
        requested = self.status_filter.currentText() if hasattr(self, "status_filter") else "Semua Status"
        target_id = self.target_filter.currentData() if hasattr(self, "target_filter") else None
        counts = Counter()
        shown = 0
        method_order = {"Otomatis": 0, "Semi Otomatis": 1, "Peninjauan Manual": 2}
        controls = sorted(
            self.control_registry.get_all_controls(),
            key=lambda item: (method_order.get(item.verification_method, 99), item.sequence),
        )
        for control in controls:
            status = self._effective_status(control)
            label = STATUS_LABELS.get(status, status)
            remediation = self._has_remediation(control.control_id)
            if search and search not in f"{control.control_id} {control.control_name}".lower():
                continue
            if profile == "Essentials" and not is_essential_control(control):
                continue
            if profile not in ("Semua Profil", "Essentials") and control.profile != profile:
                continue
            if requested == "Perlu Hardening" and status != "TIDAK SESUAI": continue
            if requested == "Perlu Bukti" and status not in ("PERLU TINJAUAN", "TIDAK DAPAT DINILAI"): continue
            if requested == "Manual Review" and control.verification_method != "Peninjauan Manual": continue
            if requested == "Error" and status != "ERROR": continue
            if requested == "Sesuai" and status != "SESUAI": continue
            if requested == "Belum Diperiksa" and status != "BELUM DIPERIKSA": continue
            if requested == "Remediation Available" and not remediation: continue
            results = self.result_map.get(control.control_id, [])
            affected = sum(r.status.value == "TIDAK SESUAI" for r in results)
            parent = QTreeWidgetItem([
                f"{control.control_id}  {control.control_name}", control.profile,
                control.verification_method, label,
                str(affected) if results else "-", "Available" if remediation else "Review only",
            ])
            parent.setData(0, Qt.ItemDataRole.UserRole, ("control", control.control_id, None))
            parent.setForeground(3, QColor(STATUS_COLORS.get(status, "#424242")))
            self.tree.addTopLevelItem(parent)
            shown += 1; counts[label] += 1
            for result in results:
                if target_id and result.target_id != target_id:
                    continue
                target = self._find_target(result.target_id)
                target_label = self._target_label(target) if target else result.target_name
                child = QTreeWidgetItem([
                    target_label, result.profile, "Target result", STATUS_LABELS.get(result.status.value, result.status.value),
                    "1" if result.status.value == "TIDAK SESUAI" else "0",
                    "Available" if remediation and result.component_type == "server" else "-",
                ])
                child.setData(0, Qt.ItemDataRole.UserRole, ("target", control.control_id, result.target_id))
                child.setForeground(3, QColor(STATUS_COLORS.get(result.status.value, "#424242")))
                parent.addChild(child)
            if selected_id and parent.data(0, Qt.ItemDataRole.UserRole) == selected_id:
                self.tree.setCurrentItem(parent)
        detail = " | ".join(f"{name}: {value}" for name, value in counts.items())
        self.summary.setText(f"Menampilkan {shown} dari {len(self.control_registry.get_all_controls())} kontrol" + (f" | {detail}" if detail else ""))
        for i in range(self.tree.columnCount()):
            self.tree.resizeColumnToContents(i)

    def _find_target(self, target_id):
        if not self.connection_registry: return None
        return next((t for t in self.connection_registry.get_connected_targets() if t.target_id == target_id), None)

    def _selection(self):
        item = self.tree.currentItem()
        return item.data(0, Qt.ItemDataRole.UserRole) if item else None

    def show_selected(self):
        selection = self._selection()
        if not selection:
            self._set_actions(False, False, False, False, False); return
        kind, control_id, target_id = selection
        control = self.control_registry.get_control_by_id(control_id)
        results = self.result_map.get(control_id, [])
        if target_id:
            results = [r for r in results if r.target_id == target_id]
        self.detail_title.setText(f"{control.control_id}  {control.control_name}")
        status = self._effective_status(control)
        lines = [
            f"Profile: {control.profile}", f"Area: {control.area}",
            f"Metode: {control.verification_method}", f"Status: {STATUS_LABELS.get(status, status)}",
            f"Risiko keamanan: {control.security_risk}", f"Risiko privasi: {control.privacy_risk}",
            "", "Kondisi yang Diharapkan:", control.expected_condition or "-",
            "", "Rekomendasi:", control.recommendation or "-",
        ]
        for result in results:
            lines.extend(["", f"Target: {result.target_name}", f"Current: {result.current_condition or '-'}", f"Status: {result.status.value}"])
        self.detail.setPlainText("\n".join(lines))
        target = self._find_target(target_id) if target_id else None
        remediation = bool(target and self._has_remediation(control_id))
        previewed = (control_id, target_id) in self.previewed
        backup = self.last_backups.get((control_id, target_id))
        reviewable = control.verification_method in ("Semi Otomatis", "Peninjauan Manual")
        self._set_actions(reviewable, remediation, remediation and previewed, remediation, bool(backup))

    def _set_actions(self, review, preview, apply, verify, rollback):
        self.review_btn.setEnabled(review); self.preview_btn.setEnabled(preview)
        self.apply_btn.setEnabled(apply); self.verify_btn.setEnabled(verify); self.rollback_btn.setEnabled(rollback)

    def _selected_remediation(self):
        selection = self._selection()
        if not selection or selection[0] != "target":
            QMessageBox.information(self, "Remediation", "Pilih child target pada kontrol yang mendukung remediation.")
            return None, None, None
        _, control_id, target_id = selection
        target = self._find_target(target_id)
        handler = self.remediation_registry.get(control_id) if self.remediation_registry else None
        if not target or not handler:
            QMessageBox.information(self, "Remediation", "Remediation belum tersedia untuk target ini.")
            return None, None, None
        return control_id, target, handler

    def preview_selected(self):
        control_id, target, handler = self._selected_remediation()
        if not handler: return
        try:
            preview = handler.preview(target)
            self.previewed.add((control_id, target.target_id))
            self.log_message.emit(f"Preview {control_id} pada {self._target_label(target)}: {preview.state.value}")
            QMessageBox.information(self, f"Preview {control_id}",
                f"Target: {self._target_label(target)}\nEndpoint: {preview.endpoint}\n\nCurrent: {preview.current_value}\nTarget: {preview.target_value}\nState: {preview.state.value}\n\nImpact:\n{preview.impact}\n\n{preview.reason}")
            self.show_selected()
        except Exception as exc:
            self.log_message.emit(f"Preview {control_id} gagal: {exc}")
            QMessageBox.critical(self, "Preview gagal", str(exc))

    def apply_selected(self):
        control_id, target, handler = self._selected_remediation()
        if not handler: return
        if (control_id, target.target_id) not in self.previewed:
            QMessageBox.warning(self, "Preview diperlukan", "Jalankan Preview sebelum Apply."); return
        answer = QMessageBox.warning(self, f"Apply {control_id}", f"Target:\n{self._target_label(target)}\n\nBackup dan live verification akan dijalankan. Lanjutkan?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        if answer != QMessageBox.StandardButton.Yes: return
        try:
            outcome = handler.apply(target)
            if outcome.backup_file: self.last_backups[(control_id, target.target_id)] = outcome.backup_file
            self.log_message.emit(f"Apply {control_id}: {outcome.state.value} | {outcome.message}")
            QMessageBox.information(self, f"Apply {control_id}", f"{outcome.message}\n\nBackup: {outcome.backup_file or '-'}")
            self.verify_selected()
        except Exception as exc:
            self.log_message.emit(f"Apply {control_id} gagal: {exc}")
            QMessageBox.critical(self, "Apply gagal", str(exc))
        self.show_selected()

    def verify_selected(self):
        control_id, target, handler = self._selected_remediation()
        if not handler: return
        try:
            preview = handler.preview(target)
            self.log_message.emit(f"Verify {control_id}: current={preview.current_value}, state={preview.state.value}")
            QMessageBox.information(self, f"Verify {control_id}", f"Target: {self._target_label(target)}\nLive value: {preview.current_value}\nState: {preview.state.value}")
        except Exception as exc:
            self.log_message.emit(f"Verify {control_id} gagal: {exc}")
            QMessageBox.critical(self, "Verify gagal", str(exc))

    def rollback_selected(self):
        control_id, target, handler = self._selected_remediation()
        if not handler: return
        backup = self.last_backups.get((control_id, target.target_id))
        if not backup:
            backup, _ = QFileDialog.getOpenFileName(self, "Pilih backup", "", "JSON Files (*.json)")
        if not backup: return
        answer = QMessageBox.warning(self, f"Rollback {control_id}", f"Target:\n{self._target_label(target)}\n\nBackup:\n{backup}\n\nLanjutkan?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        if answer != QMessageBox.StandardButton.Yes: return
        try:
            outcome = handler.rollback(target, backup)
            self.log_message.emit(f"Rollback {control_id}: {outcome.message}")
            QMessageBox.information(self, f"Rollback {control_id}", outcome.message)
        except Exception as exc:
            self.log_message.emit(f"Rollback {control_id} gagal: {exc}")
            QMessageBox.critical(self, "Rollback gagal", str(exc))

    def review_selected(self):
        selection = self._selection()
        if not selection: return
        _, control_id, _ = selection
        control = self.control_registry.get_control_by_id(control_id)
        dialog = QDialog(self); dialog.setWindowTitle(f"Review {control_id}"); dialog.resize(720, 620)
        layout = QVBoxLayout(dialog)
        form = QFormLayout()
        status = QComboBox(); status.addItems(["PERLU TINJAUAN", "SESUAI", "TIDAK SESUAI", "PERINGATAN", "TIDAK BERLAKU", "TIDAK DAPAT DINILAI"])
        reviewer = QLineEdit(); notes = QTextEdit(); evidence_label = QLineEdit(); evidence_location = QLineEdit()
        form.addRow("Status:", status); form.addRow("Reviewer:", reviewer); form.addRow("Catatan:", notes)
        form.addRow("Evidence label:", evidence_label); form.addRow("Evidence location:", evidence_location)
        layout.addLayout(form)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept); buttons.rejected.connect(dialog.reject); layout.addWidget(buttons)
        if dialog.exec() != QDialog.DialogCode.Accepted: return
        if control.verification_method == "Peninjauan Manual":
            record = self.manual_workspace.get(control_id)
            record.set_decision(status.currentText(), reviewer_name=reviewer.text(), reviewer_notes=notes.toPlainText())
            if evidence_label.text().strip() and evidence_location.text().strip():
                record.add_evidence(ManualEvidenceReference(evidence_label.text().strip(), evidence_location.text().strip()))
            self.manual_workspace.mark_dirty()
        else:
            record = self.semi_workspace.get(control_id)
            record.set_decision(status.currentText(), notes.toPlainText())
            if evidence_label.text().strip() and evidence_location.text().strip():
                record.add_evidence(EvidenceReference(evidence_label.text().strip(), evidence_location.text().strip()))
        self.log_message.emit(f"Review {control_id} disimpan: {status.currentText()}")
        self.refresh_tree()
