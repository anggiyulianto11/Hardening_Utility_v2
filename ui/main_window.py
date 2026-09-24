import sys
from PySide6.QtCore import QObject, QThread, Signal
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QFileDialog, QFormLayout, QGroupBox, QHBoxLayout,
    QLabel, QLineEdit, QMainWindow, QMessageBox, QPushButton, QRadioButton,
    QTableWidget, QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget,
)
from connections.connection_registry import ConnectionRegistry
from core.models import ConnectionState
from core.security import redact_text
from exports.discovery_export import export_discovery
from ui.assessment_widget import AssessmentWidget
from ui.catalog_widget import ControlCatalogWidget
from ui.semi_automatic_widget import SemiAutomaticEvidenceWidget
from ui.manual_review_widget import ManualReviewWidget
from ui.reporting_widget import ReportingWidget
from ui.hardening_widget import HardeningWidget


class ConnectionWorker(QObject):
    completed = Signal(object, object)
    failed = Signal(str)
    def __init__(self, mode, url, username, password, verify_tls):
        super().__init__(); self.mode=mode; self.url=url; self.username=username; self.password=password; self.verify_tls=verify_tls
    def run(self):
        try:
            registry=ConnectionRegistry(verify_tls=self.verify_tls)
            result=registry.connect_enterprise(self.url,self.username,self.password) if self.mode=="enterprise" else registry.connect_standalone(self.url,self.username,self.password)
            self.password=""; self.completed.emit(result,registry)
        except Exception as exc:
            self.password=""; self.failed.emit(redact_text(exc))


class DiscoveryWidget(QWidget):
    discovery_completed = Signal(object)
    HEADERS=["Target","Component","Role / Function","Version","State","Service URL","Registered Admin URL","Effective Admin URL","Route","Detail"]
    def __init__(self,parent=None):
        super().__init__(parent); self.thread=None; self.worker=None; self.current_result=None; self.connection_registry=None
        layout=QVBoxLayout(self); title=QLabel("Connection and Target Discovery"); title.setStyleSheet("font-size: 22px; font-weight: 700;"); layout.addWidget(title)
        target_box=QGroupBox("Target Type"); target_layout=QVBoxLayout(target_box); self.enterprise_radio=QRadioButton("ArcGIS Enterprise (Portal + all federated servers)"); self.standalone_radio=QRadioButton("ArcGIS Server (standalone / non-federated)"); self.enterprise_radio.setChecked(True); target_layout.addWidget(self.enterprise_radio); target_layout.addWidget(self.standalone_radio); layout.addWidget(target_box)
        box=QGroupBox("Connection"); self.form=QFormLayout(box); self.url_input=QLineEdit(); self.username_input=QLineEdit(); self.password_input=QLineEdit(); self.password_input.setEchoMode(QLineEdit.Password); self.verify_tls=QCheckBox("Verify TLS certificate"); self.verify_tls.setChecked(True); self.form.addRow("Portal URL:",self.url_input); self.form.addRow("Administrator username:",self.username_input); self.form.addRow("Password:",self.password_input); self.form.addRow("",self.verify_tls); layout.addWidget(box)
        buttons=QHBoxLayout(); self.connect_button=QPushButton("Connect & Discover"); self.connect_button.clicked.connect(self.connect_target); self.export_button=QPushButton("Export Discovery JSON"); self.export_button.setEnabled(False); self.export_button.clicked.connect(self.export_current_result); buttons.addWidget(self.connect_button); buttons.addWidget(self.export_button); buttons.addStretch(); layout.addLayout(buttons)
        self.summary=QLabel("Belum terhubung."); layout.addWidget(self.summary); self.table=QTableWidget(0,len(self.HEADERS)); self.table.setHorizontalHeaderLabels(self.HEADERS); self.table.cellDoubleClicked.connect(self.show_target_details); layout.addWidget(self.table)
        self.enterprise_radio.toggled.connect(self.update_mode); self.standalone_radio.toggled.connect(self.update_mode); self.update_mode()
    def update_mode(self):
        enterprise=self.enterprise_radio.isChecked(); self.form.labelForField(self.url_input).setText("Portal URL:" if enterprise else "Server URL:"); self.url_input.setPlaceholderText("https://host/portal" if enterprise else "https://host/server"); self.connect_button.setText("Connect & Discover" if enterprise else "Connect Standalone Server"); self.table.setRowCount(0); self.current_result=None; self.connection_registry=None; self.export_button.setEnabled(False); self.summary.setText("Belum terhubung.")
    def connect_target(self):
        url,username,password=self.url_input.text().strip(),self.username_input.text().strip(),self.password_input.text()
        if not url or not username or not password: QMessageBox.warning(self,"Data belum lengkap","URL, username, dan password wajib diisi."); return
        mode="enterprise" if self.enterprise_radio.isChecked() else "standalone"; self.connect_button.setEnabled(False); self.summary.setText("Menghubungkan dan menemukan target..."); self.thread=QThread(self); self.worker=ConnectionWorker(mode,url,username,password,self.verify_tls.isChecked()); self.worker.moveToThread(self.thread); self.thread.started.connect(self.worker.run); self.worker.completed.connect(self.on_completed); self.worker.failed.connect(self.on_failed); self.worker.completed.connect(self.thread.quit); self.worker.failed.connect(self.thread.quit); self.thread.finished.connect(self.worker.deleteLater); self.thread.finished.connect(self.thread.deleteLater); self.thread.start()
    @staticmethod
    def _route(t): return t.connection_route.value if t.connection_route else "-"
    @staticmethod
    def _roles(t):
        values=list(t.roles)+[x for x in t.server_functions if x not in t.roles]; return ", ".join(values) if values else "-"
    def on_completed(self,result,registry):
        self.connect_button.setEnabled(True); self.password_input.clear(); self.current_result=result; self.connection_registry=registry; self.export_button.setEnabled(True); self.table.setRowCount(len(result.targets))
        for row,t in enumerate(result.targets):
            detail=t.error or ("Connected via "+self._route(t) if t.connection_state==ConnectionState.CONNECTED else "-"); values=[t.target_name,t.component_type,self._roles(t),t.version or "-",t.connection_state.value,t.service_url or "-",t.registered_admin_url or "-",t.effective_admin_url or "-",self._route(t),detail]
            for col,value in enumerate(values): item=QTableWidgetItem(str(value)); item.setToolTip(str(value)); self.table.setItem(row,col,item)
        self.table.resizeColumnsToContents(); self.summary.setText(f"Discovery selesai. {result.connected_count} dari {len(result.targets)} target dapat diakses."); self.discovery_completed.emit(registry)
    def on_failed(self,message): self.connect_button.setEnabled(True); self.password_input.clear(); self.summary.setText("Connection gagal."); QMessageBox.critical(self,"Connection gagal",redact_text(message))
    def show_target_details(self,row,_column):
        if not self.current_result or row>=len(self.current_result.targets): return
        t=self.current_result.targets[row]; lines=[f"Target ID: {t.target_id}",f"Target Name: {t.target_name}",f"Component: {t.component_type}",f"Deployment Mode: {t.deployment_mode}",f"Version: {t.version or '-'}",f"Roles: {', '.join(t.roles) or '-'}",f"Server Functions: {', '.join(t.server_functions) or '-'}",f"Federation State: {t.federation_state}",f"Connection State: {t.connection_state.value}",f"Service URL: {t.service_url or '-'}",f"Registered Admin URL: {t.registered_admin_url or '-'}",f"Effective Admin URL: {t.effective_admin_url or '-'}",f"Connection Route: {self._route(t)}",f"Error: {t.error or '-'}"]; QMessageBox.information(self,"Target Details","\n".join(lines))
    def export_current_result(self):
        if not self.current_result: return
        path,_=QFileDialog.getSaveFileName(self,"Export Discovery","arcgis_discovery.json","JSON Files (*.json)")
        if path: export_discovery(self.current_result,path); QMessageBox.information(self,"Export selesai",f"Discovery disimpan ke:\n{path}")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__(); self.setWindowTitle("ArcGIS Enterprise Hardening Utility v2 - Milestone 2B"); self.resize(1600,850)
        self.tabs=QTabWidget(); self.discovery_widget=DiscoveryWidget(); self.catalog_widget=ControlCatalogWidget(); self.assessment_widget=AssessmentWidget(); self.evidence_widget=SemiAutomaticEvidenceWidget(); self.manual_review_widget=ManualReviewWidget(); self.reporting_widget=ReportingWidget(self.evidence_widget.workspace if hasattr(self,'evidence_widget') else None,self.manual_review_widget.workspace); self.hardening_widget=HardeningWidget(); self.discovery_widget.discovery_completed.connect(self.assessment_widget.set_connection_registry); self.discovery_widget.discovery_completed.connect(self.hardening_widget.set_connection_registry); self.assessment_widget.assessment_completed.connect(self.reporting_widget.set_assessment_results); self.assessment_widget.assessment_run_completed.connect(self.reporting_widget.set_assessment_run); self.assessment_widget.assessment_completed.connect(self.evidence_widget.set_assessment_results)
        self.tabs.addTab(self.discovery_widget,"Connection & Discovery"); self.tabs.addTab(self.catalog_widget,"Control Catalog"); self.tabs.addTab(self.assessment_widget,"Assessment"); self.tabs.addTab(self.evidence_widget,"Evidence Review"); self.tabs.addTab(self.manual_review_widget,"Manual Review"); self.tabs.addTab(self.reporting_widget,"Reporting"); self.tabs.addTab(self.hardening_widget,"Hardening Controls"); self.setCentralWidget(self.tabs)

def run_app():
    app=QApplication(sys.argv); window=MainWindow(); window.show(); sys.exit(app.exec())




