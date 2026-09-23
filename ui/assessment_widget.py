import json
from PySide6.QtCore import QObject,QThread,Signal
from PySide6.QtWidgets import QComboBox,QHBoxLayout,QLabel,QMessageBox,QPushButton,QTableWidget,QTableWidgetItem,QVBoxLayout,QWidget
from analysis.orchestrator import AssessmentOrchestrator
from controls.registry import ControlRegistry
class AssessmentWorker(QObject):
    completed=Signal(object,object,int); failed=Signal(str)
    def __init__(self,registry): super().__init__(); self.registry=registry
    def run(self):
        try: run,results,count=AssessmentOrchestrator(self.registry,ControlRegistry()).analyze(); self.completed.emit(run,results,count)
        except Exception as exc: self.failed.emit(str(exc))
class AssessmentWidget(QWidget):
    assessment_completed = Signal(object)
    HEADERS=["Target","Component","Control ID","Profile","Control Name","Current Condition","Expected Condition","Status","Security Risk","Recommendation","Evidence","Error"]
    def __init__(self,parent=None):
        super().__init__(parent); self.connection_registry=None; self.thread=None; self.worker=None; self.results=[]
        layout=QVBoxLayout(self); title=QLabel("Assessment Engine - Server Batch 1 + Portal Batch 2"); title.setStyleSheet("font-size: 22px; font-weight: 700;"); layout.addWidget(title); layout.addWidget(QLabel("Read-only analyzers: 6 Server controls and 11 Portal configuration controls."))
        bar=QHBoxLayout(); self.button=QPushButton("Analyze Connected Environment"); self.button.setEnabled(False); self.button.clicked.connect(self.analyze); self.status=QComboBox(); self.status.addItems(["Semua","SESUAI","TIDAK SESUAI","PERINGATAN","PERLU TINJAUAN","TIDAK DAPAT DINILAI","ERROR"]); self.status.currentTextChanged.connect(self.refresh); self.component=QComboBox(); self.component.addItems(["Semua","portal","server"]); self.component.currentTextChanged.connect(self.refresh); self.profile=QComboBox(); self.profile.addItems(["Semua","Basic","Advanced"]); self.profile.currentTextChanged.connect(self.refresh); bar.addWidget(self.button); bar.addWidget(QLabel("Component")); bar.addWidget(self.component); bar.addWidget(QLabel("Status")); bar.addWidget(self.status); bar.addWidget(QLabel("Profile")); bar.addWidget(self.profile); bar.addStretch(); layout.addLayout(bar)
        self.summary=QLabel("Lakukan discovery terlebih dahulu."); layout.addWidget(self.summary); self.table=QTableWidget(0,len(self.HEADERS)); self.table.setHorizontalHeaderLabels(self.HEADERS); self.table.setAlternatingRowColors(True); layout.addWidget(self.table)
    def set_connection_registry(self,registry): self.connection_registry=registry; self.button.setEnabled(bool(registry.get_connected_targets())); self.summary.setText("Environment siap dianalisis dengan 17 kontrol read-only.")
    def analyze(self):
        if not self.connection_registry: QMessageBox.warning(self,"Assessment","Lakukan discovery terlebih dahulu."); return
        self.button.setEnabled(False); self.summary.setText("Menjalankan server Batch 1 dan portal Batch 2..."); self.thread=QThread(self); self.worker=AssessmentWorker(self.connection_registry); self.worker.moveToThread(self.thread); self.thread.started.connect(self.worker.run); self.worker.completed.connect(self.on_completed); self.worker.failed.connect(self.on_failed); self.worker.completed.connect(self.thread.quit); self.worker.failed.connect(self.thread.quit); self.thread.finished.connect(self.worker.deleteLater); self.thread.finished.connect(self.thread.deleteLater); self.thread.start()
    def on_completed(self,run,results,count): self.button.setEnabled(True); self.results=results; self.refresh(); self.assessment_completed.emit(results); self.summary.setText(f"Run {run.run_id[:8]} selesai: {run.result_count} hasil, {run.error_count} error, {count} API evidence requests.")
    def refresh(self,*_):
        s=self.status.currentText(); c=self.component.currentText(); p=self.profile.currentText(); items=[r for r in self.results if (s=="Semua" or r.status.value==s) and (c=="Semua" or r.component_type==c) and (p=="Semua" or r.profile==p)]; self.table.setRowCount(len(items))
        for row,r in enumerate(items):
            vals=[r.target_name,r.component_type,r.control_id,r.profile,r.control_name,r.current_condition or "-",r.expected_condition or "-",r.status.value,r.security_risk,r.recommendation or "-",json.dumps(r.evidence,ensure_ascii=False),r.error or "-"]
            for col,v in enumerate(vals): item=QTableWidgetItem(str(v)); item.setToolTip(str(v)); self.table.setItem(row,col,item)
        self.table.resizeColumnsToContents()
    def on_failed(self,message): self.button.setEnabled(True); self.summary.setText("Assessment gagal."); QMessageBox.critical(self,"Assessment gagal",message)



