from PySide6.QtWidgets import QWidget,QVBoxLayout,QHBoxLayout,QLineEdit,QComboBox,QLabel,QTableWidget,QTableWidgetItem
from controls.registry import ControlRegistry
class ControlCatalogWidget(QWidget):
    HEADERS=["No.","Control ID","Profile","Area","Control Name","Method","Esri / 3rd Party","Security Risk","Privacy Risk","Changeable","Analyzer Status"]
    def __init__(self,parent=None):
        super().__init__(parent); self.registry=ControlRegistry(); root=QVBoxLayout(self); box=QHBoxLayout(); self.search=QLineEdit(); self.search.setPlaceholderText("Cari ID atau nama kontrol...")
        self.profile=QComboBox(); self.profile.addItems(["Semua","Basic","Advanced"]); self.area=QComboBox(); self.area.addItems(["Semua"]+sorted({c.area for c in self.registry.get_all_controls()})); self.method=QComboBox(); self.method.addItems(["Semua"]+sorted({c.verification_method for c in self.registry.get_all_controls()})); self.risk=QComboBox(); self.risk.addItems(["Semua"]+sorted({c.security_risk for c in self.registry.get_all_controls()})); self.side=QComboBox(); self.side.addItems(["Semua"]+sorted({c.implementation_side for c in self.registry.get_all_controls()}))
        for label,w in (("Search",self.search),("Profile",self.profile),("Area",self.area),("Method",self.method),("Risk",self.risk),("Side",self.side)): box.addWidget(QLabel(label)); box.addWidget(w)
        root.addLayout(box); self.summary=QLabel(); root.addWidget(self.summary); self.table=QTableWidget(0,len(self.HEADERS)); self.table.setHorizontalHeaderLabels(self.HEADERS); root.addWidget(self.table)
        self.search.textChanged.connect(self.refresh)
        for w in (self.profile,self.area,self.method,self.risk,self.side): w.currentTextChanged.connect(self.refresh)
        self.refresh()
    def refresh(self,*_):
        items=self.registry.filter(self.profile.currentText(),self.area.currentText(),self.method.currentText(),self.risk.currentText(),self.side.currentText(),self.search.text()); self.table.setRowCount(len(items))
        for r,c in enumerate(items):
            vals=[c.sequence,c.control_id,c.profile,c.area,c.control_name,c.verification_method,c.implementation_side,c.security_risk,c.privacy_risk,"Yes" if c.changeable else "No","Planned"]
            for col,v in enumerate(vals): self.table.setItem(r,col,QTableWidgetItem(str(v)))
        self.summary.setText(f"Menampilkan {len(items)} dari {self.registry.metadata['control_count']} kontrol | Basic {self.registry.metadata['basic_count']} | Advanced {self.registry.metadata['advanced_count']}")
        self.table.resizeColumnsToContents()
