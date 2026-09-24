from PySide6.QtWidgets import QComboBox, QHBoxLayout, QLabel, QMainWindow, QTabWidget, QVBoxLayout, QWidget

from ui.unified_main_window import UnifiedMainWindow
from ui.v1_connection_experience import V1ConnectionExperience
from ui.v1_theme import V1ThemeManager


class V1StyledUnifiedMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ArcGIS Enterprise Hardening Utility")
        self.resize(1680, 940)
        self.setMinimumSize(1100, 720)
        self.theme_manager = V1ThemeManager()

        base = UnifiedMainWindow()
        old_tabs = base.tabs
        discovery = old_tabs.widget(0)
        catalog = old_tabs.widget(1)
        reporting = old_tabs.widget(2)
        log_widget = old_tabs.widget(3)
        discovery.setParent(None); catalog.setParent(None); reporting.setParent(None); log_widget.setParent(None)
        base.deleteLater()

        central = QWidget(); self.setCentralWidget(central)
        root = QVBoxLayout(central); root.setContentsMargins(20, 18, 20, 10); root.setSpacing(8)
        header = QHBoxLayout()
        titles = QVBoxLayout(); titles.setSpacing(3)
        title = QLabel("ArcGIS Enterprise Hardening Utility"); title.setObjectName("appTitle")
        subtitle = QLabel("Connection, assessment, review, dan live hardening untuk ArcGIS Enterprise."); subtitle.setObjectName("appSubtitle")
        titles.addWidget(title); titles.addWidget(subtitle); header.addLayout(titles, 1)
        header.addWidget(QLabel("Theme:"))
        self.theme_combo = QComboBox(); self.theme_combo.addItems(V1ThemeManager.THEMES)
        self.theme_combo.setCurrentText(self.theme_manager.preference); self.theme_combo.setFixedWidth(150)
        self.theme_combo.currentTextChanged.connect(self.theme_manager.apply)
        header.addWidget(self.theme_combo)
        root.addLayout(header)

        self.tabs = QTabWidget(); root.addWidget(self.tabs, 1)
        self.connection = V1ConnectionExperience(discovery)
        self.tabs.addTab(self.connection, "1. Connection & Discovery")
        self.tabs.addTab(catalog, "2. Control Catalog")
        self.tabs.addTab(reporting, "3. Reporting")
        self.tabs.addTab(log_widget, "4. Execution Log")
        self.connection.discovery_completed.connect(catalog.set_connection_registry)
        self.connection.activity_message.connect(log_widget.append)
        catalog.assessment_completed.connect(reporting.set_assessment_results)
        catalog.assessment_run_completed.connect(reporting.set_assessment_run)
        catalog.log_message.connect(log_widget.append)

        self.theme_manager.apply(self.theme_manager.preference)
