from PySide6.QtWidgets import QMainWindow, QTabWidget

from ui.main_window import DiscoveryWidget
from ui.unified_control_workspace import UnifiedControlWorkspace
from ui.reporting_widget import ReportingWidget
from ui.execution_log_widget import ExecutionLogWidget


class UnifiedMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ArcGIS Enterprise Hardening Utility v2")
        self.resize(1680, 940)

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.discovery_widget = DiscoveryWidget()
        self.control_workspace = UnifiedControlWorkspace()
        self.reporting_widget = ReportingWidget(
            self.control_workspace.semi_workspace,
            self.control_workspace.manual_workspace,
        )
        self.log_widget = ExecutionLogWidget()

        self.tabs.addTab(self.discovery_widget, "1. Connection & Discovery")
        self.tabs.addTab(self.control_workspace, "2. Control Catalog")
        self.tabs.addTab(self.reporting_widget, "3. Reporting")
        self.tabs.addTab(self.log_widget, "4. Execution Log")

        self.discovery_widget.discovery_completed.connect(
            self.control_workspace.set_connection_registry
        )
        self.control_workspace.assessment_completed.connect(
            self.reporting_widget.set_assessment_results
        )
        self.control_workspace.assessment_run_completed.connect(
            self.reporting_widget.set_assessment_run
        )
        self.control_workspace.log_message.connect(self.log_widget.append)
