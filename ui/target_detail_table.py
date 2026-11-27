from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QDialog, QFormLayout, QHBoxLayout, QHeaderView, QLineEdit, QPushButton,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)
try:
    from ui.neutral_table_delegate import NeutralTableDelegate
except ImportError:
    NeutralTableDelegate = None

COMPONENT_LABELS = {"portal": "Portal", "server": "ArcGIS Server"}
STATE_LABELS = {"CONNECTED": "Connected"}
ROUTE_LABELS = {
    "DIRECT_ADMIN_URL": "Direct Admin",
    "SERVICE_URL": "Service URL",
    "REGISTERED_ADMIN_URL": "Registered Admin",
}
URL_TOOLTIP = (
    "Service URL publik yang digunakan untuk mengakses komponen.\n"
    "Dapat berasal dari Web Adaptor, reverse proxy, atau load balancer."
)


def friendly(value, mapping):
    raw = str(value or "-").strip()
    return mapping.get(raw, mapping.get(raw.upper(), raw))


def role_text(target):
    roles = list(getattr(target, "roles", None) or [])
    functions = list(getattr(target, "server_functions", None) or [])
    if str(getattr(target, "component_type", "")).lower() == "portal":
        return "Portal for ArcGIS"
    values = roles + functions
    return ", ".join(str(value) for value in values if value) or "-"


def target_details(target):
    metadata = getattr(target, "metadata", None)
    metadata = metadata if isinstance(metadata, dict) else {}
    machines = metadata.get("registered_machines", [])
    if isinstance(machines, str):
        machines = [machines] if machines else []
    return {
        "Target ID": str(getattr(target, "target_id", "") or "-"),
        "Target": str(getattr(target, "target_name", "") or "-"),
        "Component": str(getattr(target, "component_type", "") or "-"),
        "Role / Function": role_text(target),
        "Deployment Mode": str(getattr(target, "deployment_mode", "") or "-"),
        "Version": str(getattr(target, "version", "") or "-"),
        "Federation State": str(getattr(target, "federation_state", "") or "-"),
        "State": str(getattr(target, "connection_state", "") or "-"),
        "Service URL": str(getattr(target, "service_url", "") or "-"),
        "Registered Admin URL": str(getattr(target, "registered_admin_url", "") or "-"),
        "Effective Admin URL": str(getattr(target, "effective_admin_url", "") or "-"),
        "Route": str(getattr(target, "connection_route", "") or "-"),
        "Server Functions": ", ".join(getattr(target, "server_functions", None) or []) or "-",
        "Registered Machines": ", ".join(str(value) for value in machines if value) or "Unavailable",
        "Machines Endpoint": str(metadata.get("machines_endpoint", "") or "-"),
        "Machines Error": str(metadata.get("machines_error", "") or "-"),
        "Detail": str(metadata.get("detail", "") or "-"),
        "Error": str(getattr(target, "error", "") or "-"),
    }


class TargetDetailsDialog(QDialog):
    def __init__(self, details, parent=None):
        super().__init__(parent)
        self.details = details
        self.setWindowTitle("Detail Target")
        self.resize(880, 590)
        root = QVBoxLayout(self)
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop)
        form.setFormAlignment(Qt.AlignmentFlag.AlignTop)
        form.setHorizontalSpacing(18)
        form.setVerticalSpacing(8)
        fields = [
            ("Target ID", "Target ID"), ("Target Name", "Target"),
            ("Komponen", "Component"), ("Versi", "Version"),
            ("Role / Function", "Role / Function"),
            ("Registered Machines", "Registered Machines"),
            ("Machines Endpoint", "Machines Endpoint"),
            ("Machines Error", "Machines Error"),
            ("Deployment Mode", "Deployment Mode"),
            ("Federation State", "Federation State"), ("Status", "State"),
            ("URL Akses / Web Adaptor", "Service URL"),
            ("Registered Admin URL", "Registered Admin URL"),
            ("Effective Admin URL", "Effective Admin URL"),
            ("Route", "Route"), ("Server Functions", "Server Functions"),
            ("Detail Teknis", "Detail"), ("Error", "Error"),
        ]
        for label, key in fields:
            value = details.get(key, "-") or "-"
            if key == "Component": value = friendly(value, COMPONENT_LABELS)
            elif key == "State": value = friendly(value, STATE_LABELS)
            elif key == "Route": value = friendly(value, ROUTE_LABELS)
            editor = QLineEdit(str(value)); editor.setReadOnly(True)
            editor.setMinimumHeight(29); editor.setCursorPosition(0)
            if "URL" in label or "Endpoint" in label: editor.setToolTip(str(value))
            form.addRow(f"{label} :", editor)
        root.addLayout(form, 1)
        actions = QHBoxLayout(); actions.addStretch()
        copy_details = QPushButton("Copy Details")
        copy_url = QPushButton("Copy URL")
        close = QPushButton("Close")
        copy_details.clicked.connect(self.copy_details)
        copy_url.clicked.connect(self.copy_url); close.clicked.connect(self.accept)
        actions.addWidget(copy_details); actions.addWidget(copy_url); actions.addWidget(close)
        root.addLayout(actions)

    def copy_details(self):
        QGuiApplication.clipboard().setText("\n".join(f"{k}: {v or '-'}" for k, v in self.details.items()))

    def copy_url(self):
        QGuiApplication.clipboard().setText(str(self.details.get("Service URL", "") or ""))


class TargetDetailTable(QTableWidget):
    HEADERS = [
        "URL Akses / Web Adaptor", "Komponen", "Versi", "Role / Function",
        "Registered Machines", "Status", "Route", "Action",
    ]

    def __init__(self, source_table=None, parent=None):
        super().__init__(0, len(self.HEADERS), parent)
        self.source_table = source_table
        self.rows_data = []
        self.setHorizontalHeaderLabels(self.HEADERS)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.setMouseTracking(False); self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        if NeutralTableDelegate is not None:
            self.setItemDelegate(NeutralTableDelegate(self))
        self.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.setWordWrap(False); self.verticalHeader().setDefaultSectionSize(34)
        self.horizontalHeaderItem(0).setToolTip(URL_TOOLTIP)
        header = self.horizontalHeader(); header.setMinimumSectionSize(68)
        for column in (0, 3, 4): header.setSectionResizeMode(column, QHeaderView.ResizeMode.Stretch)
        for column in (1, 2, 5, 6, 7): header.setSectionResizeMode(column, QHeaderView.ResizeMode.Fixed)
        for column, width in {1:125, 2:85, 5:105, 6:135, 7:68}.items(): self.setColumnWidth(column, width)
        self.setStyleSheet("""
            QTableWidget { outline:none; }
            QTableWidget::item:hover, QTableWidget::item:selected,
            QTableWidget::item:selected:active, QTableWidget::item:selected:!active {
                background:transparent; border:none; outline:none;
            }
        """)
        if source_table is not None: self.refresh_from_source()

    def bind_targets(self, targets):
        self.rows_data = [target_details(target) for target in targets]
        self.render_rows()

    def refresh_from_source(self):
        if self.source_table is None: return
        headers = {self.source_table.horizontalHeaderItem(i).text().strip(): i for i in range(self.source_table.columnCount()) if self.source_table.horizontalHeaderItem(i)}
        rows = []
        for row in range(self.source_table.rowCount()):
            details = {}
            for name, column in headers.items():
                item = self.source_table.item(row, column)
                details[name] = item.text().strip() if item and item.text().strip() else "-"
            rows.append(details)
        self.rows_data = rows; self.render_rows()

    def render_rows(self):
        self.setRowCount(len(self.rows_data))
        for row, details in enumerate(self.rows_data):
            values = [
                details.get("Service URL", "-"), friendly(details.get("Component"), COMPONENT_LABELS),
                details.get("Version", "-"), details.get("Role / Function", "-"),
                details.get("Registered Machines", "-"), friendly(details.get("State"), STATE_LABELS),
                friendly(details.get("Route"), ROUTE_LABELS),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value)); item.setToolTip(URL_TOOLTIP if column == 0 else str(value))
                self.setItem(row, column, item)
            button = QPushButton("Detail"); button.setFixedSize(54, 23)
            button.clicked.connect(lambda _checked=False, current=row: self.show_details(current))
            container = QWidget(); layout = QHBoxLayout(container)
            layout.setContentsMargins(2,1,2,1); layout.setAlignment(Qt.AlignmentFlag.AlignCenter); layout.addWidget(button)
            self.setCellWidget(row, 7, container)

    def show_details(self, row):
        if 0 <= row < len(self.rows_data): TargetDetailsDialog(self.rows_data[row], self).exec()
