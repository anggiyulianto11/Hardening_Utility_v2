from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from ui.neutral_table_delegate import NeutralTableDelegate
from PySide6.QtWidgets import (
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

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


class TargetDetailsDialog(QDialog):
    def __init__(self, details, parent=None):
        super().__init__(parent)
        self.details = details
        self.setWindowTitle("Detail Target")
        self.resize(860, 520)

        root = QVBoxLayout(self)
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop)
        form.setFormAlignment(Qt.AlignmentFlag.AlignTop)
        form.setHorizontalSpacing(18)
        form.setVerticalSpacing(8)

        fields = [
            ("Target ID", "Target ID"),
            ("Target Name", "Target"),
            ("Komponen", "Component"),
            ("Role / Function", "Role / Function"),
            ("Registered Machines", "Registered Machines"),
            ("Machines Endpoint", "Machines Endpoint"),
            ("Deployment Mode", "Deployment Mode"),
            ("Versi", "Version"),
            ("Federation State", "Federation State"),
            ("Status", "State"),
            ("URL Akses / Web Adaptor", "Service URL"),
            ("Registered Admin URL", "Registered Admin URL"),
            ("Effective Admin URL", "Effective Admin URL"),
            ("Route", "Route"),
            ("Server Functions", "Server Functions"),
            ("Detail Teknis", "Detail"),
            ("Error", "Error"),
        ]
        for label, key in fields:
            value = details.get(key, "-") or "-"
            if key == "Component":
                value = friendly(value, COMPONENT_LABELS)
            elif key == "State":
                value = friendly(value, STATE_LABELS)
            elif key == "Route":
                value = friendly(value, ROUTE_LABELS)
            editor = QLineEdit(str(value))
            editor.setReadOnly(True)
            editor.setMinimumHeight(29)
            editor.setCursorPosition(0)
            if "URL" in label:
                editor.setToolTip(str(value))
            form.addRow(f"{label} :", editor)
        root.addLayout(form, 1)

        actions = QHBoxLayout()
        copy_details = QPushButton("Copy Details")
        copy_url = QPushButton("Copy URL")
        close = QPushButton("Close")
        copy_details.clicked.connect(self.copy_details)
        copy_url.clicked.connect(self.copy_url)
        close.clicked.connect(self.accept)
        actions.addStretch()
        actions.addWidget(copy_details)
        actions.addWidget(copy_url)
        actions.addWidget(close)
        root.addLayout(actions)

    def copy_details(self):
        text = "\n".join(
            f"{key}: {value or '-'}" for key, value in self.details.items()
        )
        QGuiApplication.clipboard().setText(text)

    def copy_url(self):
        QGuiApplication.clipboard().setText(
            str(self.details.get("Service URL", "") or "")
        )


class TargetDetailTable(QTableWidget):
    HEADERS = [
        "URL Akses / Web Adaptor",
        "Komponen",
        "Versi",
        "Role / Function",
        "Registered Machines",
        "Status",
        "Route",
        "Action",
    ]

    def __init__(self, source_table, parent=None):
        super().__init__(0, len(self.HEADERS), parent)
        self.source_table = source_table
        self.rows_data = []
        self.setHorizontalHeaderLabels(self.HEADERS)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.setMouseTracking(False)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.setItemDelegate(NeutralTableDelegate(self))
        self.setStyleSheet("""
            QTableWidget { outline: none; }
            QTableWidget::item:hover,
            QTableWidget::item:selected,
            QTableWidget::item:selected:active,
            QTableWidget::item:selected:!active {
                background: transparent;
                border: none;
                outline: none;
            }
        """)
        self.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.setWordWrap(False)
        self.verticalHeader().setDefaultSectionSize(34)
        self.horizontalHeaderItem(0).setToolTip(URL_TOOLTIP)
        header = self.horizontalHeader()
        header.setMinimumSectionSize(68)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.Fixed)
        self.setColumnWidth(1, 125)
        self.setColumnWidth(2, 85)
        self.setColumnWidth(5, 105)
        self.setColumnWidth(6, 135)
        self.setColumnWidth(7, 68)
        self.refresh_from_source()

    def _source_headers(self):
        return {
            self.source_table.horizontalHeaderItem(i).text().strip(): i
            for i in range(self.source_table.columnCount())
            if self.source_table.horizontalHeaderItem(i) is not None
        }

    def _cell(self, row, headers, name):
        index = headers.get(name)
        if index is None:
            return "-"
        item = self.source_table.item(row, index)
        return item.text().strip() if item and item.text().strip() else "-"

    def refresh_from_source(self):
        headers = self._source_headers()
        self.rows_data = []
        self.setRowCount(self.source_table.rowCount())

        for row in range(self.source_table.rowCount()):
            details = {name: self._cell(row, headers, name) for name in headers}
            details.setdefault("Target ID", "-")
            details.setdefault("Deployment Mode", "-")
            details.setdefault("Federation State", details.get("Component", "-"))
            details.setdefault("Server Functions", "-")
            details.setdefault("Error", "-")
            self.rows_data.append(details)

            values = [
                details.get("Service URL", "-"),
                friendly(details.get("Component"), COMPONENT_LABELS),
                details.get("Version", "-"),
                details.get("Role / Function", "-"),
                details.get("Registered Machines", "-"),
                friendly(details.get("State"), STATE_LABELS),
                friendly(details.get("Route"), ROUTE_LABELS),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if column == 0:
                    item.setToolTip(URL_TOOLTIP)
                elif column == 4:
                    item.setToolTip(details.get("Registered Machines", "-") or "-")
                else:
                    item.setToolTip(str(value))
                self.setItem(row, column, item)

            button = QPushButton("Detail")
            button.setObjectName("compactActionButton")
            button.setFixedSize(54, 23)
            button.setStyleSheet(
                "QPushButton#compactActionButton {"
                " min-height: 21px; max-height: 23px;"
                " padding: 0px 6px; font-size: 11px; font-weight: 600;"
                " border-radius: 4px;"
                "}"
            )
            button.clicked.connect(
                lambda _checked=False, current_row=row: self.show_details(current_row)
            )
            container = QWidget()
            layout = QHBoxLayout(container)
            layout.setContentsMargins(2, 1, 2, 1)
            layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(button)
            self.setCellWidget(row, 7, container)

    def show_details(self, row):
        if 0 <= row < len(self.rows_data):
            TargetDetailsDialog(self.rows_data[row], self).exec()
