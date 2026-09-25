from datetime import datetime

from PySide6.QtCore import Signal, Qt
from ui.target_detail_table import TargetDetailTable
from ui.registered_machines import read_registered_machines
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QRadioButton,
    QSizePolicy,
    QTableWidget, QTableWidgetItem,
    QToolButton,
    QVBoxLayout,
    QWidget,
)


class V1ConnectionExperience(QWidget):
    discovery_completed = Signal(object)
    activity_message = Signal(str)

    def __init__(self, inner_widget, parent=None):
        super().__init__(parent)
        self.inner = inner_widget
        self._tables = []

        self.root = QVBoxLayout(self)
        self.root.setContentsMargins(10, 8, 10, 8)
        self.root.setSpacing(4)

        self.inner.setParent(self)
        self.inner.setVisible(True)
        self._hide_duplicate_status()
        self._replace_target_selector()
        self._disable_tls_default()
        self._compact_connection_group()
        self._extract_tables()
        self._set_inner_fixed_height()
        self.root.addWidget(self.inner, 0)

        self.actions_frame = QFrame(self)
        self.actions_frame.setObjectName("plainActions")
        self.actions_frame.setFrameShape(QFrame.Shape.NoFrame)
        self.actions_frame.setStyleSheet(
            "QFrame#plainActions { background: transparent; border: none; }"
        )
        # A fixed transparent band keeps the buttons exactly centered between
        # the Connection border and the Detail Target panel.
        self.actions_frame.setFixedHeight(58)
        self.actions_frame.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Fixed,
        )
        actions = QHBoxLayout(self.actions_frame)
        actions.setContentsMargins(0, 0, 0, 0)
        actions.setSpacing(8)
        actions.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

        connect_button = self._find_button(("connect discover", "connect & discover", "connect standalone server", "connect server"))
        export_button = self._find_button(("export discovery json",))
        if connect_button:
            self._move_button(connect_button, actions)
            connect_button.setFixedSize(190, 34)

        self.details_button = QPushButton("Tampilkan Detail Target", self.actions_frame)
        self.details_button.setCheckable(True)
        self.details_button.setFixedSize(190, 34)
        self.details_button.toggled.connect(self.toggle_target_tables)
        actions.addWidget(self.details_button)

        if export_button:
            self._move_button(export_button, actions)
            export_button.setFixedSize(190, 34)
        actions.addStretch(1)

        self.actions_row = QHBoxLayout()
        self.actions_row.setContentsMargins(12, 0, 12, 0)
        self.actions_row.setSpacing(0)
        self.actions_row.addWidget(self.actions_frame)
        self.root.addLayout(self.actions_row, 0)

        self.detail_frame = QFrame(self)
        self.detail_frame.setObjectName("card")
        detail_layout = QVBoxLayout(self.detail_frame)
        detail_layout.setContentsMargins(6, 6, 6, 6)
        detail_layout.setSpacing(4)
        self.detail_tables = []
        for table in self._tables:
            table.hide()
            detail_table = TargetDetailTable(table, self.detail_frame)
            detail_table.setSizePolicy(
                QSizePolicy.Policy.Expanding,
                QSizePolicy.Policy.Expanding,
            )
            self.detail_tables.append(detail_table)
            detail_layout.addWidget(detail_table, 1)
        self.detail_frame.hide()
        self.root.addWidget(self.detail_frame, 1)

        self.empty_spacer = QWidget(self)
        self.empty_spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.root.addWidget(self.empty_spacer, 1)

        self.summary_card = QFrame(self)
        self.summary_card.setObjectName("summaryCard")
        self.summary_card.setMaximumHeight(105)
        self.summary_card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
        summary_layout = QVBoxLayout(self.summary_card)
        summary_layout.setContentsMargins(10, 6, 10, 6)
        summary_layout.setSpacing(2)
        heading = QLabel("Connection Status", self.summary_card)
        heading.setObjectName("sectionTitle")
        self.summary = QLabel(
            "Belum terhubung. Lengkapi URL environment dan kredensial, lalu klik Connect Discover.",
            self.summary_card,
        )
        self.summary.setWordWrap(True)
        summary_layout.addWidget(heading)
        summary_layout.addWidget(self.summary)
        self.root.addWidget(self.summary_card, 0)

        self._normalize_connect_button()
        if hasattr(self.inner, "discovery_completed"):
            self.inner.discovery_completed.connect(self._on_discovery)

    def _hide_duplicate_status(self):
        for label in self.inner.findChildren(QLabel):
            value = " ".join(label.text().strip().lower().split())
            if value == "connection and target discovery":
                label.setMaximumHeight(34)
            elif value == "belum terhubung." or value.startswith("discovery selesai") or value == "ready":
                label.hide()
                label.setMaximumHeight(0)
                label.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Ignored)

    def _replace_target_selector(self):
        radios = self.inner.findChildren(QRadioButton)
        target_group = next(
            (group for group in self.inner.findChildren(QGroupBox)
             if group.title().strip().lower() == "target type"),
            None,
        )
        if len(radios) < 2 or target_group is None or target_group.layout() is None:
            return
        for radio in radios:
            radio.hide()
            radio.setMaximumHeight(0)

        selector = QFrame(target_group)
        selector.setObjectName("targetSelector")
        selector_layout = QHBoxLayout(selector)
        selector_layout.setContentsMargins(4, 4, 4, 4)
        selector_layout.setSpacing(4)
        button_group = QButtonGroup(selector)
        button_group.setExclusive(True)

        for index, radio in enumerate(radios[:2]):
            button = QToolButton(selector)
            button.setObjectName("targetChoice")
            button.setText(radio.text())
            button.setCheckable(True)
            button.setChecked(radio.isChecked())
            button.setMinimumHeight(34)
            button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            button.clicked.connect(lambda checked, source=radio: source.setChecked(checked))
            radio.toggled.connect(button.setChecked)
            button_group.addButton(button, index)
            selector_layout.addWidget(button)

        target_group.layout().addWidget(selector)
        target_group.layout().setContentsMargins(8, 6, 8, 6)
        target_group.layout().setSpacing(2)
        target_group.setFixedHeight(88)

    def _disable_tls_default(self):
        for check in self.inner.findChildren(QCheckBox):
            if any(word in check.text().lower() for word in ("tls", "ssl", "sertifikat")):
                check.setChecked(False)

    def _compact_connection_group(self):
        connection_group = next(
            (group for group in self.inner.findChildren(QGroupBox)
             if group.title().strip().lower() == "connection"),
            None,
        )
        if connection_group is None:
            return
        layout = connection_group.layout()
        if layout:
            layout.setContentsMargins(10, 8, 10, 8)
            layout.setSpacing(4)
            layout.activate()
        connection_group.setFixedHeight(178)
        connection_group.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def _extract_tables(self):
        self._tables = self.inner.findChildren(QTableWidget)
        for table in self._tables:
            parent = table.parentWidget()
            layout = parent.layout() if parent else None
            if layout:
                layout.removeWidget(table)
            table.hide()

    def _set_inner_fixed_height(self):
        self.inner.setMinimumHeight(345)
        self.inner.setMaximumHeight(345)
        self.inner.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def _configure_table(self, table):
        header = table.horizontalHeader()
        header.setMinimumSectionSize(72)
        header.setStretchLastSection(False)
        labels = {
            table.horizontalHeaderItem(i).text().strip().lower(): i
            for i in range(table.columnCount())
            if table.horizontalHeaderItem(i) is not None
        }
        fixed = {"target": 155, "component": 110, "version": 82, "state": 95, "route": 125}
        stretch = {"role / function", "service url", "registered admin url", "effective admin url", "detail"}
        for name, index in labels.items():
            if name in fixed:
                header.setSectionResizeMode(index, QHeaderView.ResizeMode.Fixed)
                table.setColumnWidth(index, fixed[name])
            elif name in stretch:
                header.setSectionResizeMode(index, QHeaderView.ResizeMode.Stretch)
            else:
                header.setSectionResizeMode(index, QHeaderView.ResizeMode.Interactive)
        table.verticalHeader().setDefaultSectionSize(31)
        table.setWordWrap(False)

    def _normalize_connect_button(self):
        button = self._find_button((
            "connect discover", "connect standalone server", "connect server",
        ))
        if button is not None:
            button.setText("Connect Discover")

    def _find_button(self, names):
        return next(
            (button for button in self.inner.findChildren(QPushButton)
             if " ".join(button.text().strip().lower().split()) in names),
            None,
        )

    def _move_button(self, button, target_layout):
        parent = button.parentWidget()
        old_layout = parent.layout() if parent else None
        if old_layout:
            old_layout.removeWidget(button)
        button.setParent(self.actions_frame)
        target_layout.addWidget(button)

    def toggle_target_tables(self, visible):
        self.detail_frame.setVisible(visible)
        self.empty_spacer.setVisible(not visible)
        self.details_button.setText("Sembunyikan Detail Target" if visible else "Tampilkan Detail Target")
        self.root.setStretchFactor(self.detail_frame, 1 if visible else 0)
        self.root.setStretchFactor(self.empty_spacer, 0 if visible else 1)
        self.updateGeometry()

    def _portal_info_endpoint(self, portal_target):
        admin_url = str(
            getattr(portal_target, "effective_admin_url", "")
            or getattr(portal_target, "registered_admin_url", "")
            or ""
        ).rstrip("/")
        if not admin_url:
            return ""
        return f"{admin_url}/info"

    def _read_portal_product_info(self, registry, portal_target):
        endpoint = self._portal_info_endpoint(portal_target)
        if not endpoint:
            return None, "Portal Admin URL tidak tersedia."

        token_store = getattr(registry, "tokens", None)
        token_record = getattr(token_store, "portal_token", None) if token_store else None
        if not token_record or not token_record.valid():
            return None, "Portal token tidak tersedia atau kedaluwarsa."

        client = getattr(registry, "client", None)
        if client is None:
            return None, "ArcGIS HTTP client tidak tersedia."

        try:
            payload = client.request_json(
                "GET",
                endpoint,
                params={"token": token_record.token, "f": "json"},
            )
        except Exception as exc:
            return None, f"Portal info gagal dibaca: {exc}"

        if not isinstance(payload, dict):
            return None, "Portal info tidak mengembalikan JSON object."

        version = (
            payload.get("fullVersion")
            or payload.get("fullversion")
            or payload.get("currentVersion")
            or payload.get("currentversion")
        )
        if not version:
            return None, "Portal info tidak memuat currentversion/fullVersion."
        return str(version).strip(), ""

    def _apply_portal_identity(self, portal_target, version):
        # Enrich the shared target object so Control Catalog and Reporting receive
        # the same corrected Portal identity.
        for attribute, value in (
            ("version", version),
            ("role", "Portal for ArcGIS"),
            ("server_role", "Portal for ArcGIS"),
        ):
            try:
                setattr(portal_target, attribute, value)
            except Exception:
                pass

        metadata = getattr(portal_target, "metadata", None)
        if isinstance(metadata, dict):
            metadata["portal_product_version"] = version
            metadata["role"] = "Portal for ArcGIS"
            metadata["portal_info_endpoint"] = self._portal_info_endpoint(portal_target)

    def _refresh_portal_table_row(self, version):
        for table in self._tables:
            headers = {}
            for column in range(table.columnCount()):
                item = table.horizontalHeaderItem(column)
                if item is not None:
                    headers[item.text().strip().lower()] = column

            component_column = headers.get("component")
            version_column = headers.get("version")
            role_column = headers.get("role / function")
            if component_column is None:
                continue

            for row in range(table.rowCount()):
                component_item = table.item(row, component_column)
                if component_item is None:
                    continue
                if component_item.text().strip().lower() != "portal":
                    continue
                if version_column is not None and table.item(row, version_column):
                    table.item(row, version_column).setText(version)
                    table.item(row, version_column).setToolTip(version)
                if role_column is not None and table.item(row, role_column):
                    table.item(row, role_column).setText("Portal for ArcGIS")
                    table.item(row, role_column).setToolTip("Portal for ArcGIS")

    def _ensure_source_metadata_columns(self):
        for table in self._tables:
            headers = [
                table.horizontalHeaderItem(i).text().strip()
                if table.horizontalHeaderItem(i) is not None else ""
                for i in range(table.columnCount())
            ]
            for name in ("Registered Machines", "Machines Endpoint", "Machines Error"):
                if name not in headers:
                    column = table.columnCount()
                    table.insertColumn(column)
                    table.setHorizontalHeaderItem(column, QTableWidgetItem(name))
                    table.setColumnHidden(column, True)
                    headers.append(name)

    def _source_headers(self, table):
        return {
            table.horizontalHeaderItem(i).text().strip(): i
            for i in range(table.columnCount())
            if table.horizontalHeaderItem(i) is not None
        }

    def _find_source_row(self, table, target):
        headers = self._source_headers(table)
        component_column = headers.get("Component")
        service_column = headers.get("Service URL")
        target_column = headers.get("Target")
        target_component = str(getattr(target, "component_type", "")).lower()
        target_service = str(getattr(target, "service_url", "")).rstrip("/").lower()
        target_name = str(getattr(target, "target_name", "")).lower()
        for row in range(table.rowCount()):
            component = (
                table.item(row, component_column).text().strip().lower()
                if component_column is not None and table.item(row, component_column)
                else ""
            )
            service = (
                table.item(row, service_column).text().strip().rstrip("/").lower()
                if service_column is not None and table.item(row, service_column)
                else ""
            )
            name = (
                table.item(row, target_column).text().strip().lower()
                if target_column is not None and table.item(row, target_column)
                else ""
            )
            if service and target_service and service == target_service:
                return row
            if component == target_component and name and target_name and name == target_name:
                return row
        return None

    def _discover_registered_machines(self, registry, targets):
        self._ensure_source_metadata_columns()
        warnings = []
        for target in targets:
            result = read_registered_machines(registry, target)
            metadata = getattr(target, "metadata", None)
            if isinstance(metadata, dict):
                metadata["registered_machines"] = list(result.names)
                metadata["machines_endpoint"] = result.endpoint
                metadata["machines_error"] = result.error
            for table in self._tables:
                row = self._find_source_row(table, target)
                if row is None:
                    continue
                headers = self._source_headers(table)
                values = {
                    "Registered Machines": result.full_text,
                    "Machines Endpoint": result.endpoint or "-",
                    "Machines Error": result.error or "-",
                }
                for name, value in values.items():
                    column = headers[name]
                    item = QTableWidgetItem(value)
                    item.setToolTip(value)
                    table.setItem(row, column, item)
            if result.error:
                warnings.append(
                    f"{getattr(target, 'target_name', 'Target')}: {result.error}"
                )
        for detail_table in getattr(self, "detail_tables", []):
            detail_table.refresh_from_source()
        return warnings

    def _on_discovery(self, registry):
        targets = registry.get_connected_targets()
        machines_warnings = self._discover_registered_machines(registry, targets)
        portals = [
            target for target in targets
            if str(target.component_type).lower() == "portal"
        ]
        servers = [
            target for target in targets
            if str(target.component_type).lower() == "server"
        ]

        portal_info_warning = ""
        if portals:
            version, portal_info_warning = self._read_portal_product_info(
                registry, portals[0]
            )
            if version:
                self._apply_portal_identity(portals[0], version)
                self._refresh_portal_table_row(version)
                for detail_table in getattr(self, 'detail_tables', []):
                    detail_table.refresh_from_source()

        token_store = getattr(registry, "tokens", None)
        portal_token = getattr(token_store, "portal_token", None) if token_store else None
        server_tokens = getattr(token_store, "server_tokens", {}) if token_store else {}
        portal_valid = bool(portal_token and portal_token.valid())
        valid_servers = sum(
            1 for token in server_tokens.values() if token and token.valid()
        )
        checked = datetime.now().strftime("%d %b %Y %H:%M:%S")
        self.summary.setText(
            f"CONNECTED   |   Environment: 1   |   Portal: {len(portals)}   |   "
            f"ArcGIS Server: {len(servers)}\n"
            f"Portal token: {'Valid' if portal_valid else 'Unavailable / expired'}   |   "
            f"Server tokens: {valid_servers}/{len(servers)} valid   |   "
            f"Last checked: {checked}"
        )

        message = (
            f"Discovery selesai. {len(targets)} target ditemukan dan siap dianalisis."
        )
        if portal_info_warning:
            message += f" Portal version fallback digunakan: {portal_info_warning}"
        if machines_warnings:
            message += " Registered Machines warning: " + " | ".join(machines_warnings)
        self.activity_message.emit(message)
        self.discovery_completed.emit(registry)
