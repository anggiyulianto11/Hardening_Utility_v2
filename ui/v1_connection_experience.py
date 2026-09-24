from datetime import datetime

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QCheckBox, QFrame, QHBoxLayout, QLabel, QPushButton,
    QSizePolicy, QTableWidget, QVBoxLayout, QWidget,
)


class V1ConnectionExperience(QWidget):
    discovery_completed = Signal(object)
    activity_message = Signal(str)

    def __init__(self, inner_widget, parent=None):
        super().__init__(parent)
        self.inner = inner_widget
        self._tables = []

        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        # Keep the original connection form visible at the top. This contains
        # Portal URL, username, password, mode, TLS checkbox, and Connect button.
        self.inner.setParent(self)
        self.inner.setVisible(True)
        self.inner.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        root.addWidget(self.inner, 1)

        self.summary_card = QFrame()
        self.summary_card.setObjectName("summaryCard")
        self.summary_card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
        self.summary_card.setMaximumHeight(180)
        summary_layout = QVBoxLayout(self.summary_card)
        summary_layout.setContentsMargins(12, 8, 12, 8)
        summary_layout.setSpacing(4)
        heading = QLabel("Connection Status")
        heading.setObjectName("sectionTitle")
        self.summary = QLabel("Belum terhubung. Lengkapi URL environment dan kredensial, lalu klik Connect & Discover.")
        self.summary.setWordWrap(True)
        summary_layout.addWidget(heading)
        summary_layout.addWidget(self.summary)
        root.addWidget(self.summary_card)

        footer = QFrame()
        footer.setObjectName("activityCard")
        footer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
        footer.setMaximumHeight(92)
        footer_layout = QVBoxLayout(footer)
        footer_layout.setContentsMargins(10, 7, 10, 7)
        footer_layout.setSpacing(4)
        actions = QHBoxLayout()
        self.details_button = QPushButton("Tampilkan Detail Target")
        self.details_button.setCheckable(True)
        self.details_button.toggled.connect(self.toggle_target_tables)
        actions.addWidget(self.details_button)
        actions.addStretch()
        footer_layout.addLayout(actions)
        self.activity = QLabel("Activity: Ready")
        self.activity.setWordWrap(True)
        footer_layout.addWidget(self.activity)
        root.addWidget(footer)

        # Security choice requested by the project: verification is opt-in.
        for check in self.inner.findChildren(QCheckBox):
            text = check.text().lower()
            if "tls" in text or "ssl" in text or "sertifikat" in text:
                check.setChecked(False)

        # Hide only discovery result tables. Input fields and connection form remain visible.
        self._tables = self.inner.findChildren(QTableWidget)
        for table in self._tables:
            table.setVisible(False)

        if hasattr(self.inner, "discovery_completed"):
            self.inner.discovery_completed.connect(self._on_discovery)

    def toggle_target_tables(self, visible):
        for table in self._tables:
            table.setVisible(visible)
        self.details_button.setText(
            "Sembunyikan Detail Target" if visible else "Tampilkan Detail Target"
        )

    def _on_discovery(self, registry):
        targets = registry.get_connected_targets()
        portals = [t for t in targets if str(t.component_type).lower() == "portal"]
        servers = [t for t in targets if str(t.component_type).lower() == "server"]
        token_store = getattr(registry, "tokens", None)
        portal_token = getattr(token_store, "portal_token", None) if token_store else None
        server_tokens = getattr(token_store, "server_tokens", {}) if token_store else {}
        portal_valid = bool(portal_token and portal_token.valid())
        valid_servers = sum(1 for item in server_tokens.values() if item and item.valid())
        checked = datetime.now().strftime("%d %b %Y %H:%M:%S")

        self.summary.setText(
            f"â— CONNECTED   |   Environment: 1   |   Portal: {len(portals)}   |   "
            f"ArcGIS Server: {len(servers)}\n"
            f"Portal token: {'Valid' if portal_valid else 'Unavailable / expired'}   |   "
            f"Server tokens: {valid_servers}/{len(servers)} valid   |   Last checked: {checked}"
        )
        self.activity.setText(
            f"Activity: Discovery selesai. {len(targets)} target ditemukan dan siap dianalisis."
        )
        self.activity_message.emit(self.activity.text())
        self.discovery_completed.emit(registry)
