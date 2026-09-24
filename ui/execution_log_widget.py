from datetime import datetime
from PySide6.QtWidgets import QHBoxLayout, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget


class ExecutionLogWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setPlaceholderText("Aktivitas connection, assessment, preview, apply, verify, dan rollback akan tampil di sini.")
        layout.addWidget(self.output)
        actions = QHBoxLayout()
        clear = QPushButton("Bersihkan Log")
        clear.clicked.connect(self.output.clear)
        actions.addStretch()
        actions.addWidget(clear)
        layout.addLayout(actions)

    def append(self, message):
        self.output.appendPlainText(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
