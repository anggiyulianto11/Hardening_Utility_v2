import sys

from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication
from ui.v1_styled_main_window import V1StyledUnifiedMainWindow

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("ArcGIS Enterprise Hardening Utility")
    app.setOrganizationName("ArcGIS Enterprise Hardening Utility")
    app.setFont(QFont("Segoe UI", 10))
    window = V1StyledUnifiedMainWindow()
    window.show()
    return app.exec()

if __name__ == "__main__":
    raise SystemExit(main())
