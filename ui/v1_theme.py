from PySide6.QtCore import QSettings
from PySide6.QtGui import QPalette
from PySide6.QtWidgets import QApplication


class V1ThemeManager:
    THEMES = ("System", "Dark", "Light")

    def __init__(self):
        self.settings = QSettings("itspamud", "ArcGIS Enterprise Hardening Utility")
        self.preference = self.settings.value("appearance/theme", "System", type=str)
        if self.preference not in self.THEMES:
            self.preference = "System"

    def effective(self, preference=None):
        preference = preference or self.preference
        if preference != "System":
            return preference
        color = QApplication.instance().palette().color(QPalette.ColorRole.Window)
        return "Dark" if color.lightness() < 128 else "Light"

    def apply(self, preference):
        if preference not in self.THEMES:
            preference = "System"
        self.preference = preference
        self.settings.setValue("appearance/theme", preference)
        self.settings.sync()
        app = QApplication.instance()
        if app:
            app.setStyleSheet(self.dark_css() if self.effective(preference) == "Dark" else self.light_css())

    @staticmethod
    def common_css():
        return """
        * { font-family:'Segoe UI'; font-size:12px; }
        QLabel#appTitle { font-size:24px; font-weight:700; }
        QLabel#appSubtitle { font-size:13px; }
        QLabel#sectionTitle { font-size:16px; font-weight:700; }
        QFrame#card, QFrame#summaryCard, QFrame#activityCard { border-radius:7px; }
        QLineEdit, QComboBox { min-height:27px; max-height:31px; padding:3px 7px; border-radius:4px; }
        QPushButton { min-height:27px; padding:3px 12px; border-radius:4px; font-weight:600; }
        QPushButton#primaryButton { color:white; border:none; }
        QTabBar::tab { min-height:25px; padding:6px 14px; }
        QTreeWidget, QTableWidget { border-radius:0; }
        QHeaderView::section { min-height:31px; padding:5px 7px; font-weight:700; }
        QTreeWidget::item { min-height:34px; padding:2px; }
        QPlainTextEdit, QTextEdit { padding:6px; border-radius:4px; }
        QCheckBox { min-height:21px; }
        QToolTip { padding:4px; }
        """

    @classmethod
    def light_css(cls):
        return cls.common_css() + """
        QMainWindow, QWidget { background:#f5f7fa; color:#111111; }
        QLabel#appSubtitle, QLabel#mutedLabel { color:#4b5563; }
        QFrame#card, QFrame#summaryCard, QFrame#activityCard { background:#ffffff; border:1px solid #cbd2d9; }
        QLineEdit, QComboBox, QPlainTextEdit, QTextEdit { background:#ffffff; color:#111111; border:1px solid #aeb8c2; }
        QLineEdit:focus, QComboBox:focus { border:1px solid #0078d4; }
        QPushButton { background:#ffffff; color:#111111; border:1px solid #aeb8c2; }
        QPushButton:hover { background:#eef4fb; }
        QPushButton#primaryButton { background:#0078d4; }
        QPushButton:disabled { color:#8b949e; background:#edf0f3; border-color:#d5dbe1; }
        QTabWidget::pane { background:#ffffff; border:1px solid #cbd2d9; }
        QTabBar::tab { background:#e9eef5; color:#111111; border:1px solid #cbd2d9; }
        QTabBar::tab:selected { background:#0078d4; color:white; }
        QTreeWidget, QTableWidget { background:#ffffff; alternate-background-color:#f7f9fb; color:#111111; border:1px solid #cbd2d9; gridline-color:#cbd2d9; }
        QHeaderView::section { background:#e9eef5; color:#111111; border:1px solid #cbd2d9; }
        QScrollBar:vertical, QScrollBar:horizontal { background:#eef1f4; }
        QScrollBar::handle:vertical, QScrollBar::handle:horizontal { background:#aab4be; min-width:18px; min-height:18px; }
        QToolTip { background:#fffbe6; color:#111111; border:1px solid #b8a75b; }
        """

    @classmethod
    def dark_css(cls):
        return cls.common_css() + """
        QMainWindow, QWidget { background:#1e1e1e; color:#f2f2f2; }
        QLabel#appSubtitle, QLabel#mutedLabel { color:#b8b8b8; }
        QFrame#card, QFrame#summaryCard, QFrame#activityCard { background:#292929; border:1px solid #414141; }
        QLineEdit, QComboBox, QPlainTextEdit, QTextEdit { background:#181818; color:#f2f2f2; border:1px solid #505050; }
        QPushButton { background:#333333; color:#f2f2f2; border:1px solid #565656; }
        QPushButton:hover { background:#414141; }
        QPushButton#primaryButton { background:#0078d4; }
        QPushButton:disabled { color:#777777; background:#303030; border-color:#444444; }
        QTabWidget::pane { background:#1e1e1e; border:1px solid #414141; }
        QTabBar::tab { background:#292929; color:#f2f2f2; border:1px solid #414141; }
        QTabBar::tab:selected { background:#0078d4; color:white; }
        QTreeWidget, QTableWidget { background:#202020; alternate-background-color:#242424; color:#f2f2f2; border:1px solid #444444; gridline-color:#444444; }
        QHeaderView::section { background:#303030; color:#f2f2f2; border:1px solid #444444; }
        QScrollBar:vertical, QScrollBar:horizontal { background:#222222; }
        QScrollBar::handle:vertical, QScrollBar::handle:horizontal { background:#666666; min-width:18px; min-height:18px; }
        QToolTip { background:#303030; color:#ffffff; border:1px solid #666666; }
        """
