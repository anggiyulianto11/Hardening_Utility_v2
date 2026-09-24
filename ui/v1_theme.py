from PySide6.QtCore import QSettings
from PySide6.QtGui import QPalette
from PySide6.QtWidgets import QApplication
class V1ThemeManager:
    THEMES=("System","Dark","Light")
    def __init__(self):
        self.settings=QSettings("itspamud","ArcGIS Enterprise Hardening Utility"); self.preference=self.settings.value("appearance/theme","System",type=str)
        if self.preference not in self.THEMES: self.preference="System"
    def effective(self,preference=None):
        preference=preference or self.preference
        if preference!="System": return preference
        app=QApplication.instance(); return "Dark" if app and app.palette().color(QPalette.ColorRole.Window).lightness()<128 else "Light"
    def apply(self,preference):
        if preference not in self.THEMES: preference="System"
        self.preference=preference; self.settings.setValue("appearance/theme",preference); self.settings.sync(); app=QApplication.instance()
        if app: app.setStyleSheet(self.dark_css() if self.effective(preference)=="Dark" else self.light_css())
    @staticmethod
    def common_css():
        return """*{font-family:'Segoe UI';font-size:12px;} QLabel#appTitle{font-size:24px;font-weight:700;} QLabel#appSubtitle{font-size:13px;} QLabel#sectionTitle{font-size:14px;font-weight:700;} QFrame#card,QFrame#summaryCard,QFrame#targetSelector{border-radius:6px;} QLineEdit,QComboBox{min-height:27px;max-height:31px;padding:3px 7px;border-radius:4px;} QPushButton{min-height:27px;padding:3px 12px;border-radius:4px;font-weight:600;} QToolButton#targetChoice{min-height:30px;padding:3px 12px;border-radius:4px;font-weight:500;} QToolButton#targetChoice:checked{font-weight:700;} QTabBar::tab{min-height:25px;padding:6px 14px;} QHeaderView::section{min-height:31px;padding:5px 7px;font-weight:700;} QTreeWidget::item{min-height:34px;padding:2px;} QStatusBar{min-height:24px;padding-left:8px;}"""
    @classmethod
    def light_css(cls):
        return cls.common_css()+"""QMainWindow,QWidget{background:#f5f7fa;color:#111;} QLabel#appSubtitle{color:#4b5563;} QFrame#card,QFrame#summaryCard{background:#fff;border:1px solid #cbd2d9;} QFrame#targetSelector{background:#eef2f6;border:1px solid #cbd2d9;} QLineEdit,QComboBox,QPlainTextEdit,QTextEdit{background:#fff;color:#111;border:1px solid #aeb8c2;} QPushButton{background:#fff;color:#111;border:1px solid #aeb8c2;} QPushButton:hover{background:#eef4fb;} QPushButton:disabled{color:#8b949e;background:#edf0f3;border-color:#d5dbe1;} QToolButton#targetChoice{background:transparent;color:#334155;border:1px solid transparent;} QToolButton#targetChoice:hover{background:#fff;} QToolButton#targetChoice:checked{background:#0078d4;color:#fff;border:1px solid #0078d4;} QTabWidget::pane{background:#fff;border:1px solid #cbd2d9;} QTabBar::tab{background:#e9eef5;color:#111;border:1px solid #cbd2d9;} QTabBar::tab:selected{background:#0078d4;color:#fff;} QTreeWidget,QTableWidget{background:#fff;alternate-background-color:#f7f9fb;color:#111;border:1px solid #cbd2d9;gridline-color:#cbd2d9;} QHeaderView::section{background:#e9eef5;color:#111;border:1px solid #cbd2d9;} QStatusBar{background:#fff;color:#111;border-top:1px solid #cbd2d9;}"""
    @classmethod
    def dark_css(cls):
        return cls.common_css()+"""QMainWindow,QWidget{background:#1e1e1e;color:#f2f2f2;} QLabel#appSubtitle{color:#b8b8b8;} QFrame#card,QFrame#summaryCard{background:#292929;border:1px solid #414141;} QFrame#targetSelector{background:#252525;border:1px solid #484848;} QLineEdit,QComboBox,QPlainTextEdit,QTextEdit{background:#181818;color:#f2f2f2;border:1px solid #505050;} QPushButton{background:#333;color:#f2f2f2;border:1px solid #565656;} QPushButton:hover{background:#414141;} QPushButton:disabled{color:#777;background:#303030;border-color:#444;} QToolButton#targetChoice{background:transparent;color:#d8d8d8;border:1px solid transparent;} QToolButton#targetChoice:hover{background:#333;} QToolButton#targetChoice:checked{background:#0078d4;color:#fff;border:1px solid #2aa8ff;} QTabWidget::pane{background:#1e1e1e;border:1px solid #414141;} QTabBar::tab{background:#292929;color:#f2f2f2;border:1px solid #414141;} QTabBar::tab:selected{background:#0078d4;color:#fff;} QTreeWidget,QTableWidget{background:#202020;alternate-background-color:#242424;color:#f2f2f2;border:1px solid #444;gridline-color:#444;} QHeaderView::section{background:#303030;color:#f2f2f2;border:1px solid #444;} QStatusBar{background:#181818;color:#f2f2f2;border-top:1px solid #444;}"""
