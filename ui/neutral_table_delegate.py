from PySide6.QtGui import QColor
from PySide6.QtWidgets import QStyle, QStyledItemDelegate


class NeutralTableDelegate(QStyledItemDelegate):
    """Theme-aware neutral row selection without hover or focus artifacts."""

    def paint(self, painter, option, index):
        selected = bool(option.state & QStyle.StateFlag.State_Selected)
        clean = type(option)(option)
        clean.state &= ~QStyle.StateFlag.State_MouseOver
        clean.state &= ~QStyle.StateFlag.State_HasFocus
        clean.state &= ~QStyle.StateFlag.State_Selected

        if selected:
            window = option.palette.color(option.palette.ColorRole.Window)
            fill = QColor("#d9dde2") if window.lightness() >= 128 else QColor("#3a3a3a")
            painter.save()
            painter.fillRect(option.rect, fill)
            painter.restore()

        super().paint(painter, clean, index)
