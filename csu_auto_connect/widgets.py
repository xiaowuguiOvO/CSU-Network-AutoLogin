from __future__ import annotations

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import QApplication, QCheckBox, QWidget


class ToggleSwitch(QCheckBox):
    """Small theme-aware switch that behaves like a regular QCheckBox."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setText("")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedSize(44, 24)

    def sizeHint(self) -> QSize:  # noqa: N802
        return QSize(44, 24)

    def paintEvent(self, event):  # noqa: N802
        app = QApplication.instance()
        dark = bool(app and app.property("resolvedTheme") == "dark")

        if not self.isEnabled():
            track = QColor("#3A3E3A" if dark else "#D9DDD9")
            knob = QColor("#777C77" if dark else "#B8BDB8")
        elif self.isChecked():
            track = QColor("#5BD49A" if dark else "#22AD68")
            knob = QColor("#102219" if dark else "#FFFFFF")
        else:
            track = QColor("#3A3F3A" if dark else "#DDE1DD")
            knob = QColor("#C7CCC7" if dark else "#FFFFFF")

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(track)
        painter.drawRoundedRect(self.rect(), 12, 12)

        diameter = 18
        margin = 3
        x = self.width() - diameter - margin if self.isChecked() else margin
        painter.setBrush(knob)
        painter.drawEllipse(x, margin, diameter, diameter)
