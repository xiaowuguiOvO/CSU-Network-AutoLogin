from __future__ import annotations

import os

from PySide6.QtGui import QFont, QPalette
from PySide6.QtWidgets import QApplication


THEME_MODES = ("system", "light", "dark")


def resolve_theme(mode: str) -> str:
    if mode in ("light", "dark"):
        return mode

    if os.name == "nt":
        try:
            import winreg

            key_path = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
                return "light" if int(value) else "dark"
        except (OSError, ValueError, TypeError):
            pass

    color = QApplication.palette().color(QPalette.ColorRole.Window)
    return "dark" if color.lightness() < 128 else "light"


def apply_theme(app: QApplication, mode: str) -> str:
    effective = resolve_theme(mode)
    app.setProperty("resolvedTheme", effective)
    app.setStyle("Fusion")
    app.setFont(QFont("Microsoft YaHei UI", 10))
    app.setStyleSheet(_qss(effective))
    return effective


def _qss(theme: str) -> str:
    if theme == "dark":
        colors = {
            "bg": "#151715",
            "card": "#202320",
            "card_alt": "#292D29",
            "text": "#F4F5F2",
            "muted": "#969C96",
            "border": "#343934",
            "success": "#5BD49A",
            "success_bg": "#193B2A",
            "warning": "#F3B85A",
            "warning_bg": "#3C3020",
            "danger": "#FF707A",
            "danger_bg": "#422326",
            "primary": "#F2F4F0",
            "primary_text": "#111311",
            "hover": "#303530",
            "scroll": "#434943",
        }
    else:
        colors = {
            "bg": "#F1F2F0",
            "card": "#FFFFFF",
            "card_alt": "#F7F8F6",
            "text": "#111311",
            "muted": "#858A85",
            "border": "#E4E6E3",
            "success": "#22AD68",
            "success_bg": "#EAF8F0",
            "warning": "#C47A13",
            "warning_bg": "#FFF4DF",
            "danger": "#DF4450",
            "danger_bg": "#FDECEF",
            "primary": "#111311",
            "primary_text": "#FFFFFF",
            "hover": "#ECEEEC",
            "scroll": "#CDD1CD",
        }

    return f"""
QMainWindow, QDialog {{
  background: {colors['bg']};
}}

QWidget {{
  color: {colors['text']};
  font-size: 13px;
}}

QWidget#Page {{
  background: {colors['bg']};
}}

QWidget#Card, QWidget#HeroCard, QWidget#ListRow, QWidget#LoginBody,
QPushButton#ActionCard, QPushButton#SectionToggle {{
  background: {colors['card']};
  border: 1px solid {colors['border']};
  border-radius: 18px;
}}

QLabel#AppTitle {{
  color: {colors['text']};
  font-size: 25px;
  font-weight: 700;
}}

QLabel#Eyebrow, QLabel#Muted, QLabel#MetricLabel, QLabel#LatestTime {{
  color: {colors['muted']};
}}

QLabel#SectionTitle {{
  color: {colors['text']};
  font-size: 17px;
  font-weight: 700;
}}

QLabel#ConnectionTitle {{
  color: {colors['text']};
  font-size: 30px;
  font-weight: 750;
}}

QLabel#IpValue {{
  color: {colors['muted']};
  font-size: 18px;
  font-weight: 600;
}}

QLabel#MetricValue {{
  color: {colors['text']};
  font-size: 14px;
  font-weight: 650;
}}

QLabel#StatusDot {{
  background: {colors['muted']};
  border-radius: 7px;
  min-width: 14px;
  max-width: 14px;
  min-height: 14px;
  max-height: 14px;
}}

QLabel#StatusDot[status="online"] {{ background: {colors['success']}; }}
QLabel#StatusDot[status="busy"] {{ background: {colors['warning']}; }}
QLabel#StatusDot[status="error"] {{ background: {colors['danger']}; }}

QLabel#StatusPill {{
  color: {colors['muted']};
  background: {colors['card_alt']};
  border-radius: 13px;
  padding: 5px 10px;
  font-weight: 650;
}}

QLabel#StatusPill[status="online"] {{
  color: {colors['success']};
  background: {colors['success_bg']};
}}

QLabel#StatusPill[status="busy"] {{
  color: {colors['warning']};
  background: {colors['warning_bg']};
}}

QLabel#StatusPill[status="error"] {{
  color: {colors['danger']};
  background: {colors['danger_bg']};
}}

QPushButton {{
  min-height: 38px;
  border-radius: 13px;
  padding: 0 14px;
  font-weight: 650;
  border: 1px solid {colors['border']};
  background: {colors['card']};
}}

QPushButton:hover {{ background: {colors['hover']}; }}
QPushButton:pressed {{ padding-top: 1px; }}
QPushButton:disabled {{ color: {colors['muted']}; }}

QPushButton#CircleButton {{
  min-width: 44px;
  max-width: 44px;
  min-height: 44px;
  max-height: 44px;
  border-radius: 22px;
  padding: 0;
  font-size: 18px;
}}

QPushButton#CircleButton::menu-indicator {{
  image: none;
  width: 0px;
  height: 0px;
}}

QPushButton#ActionCard {{
  min-height: 72px;
  text-align: left;
  padding: 0 18px;
  font-size: 14px;
}}

QPushButton#SectionToggle {{
  min-height: 54px;
  text-align: left;
  padding: 0 18px;
  font-size: 16px;
}}

QPushButton#PrimaryButton {{
  min-height: 52px;
  color: {colors['primary_text']};
  background: {colors['primary']};
  border: none;
  border-radius: 17px;
  font-size: 15px;
}}

QPushButton#StopButton {{
  min-height: 52px;
  color: {colors['danger']};
  background: {colors['danger_bg']};
  border: 1px solid {colors['danger']};
  border-radius: 17px;
  font-size: 15px;
}}

QPushButton#TextButton {{
  color: {colors['muted']};
  background: transparent;
  border: none;
}}

QLineEdit, QComboBox, QSpinBox {{
  min-height: 42px;
  color: {colors['text']};
  background: {colors['card_alt']};
  border: 1px solid {colors['border']};
  border-radius: 12px;
  padding: 0 12px;
  selection-background-color: {colors['success']};
}}

QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{
  border: 1px solid {colors['success']};
}}

QComboBox::drop-down {{ border: none; width: 28px; }}
QComboBox QAbstractItemView {{
  color: {colors['text']};
  background: {colors['card']};
  border: 1px solid {colors['border']};
  selection-background-color: {colors['success_bg']};
}}

QCheckBox {{ spacing: 10px; }}
QCheckBox::indicator {{
  width: 38px;
  height: 22px;
  border-radius: 11px;
  background: {colors['border']};
}}
QCheckBox::indicator:checked {{
  background: {colors['success']};
}}

QPlainTextEdit {{
  color: {colors['text']};
  background: {colors['card']};
  border: 1px solid {colors['border']};
  border-radius: 14px;
  padding: 10px;
  font-family: Consolas, monospace;
}}

QMenu {{
  color: {colors['text']};
  background: {colors['card']};
  border: 1px solid {colors['border']};
  padding: 6px;
}}
QMenu::item {{ padding: 8px 26px 8px 12px; border-radius: 7px; }}
QMenu::item:selected {{ background: {colors['hover']}; }}

QScrollArea {{ border: none; background: transparent; }}
QScrollBar:vertical {{ background: transparent; width: 9px; margin: 3px; }}
QScrollBar::handle:vertical {{ background: {colors['scroll']}; border-radius: 4px; min-height: 28px; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
"""
