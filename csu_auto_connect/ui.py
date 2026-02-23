from __future__ import annotations

import argparse
import sys

import faulthandler
import tempfile
from urllib.parse import urlparse
from PySide6.QtCore import Qt, QThread, Slot, QRegularExpression
from PySide6.QtGui import QAction, QFont, QRegularExpressionValidator
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QPushButton,
    QPlainTextEdit,
    QSpinBox,
    QStyle,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

from .autostart import is_autostart_enabled, set_autostart
from .config import Config, load_ini, save_ini
from .logging_setup import setup_logging
from .paths import config_path, log_path
from .portal import (
    build_login_url,
    build_login_url_v4,
    get_all_portal_defaults,
    get_portal_defaults,
    login_once,
    normalize_user_account,
    probe_ipconfig_ipv4,
    probe_ipconfig_wlan_mac,
    probe_wlan_user_ip,
    redact_login_url,
    test_internet,
)
from .workers import AutoConnectWorker, OneShotWorker


_APP_QSS = """
QMainWindow {
  background: #f5f7fb;
}

QWidget#Card {
  background: #ffffff;
  border: 1px solid #e5e7eb;
  border-radius: 14px;
}

QWidget#Card QLabel {
  color: #0f172a;
}

QLabel#Title {
  font-size: 18px;
  font-weight: 650;
  color: #0f172a;
}

QLabel#Subtitle {
  color: #64748b;
}

QLabel#SectionTitle {
  color: #0f172a;
  font-weight: 600;
}

QLabel#Hint {
  color: #64748b;
}

QLineEdit, QComboBox, QSpinBox {
  padding: 7px 10px;
  border: 1px solid #d1d5db;
  border-radius: 10px;
  background: #ffffff;
  color: #0f172a;
  selection-background-color: #2563eb;
}

QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
  border: 1px solid #2563eb;
}

QComboBox::drop-down {
  border: 0px;
  width: 26px;
}

QPlainTextEdit {
  padding: 10px;
  border: 1px solid #d1d5db;
  border-radius: 12px;
  background: #0b1220;
  color: #e5e7eb;
  font-family: Consolas, "Cascadia Mono", monospace;
  font-size: 11px;
}

QPushButton {
  padding: 8px 12px;
  border-radius: 12px;
  border: 1px solid #d1d5db;
  background: #ffffff;
  color: #0f172a;
}

QPushButton:hover {
  background: #f3f4f6;
}

QPushButton#Primary {
  background: #2563eb;
  border: 1px solid #1d4ed8;
  color: #ffffff;
  font-weight: 600;
}

QPushButton#Primary:hover {
  background: #1d4ed8;
}

QPushButton#Danger {
  background: #ef4444;
  border: 1px solid #dc2626;
  color: #ffffff;
  font-weight: 600;
}

QPushButton#Danger:hover {
  background: #dc2626;
}

QPushButton:disabled {
  color: #9ca3af;
  background: #f8fafc;
  border: 1px solid #e5e7eb;
}

QLabel#StatusPill {
  padding: 5px 12px;
  border-radius: 999px;
  background: #e5e7eb;
  color: #111827;
  font-weight: 600;
}

QLabel#StatusPill[status="online"] {
  background: #dcfce7;
  color: #166534;
}

QLabel#StatusPill[status="busy"] {
  background: #dbeafe;
  color: #1e40af;
}

QLabel#StatusPill[status="error"] {
  background: #fee2e2;
  color: #991b1b;
}

QCheckBox {
  spacing: 10px;
  color: #0f172a;
}

QCheckBox::indicator {
  width: 16px;
  height: 16px;
  border-radius: 4px;
  border: 1px solid #94a3b8;
  background: #ffffff;
}

QCheckBox::indicator:checked {
  border: 1px solid #1d4ed8;
  background: #2563eb;
}

QCheckBox::indicator:unchecked:hover {
  border: 1px solid #64748b;
  background: #f8fafc;
}
"""


def apply_app_style(app: QApplication) -> None:
    # Fusion + QSS gives a consistent, modern look on Windows.
    app.setStyle("Fusion")
    # Qt will fall back automatically if the font is not available.
    app.setFont(QFont("Segoe UI Variable", 10))
    app.setStyleSheet(_APP_QSS)


class MainWindow(QMainWindow):
    def __init__(self, cfg: Config, start_minimized: bool):
        super().__init__()
        self._cfg_path = config_path()
        self._log_path = log_path()
        self._logger = setup_logging(self._log_path)

        self._cfg = cfg
        self._running = False

        self.setWindowTitle("CSU Auto Connect")
        self.setMinimumSize(440, 640)
        self.resize(440, 720)
        # Controls
        self.ed_user = QLineEdit(cfg.user_account)
        self.ed_user.setPlaceholderText("账号")
        # Restrict to common account characters to avoid accidental log text injection.
        self.ed_user.setValidator(QRegularExpressionValidator(QRegularExpression(r"[0-9A-Za-z@,._-]*")))

        self.ed_pass = QLineEdit(cfg.user_password)
        self.ed_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.ed_pass.setPlaceholderText("密码")

        self.sp_interval = QSpinBox()
        self.sp_interval.setRange(5, 3600)
        self.sp_interval.setValue(cfg.interval_sec)
        self.sp_interval.setSuffix(" 秒")
        self.sp_interval.setButtonSymbols(QSpinBox.ButtonSymbols.NoButtons)

        self.cb_portal = QComboBox()
        self.cb_portal.addItem("实验室（Lab）", "lab")
        self.cb_portal.addItem("电信（Telecom）", "telecom")
        self.cb_portal.addItem("联通（Unicom）", "unicom")
        self.cb_portal.addItem("移动（Mobile）", "mobile")
        self.cb_portal.addItem("校园网（Campus）", "campus")
        idx = self.cb_portal.findData(cfg.portal_type)
        self.cb_portal.setCurrentIndex(idx if idx >= 0 else 0)

        self.cb_mode = QComboBox()
        self.cb_mode.addItem("自动（断网才登录，推荐）", "detect")
        self.cb_mode.addItem("定时强制登录", "always")
        idx = self.cb_mode.findData(cfg.mode)
        self.cb_mode.setCurrentIndex(idx if idx >= 0 else 0)

        self.ed_probe = QLineEdit(cfg.portal_probe_url)
        self.ed_probe.setPlaceholderText("http://10.255.254.11/")

        self.ed_login_url = QLineEdit(cfg.portal_login_url)
        self.ed_login_url.setPlaceholderText("https://portal.csu.edu.cn:802/eportal/portal/login")

        self.ed_jsver = QLineEdit(cfg.portal_js_version)
        self.ed_jsver.setPlaceholderText("4.1.3")

        self.ed_extra = QLineEdit(cfg.portal_extra_params)
        self.ed_extra.setPlaceholderText("terminal_type=1&lang=zh-cn&v=2102&lang=zh")

        self.ed_referer = QLineEdit(cfg.portal_referer)
        self.ed_referer.setPlaceholderText("https://portal.csu.edu.cn/")

        self.chk_autostart = QCheckBox("开机自启（当前用户）")
        self.chk_autostart.setChecked(is_autostart_enabled())

        self.chk_start_min = QCheckBox("自启时最小化到托盘")
        self.chk_start_min.setChecked(cfg.start_minimized)


        self.lbl_status = QLabel("就绪")
        self.lbl_status.setObjectName("StatusPill")
        self._set_status_kind("stopped")

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)

        self.btn_toggle = QPushButton("开始")
        self.btn_toggle.setObjectName("Primary")
        self.btn_toggle.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay))

        self.btn_probe = QPushButton("探测IP")
        self.btn_probe.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_BrowserReload))

        self.btn_test = QPushButton("连接测试")
        self.btn_test.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogApplyButton))

        self.btn_save = QPushButton("保存配置")
        self.btn_save.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogSaveButton))

        self.btn_open_log = QPushButton("打开日志")
        self.btn_open_log.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon))

        self.btn_copy_log = QPushButton("复制日志")
        self.btn_copy_log.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogOpenButton))

        self.btn_clear_log = QPushButton("清空")
        self.btn_clear_log.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_TrashIcon))

        self._update_toggle_button()

        defaults = get_all_portal_defaults()
        self._default_probe_urls = {d.probe_url for d in defaults if d.probe_url}
        self._default_login_urls = {d.login_url for d in defaults if d.login_url}
        self._default_js_versions = {d.js_version for d in defaults if d.js_version}
        self._default_extra_params = {d.extra_params for d in defaults if d.extra_params}
        self._default_referers = {d.referer for d in defaults if d.referer}

        self._apply_portal_defaults()

        # Header
        title = QLabel("CSU Auto Connect")
        title.setObjectName("Title")
        subtitle = QLabel("校园网自动登录")
        subtitle.setObjectName("Subtitle")

        header_left = QVBoxLayout()
        header_left.setSpacing(2)
        header_left.addWidget(title)
        header_left.addWidget(subtitle)

        header = QHBoxLayout()
        header.addLayout(header_left)
        header.addStretch(1)
        header.addWidget(self.lbl_status, 0, Qt.AlignmentFlag.AlignVCenter)

        # Settings card
        settings_card = QWidget()
        settings_card.setObjectName("Card")
        settings_card.setMinimumWidth(360)
        settings_card.setMaximumWidth(480)

        settings = QVBoxLayout(settings_card)
        settings.setContentsMargins(16, 16, 16, 16)
        settings.setSpacing(14)

        sec1 = QLabel("账号")
        sec1.setObjectName("SectionTitle")
        settings.addWidget(sec1)

        form1 = QFormLayout()
        form1.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
        form1.setFormAlignment(Qt.AlignmentFlag.AlignTop)
        form1.setVerticalSpacing(10)
        form1.addRow("账号", self.ed_user)
        form1.addRow("密码", self.ed_pass)
        settings.addLayout(form1)

        sec2 = QLabel("运行")
        sec2.setObjectName("SectionTitle")
        settings.addWidget(sec2)

        form2 = QFormLayout()
        form2.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
        form2.setVerticalSpacing(10)
        form2.addRow("网络类型", self.cb_portal)
        form2.addRow("模式", self.cb_mode)
        form2.addRow("检查间隔", self.sp_interval)
        settings.addLayout(form2)

        hint = QLabel("建议使用“自动模式”，只有断网时才会触发登录。")
        hint.setObjectName("Hint")
        hint.setWordWrap(True)
        settings.addWidget(hint)

        sec3 = QLabel("自启")
        sec3.setObjectName("SectionTitle")
        settings.addWidget(sec3)
        settings.addWidget(self.chk_autostart)
        settings.addWidget(self.chk_start_min)

        # Advanced fields are removed from the UI for now.

        settings.addStretch(1)

        row_a = QHBoxLayout()
        row_a.addWidget(self.btn_toggle, 1)
        settings.addLayout(row_a)

        row_b = QHBoxLayout()
        row_b.addWidget(self.btn_test, 1)
        row_b.addWidget(self.btn_probe, 1)
        settings.addLayout(row_b)

        row_c = QHBoxLayout()
        row_c.addWidget(self.btn_save, 1)
        row_c.addWidget(self.btn_open_log, 1)
        settings.addLayout(row_c)

        # Log dialog (hidden by default)
        self.log_dialog = QDialog(self)
        self.log_dialog.setWindowTitle("日志")
        self.log_dialog.setMinimumSize(760, 420)
        log_layout = QVBoxLayout(self.log_dialog)
        log_layout.setContentsMargins(16, 16, 16, 16)
        log_layout.setSpacing(12)

        log_title = QLabel("日志")
        log_title.setObjectName("SectionTitle")

        log_actions = QHBoxLayout()
        log_actions.addWidget(log_title)
        log_actions.addStretch(1)
        log_actions.addWidget(self.btn_copy_log)
        log_actions.addWidget(self.btn_clear_log)
        log_layout.addLayout(log_actions)

        log_layout.addWidget(self.log_view, 1)

        log_hint = QLabel(f"配置: {self._cfg_path}\n日志: {self._log_path}")
        log_hint.setObjectName("Hint")
        log_hint.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        log_layout.addWidget(log_hint)

        body = QHBoxLayout()
        body.setSpacing(16)
        body.addWidget(settings_card, 1)

        root = QVBoxLayout()
        root.setContentsMargins(18, 18, 18, 18)
        root.setSpacing(16)
        root.addLayout(header)
        root.addLayout(body, 1)

        w = QWidget()
        w.setLayout(root)
        self.setCentralWidget(w)

        # Tray
        self.tray = QSystemTrayIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DriveNetIcon))
        self.tray.setToolTip("CSU Auto Connect")
        self.tray_menu = QMenu()
        self.act_show = QAction("打开设置", self)
        self.act_run_once = QAction("立即登录", self)
        self.act_open_log = QAction("打开日志", self)
        self.act_quit = QAction("退出", self)
        self.tray_menu.addAction(self.act_show)
        self.tray_menu.addAction(self.act_run_once)
        self.tray_menu.addAction(self.act_open_log)
        self.tray_menu.addSeparator()
        self.tray_menu.addAction(self.act_quit)
        self.tray.setContextMenu(self.tray_menu)
        self.tray.activated.connect(self._on_tray_activated)
        self.tray.show()

        # Worker thread
        self._thread: QThread | None = None
        self._worker: AutoConnectWorker | None = None

        # One-shot task (probe/test) thread
        self._oneshot_thread: QThread | None = None
        self._oneshot_worker: OneShotWorker | None = None
        self._oneshot_on_ok = None
        self._oneshot_on_err = None
        self._oneshot_ok_prefix: str | None = None
        self._oneshot_status_done: str | None = None

        # Wire actions
        self.btn_save.clicked.connect(self.on_save)
        self.btn_open_log.clicked.connect(self.on_open_log)
        self.btn_copy_log.clicked.connect(self.on_copy_log)
        self.btn_clear_log.clicked.connect(self.on_clear_log)

        self.btn_toggle.clicked.connect(self.on_toggle)
        self.btn_probe.clicked.connect(self.on_probe)
        self.btn_test.clicked.connect(self.on_test)

        self.cb_portal.currentIndexChanged.connect(self.on_portal_type_changed)
        self.chk_autostart.stateChanged.connect(self.on_autostart_changed)
        self.chk_start_min.stateChanged.connect(self.on_autostart_changed)

        self.act_show.triggered.connect(self.show_normal)
        self.act_run_once.triggered.connect(self.on_run_once)
        self.act_open_log.triggered.connect(self.on_open_log)
        self.act_quit.triggered.connect(self.on_quit)

        self.set_status("就绪")

        if start_minimized:
            self.hide()

    def _set_status_kind(self, kind: str) -> None:
        self.lbl_status.setProperty("status", kind)
        self.lbl_status.style().unpolish(self.lbl_status)
        self.lbl_status.style().polish(self.lbl_status)

    def _update_toggle_button(self) -> None:
        if self._running:
            self.btn_toggle.setText("停止")
            self.btn_toggle.setObjectName("Danger")
            self.btn_toggle.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaStop))
        else:
            self.btn_toggle.setText("开始")
            self.btn_toggle.setObjectName("Primary")
            self.btn_toggle.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay))

        # Refresh style after objectName change
        self.btn_toggle.style().unpolish(self.btn_toggle)
        self.btn_toggle.style().polish(self.btn_toggle)

    def _infer_status_kind(self, s: str) -> str:
        if not s:
            return "stopped"
        if any(x in s for x in ("失败", "异常")):
            return "error"
        if any(x in s for x in ("探测", "测试", "登录中", "启动中", "停止中", "忙碌")):
            return "busy"
        if any(x in s for x in ("在线", "已认证", "成功")):
            return "online"
        if "停止" in s:
            return "stopped"
        return "stopped"

    def _set_oneshot_busy(self, busy: bool) -> None:
        # Avoid spawning multiple overlapping probe/test threads.
        self.btn_probe.setEnabled(not busy)
        self.btn_test.setEnabled(not busy)
        self.act_run_once.setEnabled(not busy)

    def _should_override(self, val: str, default_set: set[str]) -> bool:
        if not val:
            return True
        return val in default_set

    def _apply_portal_defaults(self) -> None:
        portal_type = str(self.cb_portal.currentData() or "lab")
        defaults = get_portal_defaults(portal_type)

        if self._should_override(self.ed_probe.text().strip(), self._default_probe_urls):
            self.ed_probe.setText(defaults.probe_url)
        if self._should_override(self.ed_login_url.text().strip(), self._default_login_urls):
            self.ed_login_url.setText(defaults.login_url)
        if self._should_override(self.ed_jsver.text().strip(), self._default_js_versions):
            self.ed_jsver.setText(defaults.js_version)
        if self._should_override(self.ed_extra.text().strip(), self._default_extra_params):
            self.ed_extra.setText(defaults.extra_params)
        if self._should_override(self.ed_referer.text().strip(), self._default_referers):
            self.ed_referer.setText(defaults.referer)

    def _resolve_portal_settings(self, cfg: Config):
        defaults = get_portal_defaults(cfg.portal_type)
        probe_url = cfg.portal_probe_url or defaults.probe_url
        login_url = cfg.portal_login_url or defaults.login_url
        js_version = cfg.portal_js_version or defaults.js_version
        extra_params = cfg.portal_extra_params or defaults.extra_params
        referer = cfg.portal_referer or defaults.referer
        return defaults, probe_url, login_url, js_version, extra_params, referer

    def append_log(self, msg: str) -> None:
        self._logger.info(msg)
        self.log_view.appendPlainText(msg)

    def current_cfg(self) -> Config:
        user_account = self.ed_user.text().strip()
        if self.ed_user.validator():
            # Re-apply validator to sanitize any pasted text.
            state, fixed, _ = self.ed_user.validator().validate(user_account, 0)
            if state != self.ed_user.validator().State.Acceptable:
                user_account = "".join(ch for ch in user_account if ch.isalnum() or ch in "@,._-")
                self.ed_user.setText(user_account)
        return Config(
            user_account=user_account,
            user_password=self.ed_pass.text(),
            interval_sec=int(self.sp_interval.value()),
            mode=str(self.cb_mode.currentData() or "detect"),
            portal_type=str(self.cb_portal.currentData() or "lab"),
            portal_probe_url=self.ed_probe.text().strip(),
            portal_login_url=self.ed_login_url.text().strip(),
            portal_js_version=self.ed_jsver.text().strip(),
            portal_extra_params=self.ed_extra.text().strip(),
            portal_referer=self.ed_referer.text().strip(),
            autostart=self.chk_autostart.isChecked(),
            start_minimized=self.chk_start_min.isChecked(),
        )

    def set_status(self, s: str) -> None:
        self.lbl_status.setText(s)
        self._set_status_kind(self._infer_status_kind(s))

    def on_portal_type_changed(self):
        self._apply_portal_defaults()


    def on_copy_log(self):
        QApplication.clipboard().setText(self.log_view.toPlainText())
        self._logger.info("Copied log to clipboard")
        self.set_status("已复制")

    def on_clear_log(self):
        self.log_view.clear()
        self._logger.info("Log view cleared")
        self.set_status("已清空")

    def show_normal(self) -> None:
        self.show()
        self.raise_()
        self.activateWindow()

    def closeEvent(self, event):  # noqa: N802
        # Minimize to tray
        event.ignore()
        self.hide()
        self.append_log("已最小化到托盘（右键托盘可退出）")

    def _on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            self.show_normal()

    def on_save(self):
        self._cfg = self.current_cfg()
        save_ini(self._cfg_path, self._cfg)
        self.append_log(f"已保存配置: {self._cfg_path}")

    def on_open_log(self):
        if self.log_dialog.isVisible():
            self.log_dialog.raise_()
            self.log_dialog.activateWindow()
        else:
            self.log_dialog.show()

    def on_autostart_changed(self):
        enabled = self.chk_autostart.isChecked()
        start_min = self.chk_start_min.isChecked()
        try:
            set_autostart(enabled, start_minimized=start_min)
            self._logger.info("Autostart updated: enabled=%s start_min=%s", enabled, start_min)
        except Exception as e:
            self.append_log(f"更新自启失败: {e!r}")

    def on_start(self):
        if self._running:
            return

        self._cfg = self.current_cfg()
        self.append_log("后台服务启动")
        self.set_status("启动中...")

        self._thread = QThread()
        self._worker = AutoConnectWorker(self._cfg)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.log.connect(self.append_log)
        self._worker.status.connect(self.set_status)
        self._worker.running.connect(self._on_running_changed)
        self._worker.finished.connect(self._thread.quit)
        self._worker.finished.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._thread.deleteLater)
        self._thread.start()

    def _on_running_changed(self, running: bool):
        self._running = running
        self._update_toggle_button()

    def on_toggle(self):
        if self._running:
            self.on_stop()
        else:
            self.on_start()

    def on_stop(self):
        if not self._worker:
            return
        self.append_log("后台服务停止")
        self._worker.stop()
        self.set_status("停止中...")

    def on_run_once(self):
        self.on_test()

    def on_probe(self):
        if self._oneshot_thread and self._oneshot_thread.isRunning():
            self.append_log("已有任务在执行，请稍候…")
            self.set_status("忙碌中…")
            return

        cfg = self.current_cfg()
        self.set_status("探测中...(请稍候)")
        self.append_log("探测IP...")

        def fn():
            import requests

            s = requests.Session()
            defaults, probe_url, login_url, _, _, _ = self._resolve_portal_settings(cfg)
            fallback_host = None
            if login_url:
                fallback_host = urlparse(login_url).hostname
            if not fallback_host and probe_url:
                fallback_host = urlparse(probe_url).hostname
            if cfg.portal_type == "telecom":
                return probe_ipconfig_ipv4()
            only_status = defaults.login_style == "lab"
            return probe_wlan_user_ip(
                s,
                probe_url,
                timeout_sec=3.0,
                fallback_host=fallback_host,
                allow_private=defaults.login_style != "lab",
                only_status=only_status,
            )

        self._run_oneshot(fn, ok_prefix="探测结果", status_done="完成")

    def on_test(self):
        if self._oneshot_thread and self._oneshot_thread.isRunning():
            self.append_log("已有任务在执行，请稍候…")
            self.set_status("忙碌中…")
            return

        cfg = self.current_cfg()
        self.set_status("测试中...(请稍候)")
        self.append_log("连接测试...")

        def fn():
            import requests

            s = requests.Session()
            defaults, probe_url, login_url, js_version, extra_params, referer = self._resolve_portal_settings(cfg)
            fallback_host = None
            if login_url:
                fallback_host = urlparse(login_url).hostname
            if not fallback_host and probe_url:
                fallback_host = urlparse(probe_url).hostname
            wlan_user_mac = None
            if cfg.portal_type == "telecom":
                ip = probe_ipconfig_ipv4()
                wlan_user_mac = probe_ipconfig_wlan_mac()
            else:
                only_status = defaults.login_style == "lab"
                ip = probe_wlan_user_ip(
                    s,
                    probe_url,
                    timeout_sec=3.0,
                    fallback_host=fallback_host,
                    allow_private=defaults.login_style != "lab",
                    only_status=only_status,
                )
            if not ip:
                return {"ok": False, "error": "未探测到 wlan_user_ip"}
            if defaults.login_style == "lab":
                url = build_login_url(
                    normalize_user_account(cfg.user_account, cfg.portal_type),
                    cfg.user_password,
                    ip,
                    js_version=js_version or "3.3.1",
                )
            else:
                if not login_url:
                    return {"ok": False, "error": "未配置 PortalLoginUrl"}
                user_account = normalize_user_account(cfg.user_account, cfg.portal_type)
                url = build_login_url_v4(
                    user_account,
                    cfg.user_password,
                    ip,
                    login_url=login_url,
                    wlan_user_mac=wlan_user_mac or "000000000000",
                    js_version=js_version or "4.1.3",
                    extra_params=extra_params,
                )
            res = login_once(s, url, timeout_sec=8.0, referer=referer or None)
            online = test_internet(s, timeout_sec=3.0)
            return {
                "ok": res.ok,
                "online": online,
                "ret_code": res.ret_code,
                "msg": res.msg_decoded or res.msg,
                "raw": res.raw[:300],
                "login_url": redact_login_url(url),
                "mac": wlan_user_mac or "000000000000",
                "result": res.result,
            }

        def on_ok(obj):
            if isinstance(obj, dict) and not obj.get("ok") and obj.get("error"):
                self.append_log(f"测试登录：失败 {obj.get('error')}".strip())
                self.set_status("失败")
                return
            result_val = None
            if isinstance(obj, dict):
                result_val = obj.get("result")
            if isinstance(obj, dict) and (obj.get("ok") or str(result_val) == "1"):
                self.append_log("测试登录：认证成功")
                self.set_status("成功")
                return
            if isinstance(obj, dict) and obj.get("online"):
                self.append_log("测试登录：已在线（无需重复认证）")
                self.set_status("在线")
                return
            self.append_log(f"测试登录：返回 {obj!r}")
            self.set_status("完成")

        def on_err(err: str):
            self.append_log(f"测试登录：异常 {err}")
            self.set_status("失败")

        self._run_oneshot(fn, on_ok=on_ok, on_err=on_err, status_done=None)

    def _run_oneshot(
        self,
        fn,
        ok_prefix: str | None = None,
        status_done: str | None = "完成",
        on_ok=None,
        on_err=None,
    ):
        # Keep references to avoid premature GC in PySide.
        self._set_oneshot_busy(True)
        self._oneshot_thread = QThread(self)
        self._oneshot_worker = OneShotWorker(fn)
        self._oneshot_worker.moveToThread(self._oneshot_thread)
        thread = self._oneshot_thread
        worker = self._oneshot_worker

        self._oneshot_on_ok = on_ok
        self._oneshot_on_err = on_err
        self._oneshot_ok_prefix = ok_prefix
        self._oneshot_status_done = status_done

        thread.started.connect(worker.run)
        worker.finished.connect(self._oneshot_done, Qt.ConnectionType.QueuedConnection)
        worker.error.connect(self._oneshot_error, Qt.ConnectionType.QueuedConnection)
        worker.finished.connect(worker.deleteLater)
        worker.error.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.start()

    @Slot(object)
    def _oneshot_done(self, obj):
        try:
            if self._oneshot_on_ok:
                self._oneshot_on_ok(obj)
            else:
                self.append_log(f"{self._oneshot_ok_prefix}: {obj}")
                if self._oneshot_status_done:
                    self.set_status(self._oneshot_status_done)
        except Exception as e:
            self.append_log(f"任务处理异常: {e!r}")
            self.set_status("失败")
        finally:
            self._set_oneshot_busy(False)
            self._oneshot_on_ok = None
            self._oneshot_on_err = None
            self._oneshot_ok_prefix = None
            self._oneshot_status_done = None
            if self._oneshot_thread:
                self._oneshot_thread.quit()
            self._oneshot_worker = None
            self._oneshot_thread = None

    @Slot(str)
    def _oneshot_error(self, msg: str):
        try:
            if self._oneshot_on_err:
                self._oneshot_on_err(msg)
            else:
                self.append_log(f"{self._oneshot_ok_prefix or '任务'}失败: {msg}")
                if self._oneshot_status_done:
                    self.set_status("失败")
        except Exception as e:
            self.append_log(f"任务错误处理异常: {e!r}")
            self.set_status("失败")
        finally:
            self._set_oneshot_busy(False)
            self._oneshot_on_ok = None
            self._oneshot_on_err = None
            self._oneshot_ok_prefix = None
            self._oneshot_status_done = None
            if self._oneshot_thread:
                self._oneshot_thread.quit()
            self._oneshot_worker = None
            self._oneshot_thread = None

    def on_quit(self):
        try:
            if self._worker:
                self._worker.stop()
        finally:
            QApplication.quit()


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--start-minimized", action="store_true")
    return p.parse_args(argv)


def run(argv: list[str]) -> int:
    import threading
    from pathlib import Path

    args = parse_args(argv)
    cfg = load_ini(config_path())

    app = QApplication(sys.argv[:1])
    app.setQuitOnLastWindowClosed(False)
    apply_app_style(app)

    # Log unhandled exceptions to file to avoid silent crashes.
    log_file = log_path()
    logger = setup_logging(log_file)

    # Also capture fatal errors (segfaults) to a file.
    global _FAULT_LOG_FH
    try:
        _FAULT_LOG_FH = open(log_file, "a", encoding="utf-8")
    except Exception:
        fallback = Path(tempfile.gettempdir()) / "csu_auto_connect_fatal.log"
        _FAULT_LOG_FH = open(fallback, "a", encoding="utf-8")
    faulthandler.enable(file=_FAULT_LOG_FH, all_threads=True)
    logger.info("Fault handler enabled: %s", getattr(_FAULT_LOG_FH, "name", "unknown"))

    def _excepthook(exc_type, exc, tb):
        logger.error("Unhandled exception", exc_info=(exc_type, exc, tb))
        sys.__excepthook__(exc_type, exc, tb)

    def _thread_hook(args):
        logger.error("Thread exception", exc_info=(args.exc_type, args.exc_value, args.exc_traceback))

    sys.excepthook = _excepthook
    threading.excepthook = _thread_hook

    start_min = args.start_minimized or cfg.start_minimized
    win = MainWindow(cfg, start_minimized=start_min)
    if not start_min:
        win.show()
    return app.exec()
