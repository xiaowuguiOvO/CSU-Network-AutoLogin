from __future__ import annotations

import argparse
import sys
from datetime import datetime

import faulthandler
import tempfile
from urllib.parse import urlparse
from PySide6.QtCore import Qt, QThread, QTimer, Slot, QRegularExpression
from PySide6.QtGui import QAction, QRegularExpressionValidator
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QFormLayout,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QPushButton,
    QPlainTextEdit,
    QScrollArea,
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
from .theme import apply_theme
from .widgets import ToggleSwitch


def apply_app_style(app: QApplication, theme: str = "system") -> str:
    return apply_theme(app, theme)


class MainWindow(QMainWindow):
    def __init__(self, cfg: Config, start_minimized: bool):
        super().__init__()
        self._cfg_path = config_path()
        self._log_path = log_path()
        self._logger = setup_logging(self._log_path)

        self._cfg = cfg
        self._running = False
        self._theme_mode = cfg.theme

        self.setWindowTitle("CSU Auto Connect")
        self.setMinimumSize(420, 680)
        self.resize(460, 820)
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

        self.chk_autostart = ToggleSwitch()
        self.chk_autostart.setChecked(is_autostart_enabled())

        self.chk_connect_on_launch = ToggleSwitch()
        self.chk_connect_on_launch.setChecked(cfg.connect_on_launch)

        self.chk_start_min = ToggleSwitch()
        self.chk_start_min.setChecked(cfg.start_minimized)


        self.lbl_status = QLabel("待机")
        self.lbl_status.setObjectName("StatusPill")

        self.lbl_status_dot = QLabel()
        self.lbl_status_dot.setObjectName("StatusDot")
        self.lbl_connection_title = QLabel("等待启动")
        self.lbl_connection_title.setObjectName("ConnectionTitle")
        self.lbl_ip_value = QLabel("尚未探测 IP")
        self.lbl_ip_value.setObjectName("IpValue")
        self.lbl_network_value = QLabel()
        self.lbl_network_value.setObjectName("MetricValue")
        self.lbl_mode_value = QLabel()
        self.lbl_mode_value.setObjectName("MetricValue")
        self.lbl_interval_value = QLabel()
        self.lbl_interval_value.setObjectName("MetricValue")
        self.lbl_latest_event = QLabel("应用已准备就绪")
        self.lbl_latest_event.setObjectName("MetricValue")
        self.lbl_latest_event.setWordWrap(True)
        self.lbl_latest_time = QLabel("--:--:--")
        self.lbl_latest_time.setObjectName("LatestTime")

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)

        self.btn_toggle = QPushButton("启动服务")
        self.btn_toggle.setObjectName("PrimaryButton")
        self.btn_toggle.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay))

        self.btn_probe = QPushButton("探测 IP")
        self.btn_probe.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_BrowserReload))
        self.btn_probe.setObjectName("ActionCard")

        self.btn_test = QPushButton("连接测试")
        self.btn_test.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogApplyButton))
        self.btn_test.setObjectName("ActionCard")

        self.btn_save = QPushButton("保存配置")
        self.btn_save.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogSaveButton))
        self.btn_save.setObjectName("TextButton")

        self.btn_open_log = QPushButton("☷")
        self.btn_open_log.setObjectName("CircleButton")
        self.btn_open_log.setToolTip("打开日志")

        self.btn_theme = QPushButton("◐")
        self.btn_theme.setObjectName("CircleButton")
        self.btn_theme.setToolTip("切换主题")
        self.theme_menu = QMenu(self)
        for text, mode in (("跟随系统", "system"), ("浅色", "light"), ("深色", "dark")):
            action = self.theme_menu.addAction(text)
            action.triggered.connect(lambda checked=False, value=mode: self.set_theme(value))
        self.btn_theme.setMenu(self.theme_menu)

        self.btn_login_toggle = QPushButton()
        self.btn_login_toggle.setObjectName("SectionToggle")

        self.btn_copy_log = QPushButton("复制日志")
        self.btn_copy_log.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogOpenButton))

        self.btn_clear_log = QPushButton("清空")
        self.btn_clear_log.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_TrashIcon))

        self._set_status_kind("stopped")
        self._update_toggle_button()

        defaults = get_all_portal_defaults()
        self._default_probe_urls = {d.probe_url for d in defaults if d.probe_url}
        self._default_login_urls = {d.login_url for d in defaults if d.login_url}
        self._default_js_versions = {d.js_version for d in defaults if d.js_version}
        self._default_extra_params = {d.extra_params for d in defaults if d.extra_params}
        self._default_referers = {d.referer for d in defaults if d.referer}

        self._apply_portal_defaults()

        # Portrait dashboard header
        title = QLabel("校园网自动连接")
        title.setObjectName("AppTitle")
        subtitle = QLabel("CSU Auto Connect")
        subtitle.setObjectName("Eyebrow")

        header_text = QVBoxLayout()
        header_text.setSpacing(1)
        header_text.addWidget(subtitle)
        header_text.addWidget(title)

        header = QHBoxLayout()
        header.setSpacing(10)
        header.addWidget(self.btn_open_log)
        header.addLayout(header_text, 1)
        header.addWidget(self.btn_theme)

        # Main connection status card
        hero_card = QWidget()
        hero_card.setObjectName("HeroCard")
        hero = QVBoxLayout(hero_card)
        hero.setContentsMargins(20, 18, 20, 18)
        hero.setSpacing(10)

        hero_top = QHBoxLayout()
        hero_top.setSpacing(8)
        hero_top.addWidget(self.lbl_status_dot)
        hero_label = QLabel("当前连接状态")
        hero_label.setObjectName("Muted")
        hero_top.addWidget(hero_label)
        hero_top.addStretch(1)
        hero_top.addWidget(self.lbl_status)
        hero.addLayout(hero_top)
        hero.addWidget(self.lbl_connection_title)
        hero.addWidget(self.lbl_ip_value)

        metrics = QGridLayout()
        metrics.setHorizontalSpacing(16)
        metrics.setVerticalSpacing(4)
        metric_specs = (
            ("网络", self.lbl_network_value),
            ("模式", self.lbl_mode_value),
            ("下次检查", self.lbl_interval_value),
        )
        for column, (label_text, value_label) in enumerate(metric_specs):
            metric_label = QLabel(label_text)
            metric_label.setObjectName("MetricLabel")
            metrics.addWidget(metric_label, 0, column)
            metrics.addWidget(value_label, 1, column)
        metrics.setColumnStretch(0, 1)
        metrics.setColumnStretch(1, 1)
        metrics.setColumnStretch(2, 1)
        hero.addLayout(metrics)

        action_row = QHBoxLayout()
        action_row.setSpacing(12)
        action_row.addWidget(self.btn_test, 1)
        action_row.addWidget(self.btn_probe, 1)

        auto_title = QLabel("自动运行")
        auto_title.setObjectName("SectionTitle")

        def make_switch_row(label_text: str, checkbox: ToggleSwitch) -> QWidget:
            row = QWidget()
            row.setObjectName("ListRow")
            layout = QHBoxLayout(row)
            layout.setContentsMargins(16, 11, 12, 11)
            label = QLabel(label_text)
            label.setObjectName("MetricValue")
            layout.addWidget(label)
            layout.addStretch(1)
            layout.addWidget(checkbox)
            return row

        auto_rows = QVBoxLayout()
        auto_rows.setSpacing(8)
        auto_rows.addWidget(make_switch_row("开机自启", self.chk_autostart))
        auto_rows.addWidget(make_switch_row("启动软件后自动连接", self.chk_connect_on_launch))
        auto_rows.addWidget(make_switch_row("自启时最小化到托盘", self.chk_start_min))

        # Login settings stay collapsed during normal operation.
        self.login_body = QWidget()
        self.login_body.setObjectName("LoginBody")
        login_form = QFormLayout(self.login_body)
        login_form.setContentsMargins(16, 16, 16, 16)
        login_form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
        login_form.setVerticalSpacing(11)
        login_form.addRow("账号", self.ed_user)
        login_form.addRow("密码", self.ed_pass)
        login_form.addRow("网络类型", self.cb_portal)
        login_form.addRow("模式", self.cb_mode)
        login_form.addRow("检查间隔", self.sp_interval)
        self._login_expanded = not bool(cfg.user_account and cfg.user_password)
        self.login_body.setVisible(self._login_expanded)
        self._update_login_toggle()

        latest_card = QWidget()
        latest_card.setObjectName("Card")
        latest = QHBoxLayout(latest_card)
        latest.setContentsMargins(16, 13, 16, 13)
        latest_icon = QLabel("●")
        latest_icon.setStyleSheet("color: #22AD68; font-size: 11px;")
        latest.addWidget(latest_icon, 0, Qt.AlignmentFlag.AlignTop)
        latest.addWidget(self.lbl_latest_event, 1)
        latest.addWidget(self.lbl_latest_time, 0, Qt.AlignmentFlag.AlignTop)

        bottom_actions = QHBoxLayout()
        bottom_actions.setSpacing(8)
        bottom_actions.addWidget(self.btn_save)
        bottom_actions.addWidget(self.btn_toggle, 1)

        page = QWidget()
        page.setObjectName("Page")
        root = QVBoxLayout(page)
        root.setContentsMargins(18, 18, 18, 20)
        root.setSpacing(14)
        root.addLayout(header)
        root.addWidget(hero_card)
        root.addLayout(action_row)
        root.addWidget(auto_title)
        root.addLayout(auto_rows)
        root.addWidget(self.btn_login_toggle)
        root.addWidget(self.login_body)
        root.addWidget(latest_card)
        root.addLayout(bottom_actions)
        root.addStretch(1)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setWidget(page)
        self.setCentralWidget(scroll)

        # Log dialog (hidden by default)
        self.log_dialog = QDialog(self)
        self.log_dialog.setWindowTitle("运行日志")
        self.log_dialog.setMinimumSize(720, 420)
        log_layout = QVBoxLayout(self.log_dialog)
        log_layout.setContentsMargins(16, 16, 16, 16)
        log_layout.setSpacing(12)
        log_title = QLabel("运行日志")
        log_title.setObjectName("SectionTitle")
        log_actions = QHBoxLayout()
        log_actions.addWidget(log_title)
        log_actions.addStretch(1)
        log_actions.addWidget(self.btn_copy_log)
        log_actions.addWidget(self.btn_clear_log)
        log_layout.addLayout(log_actions)
        log_layout.addWidget(self.log_view, 1)
        log_hint = QLabel(f"配置: {self._cfg_path}\n日志: {self._log_path}")
        log_hint.setObjectName("Muted")
        log_hint.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        log_layout.addWidget(log_hint)

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
        self.btn_login_toggle.clicked.connect(self.toggle_login_config)

        self.cb_portal.currentIndexChanged.connect(self.on_portal_type_changed)
        self.cb_mode.currentIndexChanged.connect(self._sync_summary)
        self.sp_interval.valueChanged.connect(self._sync_summary)
        self.chk_autostart.stateChanged.connect(self.on_autostart_changed)
        self.chk_connect_on_launch.stateChanged.connect(self.on_config_changed)
        self.chk_start_min.stateChanged.connect(self.on_autostart_changed)

        self.act_show.triggered.connect(self.show_normal)
        self.act_run_once.triggered.connect(self.on_run_once)
        self.act_open_log.triggered.connect(self.on_open_log)
        self.act_quit.triggered.connect(self.on_quit)

        self.set_theme(cfg.theme, persist=False)
        self._sync_summary()
        self.set_status("待机")

        if start_minimized:
            self.hide()

        QTimer.singleShot(0, self._start_if_configured)

    def _set_status_kind(self, kind: str) -> None:
        for widget in (self.lbl_status, self.lbl_status_dot):
            widget.setProperty("status", kind)
            widget.style().unpolish(widget)
            widget.style().polish(widget)

    def _update_toggle_button(self) -> None:
        if self._running:
            self.btn_toggle.setText("停止服务")
            self.btn_toggle.setObjectName("StopButton")
            self.btn_toggle.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaStop))
        else:
            self.btn_toggle.setText("启动服务")
            self.btn_toggle.setObjectName("PrimaryButton")
            self.btn_toggle.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay))

        # Refresh style after objectName change
        self.btn_toggle.style().unpolish(self.btn_toggle)
        self.btn_toggle.style().polish(self.btn_toggle)

    def _update_login_toggle(self) -> None:
        arrow = "⌃" if self._login_expanded else "⌄"
        self.btn_login_toggle.setText(f"登录配置  {arrow}")

    def toggle_login_config(self) -> None:
        self._login_expanded = not self._login_expanded
        self.login_body.setVisible(self._login_expanded)
        self._update_login_toggle()

    def set_theme(self, mode: str, persist: bool = True) -> None:
        if mode not in ("system", "light", "dark"):
            mode = "system"
        self._theme_mode = mode
        app = QApplication.instance()
        effective = apply_theme(app, mode) if app else mode
        icons = {"system": "◐", "light": "☀", "dark": "☾"}
        labels = {"system": "跟随系统", "light": "浅色", "dark": "深色"}
        self.btn_theme.setText(icons[mode])
        self.btn_theme.setToolTip(f"主题：{labels[mode]}（当前 {effective}）")
        for switch in (self.chk_autostart, self.chk_connect_on_launch, self.chk_start_min):
            switch.update()
        if persist:
            self._save_current_config()

    def _sync_summary(self, *args) -> None:
        portal_text = self.cb_portal.currentText().replace("（", " ").replace("）", "")
        self.lbl_network_value.setText(portal_text)
        self.lbl_mode_value.setText("自动" if self.cb_mode.currentData() == "detect" else "强制")
        self.lbl_interval_value.setText(f"{self.sp_interval.value()} 秒")

    def _set_current_ip(self, ip: str) -> None:
        if ip:
            self.lbl_ip_value.setText(ip)

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
        self.lbl_latest_event.setText(msg)
        self.lbl_latest_time.setText(datetime.now().strftime("%H:%M:%S"))

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
            connect_on_launch=self.chk_connect_on_launch.isChecked(),
            theme=self._theme_mode,
            start_minimized=self.chk_start_min.isChecked(),
        )

    def set_status(self, s: str) -> None:
        self.lbl_status.setText(s)
        kind = self._infer_status_kind(s)
        self._set_status_kind(kind)
        if kind == "online":
            self.lbl_connection_title.setText("已连接")
        elif kind == "error":
            self.lbl_connection_title.setText("连接异常")
        elif kind == "busy":
            self.lbl_connection_title.setText("正在处理")
        elif "停止" in s:
            self.lbl_connection_title.setText("服务已停止")
        elif not self._running and s in ("待机", "就绪"):
            self.lbl_connection_title.setText("等待启动")

    def on_portal_type_changed(self, *args):
        self._apply_portal_defaults()
        self._sync_summary()


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

    def _save_current_config(self, log: bool = False) -> None:
        self._cfg = self.current_cfg()
        save_ini(self._cfg_path, self._cfg)
        if log:
            self.append_log(f"已保存配置: {self._cfg_path}")

    def on_save(self):
        self._save_current_config(log=True)

    def on_config_changed(self):
        self._save_current_config()

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
            self._save_current_config()
            self._logger.info("Autostart updated: enabled=%s start_min=%s", enabled, start_min)
        except Exception as e:
            self.append_log(f"更新自启失败: {e!r}")

    def on_start(self):
        if self._running:
            return

        self._save_current_config()
        self.append_log("后台服务启动")
        self.set_status("启动中...")

        self._thread = QThread()
        self._worker = AutoConnectWorker(self._cfg)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.log.connect(self.append_log)
        self._worker.status.connect(self.set_status)
        self._worker.ip_resolved.connect(self._set_current_ip)
        self._worker.running.connect(self._on_running_changed)
        self._worker.finished.connect(self._thread.quit)
        self._worker.finished.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._thread.deleteLater)
        self._thread.start()

    def _start_if_configured(self) -> None:
        if not self._cfg.connect_on_launch:
            return
        if not self._cfg.user_account or not self._cfg.user_password:
            self.append_log("已启用自动连接，但账号或密码为空")
            return
        self.append_log("已加载保存的配置，自动启动后台服务")
        self.on_start()

    def _on_running_changed(self, running: bool):
        self._running = running
        self._update_toggle_button()
        if not running and self.lbl_status.text() == "停止中...":
            self.set_status("已停止")

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
                "ip": ip,
                "ret_code": res.ret_code,
                "msg": res.msg_decoded or res.msg,
                "raw": res.raw[:300],
                "login_url": redact_login_url(url),
                "mac": wlan_user_mac or "000000000000",
                "result": res.result,
            }

        def on_ok(obj):
            if isinstance(obj, dict) and obj.get("ip"):
                self._set_current_ip(str(obj["ip"]))
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
            if self._oneshot_ok_prefix == "探测结果" and obj:
                self._set_current_ip(str(obj))
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
            self._save_current_config()
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
    apply_app_style(app, cfg.theme)

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
