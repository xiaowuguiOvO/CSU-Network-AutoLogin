from __future__ import annotations

import threading

import requests
from urllib.parse import urlparse
from PySide6.QtCore import QObject, Signal, Slot

from .config import Config
from .portal import (
    build_login_url,
    build_login_url_v4,
    get_portal_defaults,
    login_once,
    normalize_user_account,
    probe_ipconfig_ipv4,
    probe_ipconfig_wlan_mac,
    probe_wlan_user_ip,
    redact_login_url,
    test_internet,
)


def _resolve_portal_settings(cfg: Config):
    defaults = get_portal_defaults(cfg.portal_type)
    probe_url = cfg.portal_probe_url or defaults.probe_url
    login_url = cfg.portal_login_url or defaults.login_url
    js_version = cfg.portal_js_version or defaults.js_version
    extra_params = cfg.portal_extra_params or defaults.extra_params
    referer = cfg.portal_referer or defaults.referer
    return defaults, probe_url, login_url, js_version, extra_params, referer


class AutoConnectWorker(QObject):
    log = Signal(str)
    status = Signal(str)
    running = Signal(bool)
    finished = Signal()

    def __init__(self, cfg: Config):
        super().__init__()
        self._cfg = cfg
        self._stop = threading.Event()
        self._session = requests.Session()

    def update_config(self, cfg: Config) -> None:
        self._cfg = cfg

    def stop(self) -> None:
        self._stop.set()

    @Slot()
    def run(self) -> None:
        self.running.emit(True)
        try:
            while not self._stop.is_set():
                cfg = self._cfg
                interval = max(5, int(cfg.interval_sec))

                try:
                    verbose = cfg.mode != "detect"

                    def _log(msg: str, force: bool = False) -> None:
                        if verbose or force:
                            self.log.emit(msg)

                    if cfg.mode == "detect":
                        # In detect mode, skip login if already online.
                        if test_internet(self._session, timeout_sec=3.0):
                            self.status.emit("在线")
                            self._stop.wait(interval)
                            continue
                        _log("断网，尝试重连", force=True)

                    self.status.emit("探测 IP...")
                    defaults, probe_url, login_url, js_version, extra_params, referer = _resolve_portal_settings(cfg)
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
                            self._session,
                            probe_url,
                            timeout_sec=3.0,
                            fallback_host=fallback_host,
                            allow_private=defaults.login_style != "lab",
                            only_status=only_status,
                        )
                    if not ip:
                        _log("未探测到 wlan_user_ip，等待重试", force=True)
                        self.status.emit("未探测到 IP")
                        self._stop.wait(interval)
                        continue

                    _log(f"wlan_user_ip={ip}")
                    self.status.emit("登录中...")
                    if defaults.login_style == "lab":
                        url = build_login_url(
                            normalize_user_account(cfg.user_account, cfg.portal_type),
                            cfg.user_password,
                            ip,
                            js_version=js_version or "3.3.1",
                        )
                    else:
                        if not login_url:
                            _log("未配置 PortalLoginUrl，无法登录", force=True)
                            self.status.emit("未配置登录地址")
                            self._stop.wait(interval)
                            continue
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
                    res = login_once(self._session, url, timeout_sec=8.0, referer=referer or None)
                    if res.ok:
                        _log("已重连", force=True)
                        self.status.emit("已认证")
                    else:
                        # Many portals return non-success codes even if you're already online.
                        if test_internet(self._session, timeout_sec=3.0):
                            _log("已重连", force=True)
                            self.status.emit("在线")
                        else:
                            extra = ""
                            if res.ret_code is not None:
                                extra += f" ret_code={res.ret_code}"
                            if res.msg_decoded:
                                extra += f" msg={res.msg_decoded}"
                            _log(f"认证失败{extra}", force=True)
                            self.status.emit("认证失败")

                except Exception as e:
                    self.log.emit(f"异常: {e!r}")
                    self.status.emit("异常")

                self._stop.wait(interval)
        finally:
            self.running.emit(False)
            self.finished.emit()


class OneShotWorker(QObject):
    finished = Signal(object)
    error = Signal(str)

    def __init__(self, fn):
        super().__init__()
        self._fn = fn

    @Slot()
    def run(self) -> None:
        try:
            out = self._fn()
            self.finished.emit(out)
        except Exception as e:
            self.error.emit(str(e))
