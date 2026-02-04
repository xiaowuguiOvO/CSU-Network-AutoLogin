from __future__ import annotations

import threading

import requests
from PySide6.QtCore import QObject, Signal, Slot

from .config import Config
from .portal import build_login_url, login_once, probe_wlan_user_ip, test_internet


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
                    # If internet already works, don't keep hitting the portal.
                    if test_internet(self._session, timeout_sec=3.0):
                        self.status.emit("在线")
                        self._stop.wait(interval)
                        continue

                    self.status.emit("探测 IP...")
                    ip = probe_wlan_user_ip(self._session, cfg.portal_probe_url, timeout_sec=3.0)
                    if not ip:
                        self.log.emit("未探测到 wlan_user_ip，等待重试")
                        self.status.emit("未探测到 IP")
                        self._stop.wait(interval)
                        continue

                    self.log.emit(f"wlan_user_ip={ip}")
                    self.status.emit("登录中...")
                    url = build_login_url(cfg.user_account, cfg.user_password, ip)
                    res = login_once(self._session, url, timeout_sec=8.0)
                    if res.ok:
                        self.log.emit("认证成功")
                        self.status.emit("已认证")
                    else:
                        # Many portals return non-success codes even if you're already online.
                        if test_internet(self._session, timeout_sec=3.0):
                            self.log.emit("已在线（无需重复认证）")
                            self.status.emit("在线")
                        else:
                            extra = ""
                            if res.ret_code is not None:
                                extra += f" ret_code={res.ret_code}"
                            if res.msg_decoded:
                                extra += f" msg={res.msg_decoded}"
                            self.log.emit(f"认证失败{extra}")
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
