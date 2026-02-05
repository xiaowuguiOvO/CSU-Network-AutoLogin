from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class Config:
    user_account: str = ""
    user_password: str = ""
    interval_sec: int = 5
    mode: str = "detect"  # always | detect
    portal_type: str = "lab"  # lab | telecom | unicom | mobile | campus
    portal_probe_url: str = ""
    portal_login_url: str = ""
    portal_js_version: str = ""
    portal_extra_params: str = ""
    portal_referer: str = ""
    autostart: bool = True
    # Show the window on first run; user can enable "start minimized" later.
    start_minimized: bool = False


def load_ini(path: Path) -> Config:
    cfg = Config()
    if not path.exists():
        return cfg

    try:
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line:
                continue
            if line.startswith("#") or line.startswith(";"):
                continue
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            key = k.strip()
            val = v.strip()

            if key == "UserAccount":
                cfg.user_account = val
            elif key == "UserPassword":
                cfg.user_password = val
            elif key == "IntervalSec":
                try:
                    cfg.interval_sec = max(5, int(val))
                except ValueError:
                    pass
            elif key == "Mode":
                if val in ("always", "detect"):
                    cfg.mode = val
            elif key == "PortalType":
                if val in ("lab", "telecom", "unicom", "mobile", "campus"):
                    cfg.portal_type = val
            elif key == "PortalProbeUrl":
                if val:
                    cfg.portal_probe_url = val
            elif key == "PortalLoginUrl":
                if val:
                    cfg.portal_login_url = val
            elif key == "PortalJsVersion":
                if val:
                    cfg.portal_js_version = val
            elif key == "PortalExtraParams":
                cfg.portal_extra_params = val
            elif key == "PortalReferer":
                if val:
                    cfg.portal_referer = val
            elif key == "AutoStart":
                cfg.autostart = val.lower() in ("1", "true", "yes", "on")
            elif key == "StartMinimized":
                cfg.start_minimized = val.lower() in ("1", "true", "yes", "on")
    except OSError:
        return cfg

    return cfg


def save_ini(path: Path, cfg: Config) -> None:
    lines = [
        "# CSU Auto Connect Config",
        f"UserAccount={cfg.user_account}",
        f"UserPassword={cfg.user_password}",
        f"IntervalSec={cfg.interval_sec}",
        f"Mode={cfg.mode}",
        f"PortalType={cfg.portal_type}",
        f"PortalProbeUrl={cfg.portal_probe_url}",
        f"PortalLoginUrl={cfg.portal_login_url}",
        f"PortalJsVersion={cfg.portal_js_version}",
        f"PortalExtraParams={cfg.portal_extra_params}",
        f"PortalReferer={cfg.portal_referer}",
        f"AutoStart={'true' if cfg.autostart else 'false'}",
        f"StartMinimized={'true' if cfg.start_minimized else 'false'}",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
