from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class Config:
    user_account: str = ""
    user_password: str = ""
    interval_sec: int = 30
    mode: str = "always"  # always | detect
    portal_probe_url: str = "http://10.255.254.11/"
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
            elif key == "PortalProbeUrl":
                if val:
                    cfg.portal_probe_url = val
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
        f"PortalProbeUrl={cfg.portal_probe_url}",
        f"AutoStart={'true' if cfg.autostart else 'false'}",
        f"StartMinimized={'true' if cfg.start_minimized else 'false'}",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
