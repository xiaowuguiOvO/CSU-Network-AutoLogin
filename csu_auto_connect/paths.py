from __future__ import annotations

import os
import sys
from pathlib import Path


def app_dir() -> Path:
    """
    Directory used to store config/logs.

    Preference order:
    1) Next to executable (portable usage)
    2) %APPDATA%\\CSUAutoConnect (fallback)
    """
    frozen = getattr(sys, "frozen", False)
    if frozen:
        base = Path(sys.executable).resolve().parent
    else:
        # project root (../.. from this file)
        base = Path(__file__).resolve().parents[1]

    cfg = base / "config.ini"

    # Portable mode:
    # - Frozen: default to next to the exe if writable.
    # - Source: only use project root when user explicitly created config.ini
    if base.exists() and cfg.exists():
        return base
    if frozen and base.exists() and os.access(str(base), os.W_OK):
        return base

    appdata = os.environ.get("APPDATA")
    if appdata:
        d = Path(appdata) / "CSUAutoConnect"
        d.mkdir(parents=True, exist_ok=True)
        return d

    d = Path.home() / ".csu_auto_connect"
    d.mkdir(parents=True, exist_ok=True)
    return d


def config_path() -> Path:
    return app_dir() / "config.ini"


def log_path() -> Path:
    return app_dir() / "csu_auto_connect.log"
