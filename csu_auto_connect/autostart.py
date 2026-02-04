from __future__ import annotations

import os
import sys
from pathlib import Path


def _run_command(start_minimized: bool) -> str:
    exe = Path(sys.executable).resolve()
    if start_minimized:
        return f'"{exe}" --start-minimized'
    return f'"{exe}"'


def set_autostart(enabled: bool, start_minimized: bool = True, name: str = "CSU Auto Connect") -> None:
    """
    Enable/disable autostart for current user.
    Uses HKCU\\...\\Run (no admin required).
    """
    if os.name != "nt":
        return

    import winreg

    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
        if enabled:
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, _run_command(start_minimized))
        else:
            try:
                winreg.DeleteValue(key, name)
            except FileNotFoundError:
                pass


def is_autostart_enabled(name: str = "CSU Auto Connect") -> bool:
    if os.name != "nt":
        return False
    import winreg

    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
            winreg.QueryValueEx(key, name)
            return True
    except FileNotFoundError:
        return False
    except OSError:
        return False

