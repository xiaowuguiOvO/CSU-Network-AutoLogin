from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


def setup_logging(path: Path) -> logging.Logger:
    logger = logging.getLogger("csu_auto_connect")
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        path.parent.mkdir(parents=True, exist_ok=True)
        fh = RotatingFileHandler(path, maxBytes=1024 * 1024, backupCount=3, encoding="utf-8")
        fmt = logging.Formatter("[%(asctime)s][%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
        logger.propagate = False

    return logger

