from __future__ import annotations

import logging
from pathlib import Path


def configure_logging() -> logging.Logger:
    log_directory = Path("logs")
    log_directory.mkdir(exist_ok=True)
    logger = logging.getLogger("jarvis")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.FileHandler(log_directory / "jarvis.log", encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
        logger.addHandler(handler)
    return logger
