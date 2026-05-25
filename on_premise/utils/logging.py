"""Structured logger for On-Premise service."""

import logging
import os


def _build_logger() -> logging.Logger:
    _logger = logging.getLogger("on_premise")
    _logger.propagate = False
    _logger.setLevel(logging.DEBUG)

    log_dir = os.path.join(os.path.normpath(os.getcwd()), "logs")
    os.makedirs(log_dir, exist_ok=True)

    log_fname = os.path.join(log_dir, os.getenv("LOG_FILE_NAME", "on_premise.log"))
    formatter = logging.Formatter(
        "%(levelname)s | %(asctime)s | %(filename)s:%(lineno)d | %(funcName)s | %(message)s"
    )

    file_handler = logging.FileHandler(log_fname)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(formatter)

    if _logger.hasHandlers():
        _logger.handlers.clear()

    _logger.addHandler(file_handler)
    _logger.addHandler(stream_handler)
    return _logger


logger = _build_logger()

