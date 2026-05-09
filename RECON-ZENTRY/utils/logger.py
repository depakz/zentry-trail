"""Centralized logger using Rich."""
import logging
from rich.logging import RichHandler

_LOGGERS: dict[str, logging.Logger] = {}

def get_logger(name: str = "hwy", level: int = logging.INFO) -> logging.Logger:
    if name in _LOGGERS:
        return _LOGGERS[name]
    logger = logging.getLogger(name)
    logger.setLevel(level)
    if not logger.handlers:
        handler = RichHandler(rich_tracebacks=True, show_path=False, markup=True)
        handler.setFormatter(logging.Formatter("%(message)s", datefmt="[%X]"))
        logger.addHandler(handler)
    logger.propagate = False
    _LOGGERS[name] = logger
    return logger
