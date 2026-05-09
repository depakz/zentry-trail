"""Unified logging"""
import logging
from rich.logging import RichHandler

def setup_logger(name="yuva", level=logging.INFO):
    log = logging.getLogger(name)
    if log.handlers:
        return log
    log.setLevel(level)
    handler = RichHandler(rich_tracebacks=True, show_time=True, show_path=False)
    handler.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(handler)
    return log

logger = setup_logger()
