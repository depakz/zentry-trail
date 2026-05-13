import logging
import os
import sys
from typing import Optional

from core.logger import dashboard


class DashboardLogHandler(logging.Handler):
    """Logging handler that forwards messages to the central dashboard."""

    def __init__(self) -> None:
        super().__init__()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = self.format(record)
            if dashboard and getattr(dashboard, "active", False):
                try:
                    dashboard.print_log(message)
                except Exception:
                    # fallback to stderr
                    sys.stderr.write(message + "\n")
            else:
                sys.stderr.write(message + "\n")
        except Exception:
            pass


def setup_logger():
    os.makedirs("output", exist_ok=True)

    log = logging.getLogger("security_pipeline")
    log.setLevel(logging.INFO)

    # Avoid duplicate handlers if this module is imported multiple times.
    if log.handlers:
        return log

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    file_handler = logging.FileHandler("output/engine.log")
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)

    dashboard_handler = DashboardLogHandler()
    dashboard_handler.setLevel(logging.INFO)
    dashboard_handler.setFormatter(formatter)

    log.addHandler(file_handler)
    log.addHandler(dashboard_handler)
    log.propagate = False

    return log


logger = setup_logger()
