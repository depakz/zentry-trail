"""Unified logging and live dashboard rendering."""

from __future__ import annotations

import logging
from contextlib import contextmanager
from datetime import datetime
from threading import RLock
import builtins
from typing import Optional

from rich.console import Group
from rich.live import Live
from rich.logging import RichHandler
from rich.progress import BarColumn, Progress, TextColumn
from rich.text import Text


class LiveDashboard:
    """Thread-safe live dashboard with fixed progress bars and scrolling logs."""

    def __init__(self, max_logs: int = 200) -> None:
        self._lock = RLock()
        self._max_logs = max_logs
        self._logs = []
        self._active = False
        self._live: Optional[Live] = None
        self._recon_task_id: Optional[int] = None
        self._validation_task_id: Optional[int] = None
        # Single shared Progress instance for the whole app
        self._progress = Progress(
            TextColumn("{task.description}"),
            BarColumn(bar_width=None),
            TextColumn("{task.percentage:>3.0f}%"),
            TextColumn("{task.fields[detail]}"),
            expand=True,
        )

    def _renderable(self) -> Group:
        # Only render the shared progress at the top; logs are printed via live.console.print()
        return Group(self._progress)

    def start(self) -> None:
        with self._lock:
            if self._active:
                return
            # Recreate the Progress instance each time we start to avoid duplicate task entries
            self._progress = Progress(
                TextColumn("{task.description}"),
                BarColumn(bar_width=None),
                TextColumn("{task.percentage:>3.0f}%"),
                TextColumn("{task.fields[detail]}"),
                expand=True,
            )
            # reset task ids and add two fixed tasks
            self._recon_task_id = self._progress.add_task("Discovery & Recon", total=None, detail="starting")
            self._validation_task_id = self._progress.add_task("Vulnerability Validation", total=None, detail="waiting")

            self._live = Live(self._renderable(), refresh_per_second=10, transient=False)
            self._live.start()
            self._active = True

    def stop(self) -> None:
        with self._lock:
            if not self._active:
                return
            if self._live is not None:
                try:
                    self._live.update(self._renderable(), refresh=True)
                except Exception:
                    pass
                self._live.stop()
            self._active = False

    @contextmanager
    def session(self):
        self.start()
        try:
            yield self
        finally:
            self.stop()

    def log(self, message: str, level: str = "INFO") -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        level_style = {
            "DEBUG": "dim",
            "INFO": "cyan",
            "WARNING": "yellow",
            "ERROR": "bold red",
            "CRITICAL": "bold red",
        }.get(level.upper(), "white")
        entry = Text()
        entry.append(f"[{timestamp}] ", style="dim")
        entry.append(f"{level.upper():<7}", style=level_style)
        entry.append(f" {message}")

        with self._lock:
            # Print via the live console so messages appear below the pinned progress bars
            if self._active and self._live is not None:
                try:
                    self._live.console.print(entry)
                except Exception:
                    # fallback to progress console if available
                    try:
                        self._progress.console.print(entry)
                    except Exception:
                        pass
            else:
                # store minimal history when not active
                self._logs.append(entry)

    def _update_task(self, task_id: Optional[int], completed: int, detail: str) -> None:
        if task_id is None:
            return
        with self._lock:
            if not self._active:
                return
            try:
                self._progress.update(task_id, completed=max(0, min(int(completed), int(self._progress.tasks[task_id].total or 1))), detail=detail)
            except Exception:
                try:
                    self._progress.update(task_id, detail=detail)
                except Exception:
                    pass
            if self._live is not None:
                try:
                    self._live.update(self._renderable(), refresh=True)
                except Exception:
                    pass

    def init_recon(self, total: int) -> None:
        """Set the recon task total based on the number of tools."""
        with self._lock:
            if self._recon_task_id is None:
                self.start()
            try:
                self._progress.update(self._recon_task_id, total=max(1, int(total)), completed=0, detail="initialized")
            except Exception:
                pass

    def advance_recon(self, detail: str = "") -> None:
        with self._lock:
            if not self._active or self._recon_task_id is None:
                return
            try:
                self._progress.advance(self._recon_task_id, 1)
                if detail:
                    self._progress.update(self._recon_task_id, detail=detail)
                if self._live is not None:
                    try:
                        self._live.update(self._renderable(), refresh=True)
                    except Exception:
                        pass
            except Exception:
                pass

    def advance_validation(self, detail: str = "") -> None:
        with self._lock:
            if not self._active or self._validation_task_id is None:
                return
            try:
                self._progress.advance(self._validation_task_id, 1)
                if detail:
                    self._progress.update(self._validation_task_id, detail=detail)
                if self._live is not None:
                    try:
                        self._live.update(self._renderable(), refresh=True)
                    except Exception:
                        pass
            except Exception:
                pass

    def update_recon(self, completed: int, detail: str) -> None:
        self._update_task(self._recon_task_id, completed, detail)

    def update_validation(self, completed: int, detail: str) -> None:
        self._update_task(self._validation_task_id, completed, detail)

    def finish(self) -> None:
        self.update_recon(100, "complete")
        self.update_validation(100, "complete")

    def print_log(self, message: str) -> None:
        """Direct print helper for modules to ensure logs go via live.console.print()."""
        with self._lock:
            if self._active and self._live is not None:
                try:
                    self._live.console.print(message)
                except Exception:
                    try:
                        self._progress.console.print(message)
                    except Exception:
                        pass
            else:
                # store fallback
                try:
                    self._logs.append(Text(str(message)))
                except Exception:
                    pass

    @property
    def active(self) -> bool:
        with self._lock:
            return self._active


class DashboardHandler(logging.Handler):
    """Logging handler that feeds messages into the live dashboard."""

    def __init__(self, dashboard: LiveDashboard, fallback: Optional[logging.Handler] = None) -> None:
        super().__init__()
        self._dashboard = dashboard
        self._fallback = fallback or RichHandler(rich_tracebacks=True, show_time=True, show_path=False)
        self._fallback.setFormatter(logging.Formatter("%(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = self.format(record)
            if self._dashboard.active:
                # print directly to the live console so messages don't create new bars
                try:
                    self._dashboard.print_log(message)
                except Exception:
                    self._fallback.emit(record)
            else:
                self._fallback.emit(record)
        except Exception:
            self.handleError(record)


_existing_dashboard = getattr(builtins, "_yuva_dashboard", None)
if _existing_dashboard is not None and all(
    hasattr(_existing_dashboard, attr)
    for attr in ("start", "stop", "print_log", "advance_recon", "advance_validation", "update_recon", "update_validation")
):
    dashboard = _existing_dashboard
else:
    dashboard = LiveDashboard()
    try:
        setattr(builtins, "_yuva_dashboard", dashboard)
    except Exception:
        pass


def setup_logger(name: str = "yuva", level: int = logging.INFO) -> logging.Logger:
    log = logging.getLogger(name)
    if log.handlers:
        return log

    log.setLevel(level)
    handler = DashboardHandler(dashboard)
    handler.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(handler)
    log.propagate = False
    return log


logger = setup_logger()
