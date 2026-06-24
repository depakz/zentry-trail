"""
zentry/reporting/html_reporter.py — HTML report generator.

Facade class wrapping the html_* functions from reporters.py.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .reporters import html_build_report, html_write


class HTMLReporter:
    """HTML Report Generator class."""

    def build_report(self, session: Any, report_payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return html_build_report(session, report_payload=report_payload)

    def write(self, session: Any, out_dir: str = "reports", report_payload: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
        return html_write(session, out_dir=out_dir, report_payload=report_payload)
