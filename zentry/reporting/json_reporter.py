"""
zentry/reporting/json_reporter.py — JSON report generator.

Facade class wrapping the json_* functions from reporters.py.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .reporters import (
    json_build_report,
    json_write,
    ingest_report,
    load_into_fact_store,
    check_juice_shop_error,
)


class JSONReporter:
    """JSON Report Generator class with static-method API for backward compat."""

    @staticmethod
    def build_report(session: Any, report_payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return json_build_report(session, report_payload=report_payload)

    @staticmethod
    def write(session: Any, out_dir: str = "reports", report_payload: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
        return json_write(session, out_dir=out_dir, report_payload=report_payload)

    @staticmethod
    def ingest_report(report: Dict[str, Any], fact_store) -> int:
        return ingest_report(report, fact_store)

    @staticmethod
    def load_into_fact_store(report_path: str, fact_store) -> int:
        return load_into_fact_store(report_path, fact_store)

    @staticmethod
    def check_juice_shop_error(response_text: object) -> bool:
        return check_juice_shop_error(response_text)
