"""
zentry/reporting/pdf_reporter.py — PDF report generator.

Re-exports PDFReporter from the unified reporters module.
"""

from .reporters import PDFReporter  # noqa: F401

__all__ = ["PDFReporter"]
