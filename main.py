#!/usr/bin/env python3
"""Unified entry point for reconnaissance, validation, and reporting."""

import argparse
import asyncio
from typing import Dict

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.table import Table

from core.orchestrator import Orchestrator
from core.logger import logger
from modules.recon.reporting import json_report


def _severity_summary(session) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    findings = getattr(session, "findings", []) or []
    for finding in findings:
        severity = "info"
        if isinstance(finding, dict):
            severity = str(finding.get("severity") or "info").lower()
        else:
            severity = str(getattr(finding, "severity", "info") or "info").lower()
        if severity not in counts:
            severity = "info"
        counts[severity] += 1
    return counts


def _print_final_summary(session) -> None:
    console = Console()
    counts = _severity_summary(session)
    table = Table(title="Final Scan Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")
    table.add_row("Target", str(getattr(session, "target", "")))
    table.add_row("Findings", str(len(getattr(session, "findings", []) or [])))
    table.add_row("Critical", str(counts["critical"]))
    table.add_row("High", str(counts["high"]))
    table.add_row("Medium", str(counts["medium"]))
    table.add_row("Low", str(counts["low"]))
    table.add_row("Info", str(counts["info"]))

    report_paths = getattr(session, "data", {}).get("report_paths", {}) if hasattr(session, "data") else {}
    if isinstance(report_paths, dict):
        table.add_row("HTML Report", str(report_paths.get("html", "n/a")))
        table.add_row("JSON Report", str(report_paths.get("json", "n/a")))
    console.print(table)


def main() -> None:
    parser = argparse.ArgumentParser(description="Unified async vulnerability scanner")
    parser.add_argument("-u", "--url", "--target", dest="target", required=True, help="Target URL or host")
    parser.add_argument("--profile", choices=("auto", "balanced", "aggressive"), default="auto", help="Recon profile selection")
    parser.add_argument("--scope", nargs="*", default=[], help="Allowed domains for scope enforcement")
    parser.add_argument("--output", default="reports", help="Output directory for HTML/JSON reports")
    args = parser.parse_args()

    # Normalize target URL
    target = args.target.strip()
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    fast_mode = args.profile != "aggressive"
    scope_list = []
    if isinstance(args.scope, list):
        for value in args.scope:
            scope_list.extend([s.strip() for s in str(value).split(",") if s.strip()])

    try:
        # Single Progress Manager initialized here
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            transient=True # Hides the bar after completion
        ) as progress:
            # Two Primary Bars
            recon_task = progress.add_task("[cyan]Phase 1: Reconnaissance...", total=100)
            validation_task = progress.add_task("[magenta]Phase 2: Validation...", total=100)
            
            orchestrator = Orchestrator(target=target, fast=fast_mode, scope=scope_list, output_dir=args.output)
            # Pass the single progress bar and task IDs to the orchestrator
            session = asyncio.run(orchestrator.run(progress, recon_task, validation_task))

        report_paths = getattr(session, "data", {}).get("recon_report_paths", {}) if hasattr(session, "data") else {}
        if isinstance(report_paths, dict):
            report_path = report_paths.get("json")
            if isinstance(report_path, str) and report_path:
                json_report.load_into_fact_store(report_path, orchestrator.fact_store)

        _print_final_summary(session)

    except KeyboardInterrupt:
        print("[-] Scan interrupted by user")
        raise SystemExit(130)
    except Exception as exc:
        print(f"[-] Scan failed: {exc}")
        raise SystemExit(1)

if __name__ == "__main__":
    main()
