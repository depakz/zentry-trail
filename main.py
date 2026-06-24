#!/usr/bin/env python3
"""Unified entry point for reconnaissance, validation, and reporting."""

import argparse
import asyncio
from typing import Any, Dict

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.table import Table

from zentry.recon.orchestrator import ReconOrchestrator
from zentry.reporting.json_reporter import JSONReporter
from zentry.session import ScanSession


def _severity_summary(session: ScanSession) -> Dict[str, int]:
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


def _print_final_summary(session: ScanSession) -> None:
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

    report_paths = session.data.get("report_paths", {})
    if isinstance(report_paths, dict):
        table.add_row("HTML Report", str(report_paths.get("html", "n/a")))
        table.add_row("JSON Report", str(report_paths.get("json", "n/a")))
    console.print(table)


def main() -> None:
    parser = argparse.ArgumentParser(description="Unified async vulnerability scanner")
    parser.add_argument("-u", "--url", "--target", dest="target", required=False, default=None, help="Target URL or host")
    parser.add_argument("--fast", action="store_true", help="Fast mode (skips some deep recon steps)")
    parser.add_argument("--scope", nargs="*", default=[], help="Allowed domains for scope enforcement")
    parser.add_argument("--output", default="reports", help="Output directory for HTML/JSON reports")
    # ── Authentication flags ───────────────────────────────────────────
    parser.add_argument("--auth",       default=None, help="Authenticated credentials (username:password)")
    parser.add_argument("--auth2",      default=None, help="Second user credentials (username:password)")
    parser.add_argument("--auth-url",   default=None, help="Login URL (e.g. http://target/login)")
    parser.add_argument("--auth-user",  default=None, help="Username to authenticate with")
    parser.add_argument("--auth-pass",  default=None, help="Password to authenticate with")
    parser.add_argument("--no-auth",    action="store_true",  help="Disable pre-scan authentication attempt")
    # ── False-positive labelling (Session 9 / 10) ──────────────────────────
    parser.add_argument("--label-fp",   nargs=2, metavar=("SCAN_ID", "FINDING_ID"),
                        help="Label a finding as a false positive: --label-fp SCAN_ID FINDING_ID")
    args = parser.parse_args()

    # ── False-positive labelling (no scan needed) ─────────────────────────
    if args.label_fp:
        scan_id, finding_id = args.label_fp
        from scripts.label_findings import label_false_positive
        label_false_positive("data/outcomes.db", scan_id, finding_id)
        return

    if not args.target:
        parser.error("--url / -u is required unless using --label-fp")

    # Normalize target URL
    target = args.target.strip()
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    fast_mode = args.fast
    scope_list = []
    if isinstance(args.scope, list):
        for value in args.scope:
            scope_list.extend([s.strip() for s in str(value).split(",") if s.strip()])

    try:
        # Build custom credential profile if user supplied auth flags
        custom_creds: Optional[Dict[str, str]] = None
        custom_creds2: Optional[Dict[str, str]] = None
        if not getattr(args, "no_auth", False):
            if getattr(args, "auth", None):
                parts = args.auth.split(":", 1)
                if len(parts) == 2:
                    custom_creds = {"username": parts[0], "password": parts[1]}
            elif args.auth_user and args.auth_pass:
                custom_creds = {"username": args.auth_user, "password": args.auth_pass}

            if getattr(args, "auth2", None):
                parts2 = args.auth2.split(":", 1)
                if len(parts2) == 2:
                    custom_creds2 = {"username": parts2[0], "password": parts2[1]}

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

            recon_orchestrator = ReconOrchestrator(target=target, fast=fast_mode, scope=scope_list, output_dir=args.output)

            # Override credential profiles if user supplied --auth-* flags
            if custom_creds or custom_creds2:
                from zentry.auth.manager import AuthManager
                recon_orchestrator.auth_manager = AuthManager(target=target, credentials=custom_creds)
                if custom_creds2:
                    recon_orchestrator.auth_manager.credentials2 = custom_creds2

            # Pass the single progress bar and task IDs to the orchestrator
            session = asyncio.run(recon_orchestrator.run(progress, recon_task, validation_task))

        report_paths = session.data.get("recon_report_paths", {})
        if isinstance(report_paths, dict):
            report_path = report_paths.get("json")
            if isinstance(report_path, str) and report_path:
                JSONReporter.load_into_fact_store(report_path, recon_orchestrator.fact_store)

        _print_final_summary(session)

    except KeyboardInterrupt:
        print("[-] Scan interrupted by user")
        raise SystemExit(130)
    except Exception as exc:
        print(f"[-] Scan failed: {exc}")
        raise SystemExit(1)

if __name__ == "__main__":
    main()
