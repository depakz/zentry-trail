#!/usr/bin/env python3
"""
scripts/label_findings.py — Session 9

CLI tool to label scan findings as false positives in OutcomeDB.
This allows the GNN fine-tuner to down-weight similar node types in
future scans.

Usage:
    python scripts/label_findings.py --scan-id SCAN_ID --finding-id FINDING_ID --label fp
    python scripts/label_findings.py --list --scan-id SCAN_ID
    python scripts/label_findings.py --stats --scan-id SCAN_ID
"""

import argparse
import sqlite3
import sys
import time
from pathlib import Path


DEFAULT_DB = "data/outcomes.db"


def label_false_positive(db_path: str, scan_id: str, finding_id: str) -> None:
    """Mark a finding as a false positive in the database."""
    if not Path(db_path).exists():
        print(f"[ERROR] Database not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    with sqlite3.connect(db_path) as conn:
        # Check if finding exists
        row = conn.execute(
            "SELECT finding_id, vuln_class, endpoint_url, confirmed FROM findings "
            "WHERE finding_id = ? AND scan_id = ?",
            (finding_id, scan_id),
        ).fetchone()

        if row is None:
            print(f"[ERROR] Finding '{finding_id}' not found in scan '{scan_id}'", file=sys.stderr)
            sys.exit(1)

        conn.execute(
            "UPDATE findings SET confirmed = 0 WHERE finding_id = ? AND scan_id = ?",
            (finding_id, scan_id),
        )
        conn.execute(
            "UPDATE scans SET false_positive_count = false_positive_count + 1 "
            "WHERE scan_id = ?",
            (scan_id,),
        )
        conn.commit()

    print(f"[✓] Finding '{finding_id}' ({row[1]} @ {row[2]}) labelled as FALSE POSITIVE")
    print(f"    GNN fine-tuner will down-weight similar nodes in future scans.")


def list_findings(db_path: str, scan_id: str) -> None:
    """List all findings for a scan."""
    if not Path(db_path).exists():
        print(f"[ERROR] Database not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT finding_id, vuln_class, endpoint_url, confidence, confirmed "
            "FROM findings WHERE scan_id = ? ORDER BY confidence DESC",
            (scan_id,),
        ).fetchall()

    if not rows:
        print(f"No findings found for scan '{scan_id}'")
        return

    print(f"\nFindings for scan: {scan_id}")
    print(f"{'ID':<36}  {'Class':<20}  {'Conf':>5}  {'Status':<12}  URL")
    print("-" * 100)
    for finding_id, vuln_class, url, conf, confirmed in rows:
        if confirmed is None:
            status = "unknown"
        elif confirmed == 1:
            status = "confirmed"
        elif confirmed == 0:
            status = "false_pos"
        else:
            status = str(confirmed)
        conf_str = f"{conf:.2f}" if conf is not None else "n/a"
        url_short = (url or "")[:50]
        print(f"{finding_id:<36}  {(vuln_class or ''):<20}  {conf_str:>5}  {status:<12}  {url_short}")


def print_stats(db_path: str, scan_id: str) -> None:
    """Print win-rate statistics for attack strategies."""
    if not Path(db_path).exists():
        print(f"[ERROR] Database not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    with sqlite3.connect(db_path) as conn:
        # Scan summary
        scan = conn.execute(
            "SELECT target, started_at, finding_count, false_positive_count "
            "FROM scans WHERE scan_id = ?",
            (scan_id,),
        ).fetchone()

        if scan:
            target, started_at, fc, fpc = scan
            started_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(started_at)) if started_at else "n/a"
            print(f"\nScan: {scan_id}")
            print(f"  Target:          {target}")
            print(f"  Started:         {started_str}")
            print(f"  Findings:        {fc or 0}")
            print(f"  False positives: {fpc or 0}")

        # Win-rate stats (if table exists)
        try:
            rows = conn.execute(
                "SELECT strategy_id, tech_stack, waf_provider, attempts, successes "
                "FROM attack_win_rates ORDER BY successes DESC LIMIT 20"
            ).fetchall()
            if rows:
                print(f"\n{'Strategy':<30}  {'Tech':<15}  {'WAF':<15}  {'Win Rate':>10}  Attempts")
                print("-" * 85)
                for strategy_id, tech, waf, attempts, successes in rows:
                    rate = (successes / attempts * 100) if attempts else 0
                    print(f"{(strategy_id or ''):<30}  {(tech or 'any'):<15}  {(waf or 'any'):<15}  {rate:>9.1f}%  {attempts}")
        except sqlite3.OperationalError:
            pass  # Table doesn't exist yet


def main() -> None:
    parser = argparse.ArgumentParser(
        description="zentry-trail — label findings and view scan statistics",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Label a finding as a false positive
  python scripts/label_findings.py --scan-id abc123 --finding-id f456 --label fp

  # List all findings for a scan
  python scripts/label_findings.py --list --scan-id abc123

  # Show win-rate statistics
  python scripts/label_findings.py --stats --scan-id abc123
""",
    )
    parser.add_argument("--scan-id",    required=True, help="Scan ID to operate on")
    parser.add_argument("--finding-id", help="Finding ID to label (required with --label)")
    parser.add_argument("--label",      choices=["fp"], help="Label type: 'fp' = false positive")
    parser.add_argument("--list",       action="store_true", help="List findings for the scan")
    parser.add_argument("--stats",      action="store_true", help="Show attack win-rate statistics")
    parser.add_argument("--db",         default=DEFAULT_DB, help=f"Path to outcomes.db (default: {DEFAULT_DB})")

    args = parser.parse_args()

    if args.label:
        if not args.finding_id:
            parser.error("--finding-id is required when using --label")
        label_false_positive(args.db, args.scan_id, args.finding_id)
    elif args.list:
        list_findings(args.db, args.scan_id)
    elif args.stats:
        print_stats(args.db, args.scan_id)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
