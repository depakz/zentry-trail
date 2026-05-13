#!/usr/bin/env python3
"""Unified entry point for reconnaissance, validation, and reporting."""

import argparse
import asyncio
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from core.orchestrator import Orchestrator
from core.logger import logger

def main() -> None:
    parser = argparse.ArgumentParser(description="Unified async vulnerability scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL or host")
    parser.add_argument("--profile", choices=("auto", "balanced", "aggressive"), default="auto", help="Recon profile selection")
    args = parser.parse_args()

    # Normalize target URL
    target = args.url.strip()
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    fast_mode = args.profile != "aggressive"

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
            
            orchestrator = Orchestrator(target=target, fast=fast_mode)
            # Pass the single progress bar and task IDs to the orchestrator
            asyncio.run(orchestrator.run(progress, recon_task, validation_task))

    except KeyboardInterrupt:
        print("[-] Scan interrupted by user")
        raise SystemExit(130)
    except Exception as exc:
        print(f"[-] Scan failed: {exc}")
        raise SystemExit(1)

if __name__ == "__main__":
    main()
