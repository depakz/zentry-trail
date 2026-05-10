#!/usr/bin/env python3
import argparse
import asyncio
import os
import sys
import time
import json
from datetime import datetime, timezone

# Ensure the root directory is in the path to support module imports
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Prepend ~/bin to PATH so that projectdiscovery tools (subfinder, httpx, etc.) take precedence
os.environ["PATH"] = os.path.expanduser("~/bin") + os.pathsep + os.environ.get("PATH", "")

from modules.pipeline.integrations.recon_zentry_adapter import run_recon_zentry
from modules.pipeline.brain.dag_engine_enhanced import DAGBrain, ConcurrentValidationEngine
from modules.pipeline.main import build_validation_state, save_final_reports, _extract_pipeline_validation_records

def main():
    parser = argparse.ArgumentParser(description="Unified Master CLI for Recon and Vulnerability Validation Pipeline")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., https://example.com)")
    args = parser.parse_args()

    target = args.url
    print("=" * 60)
    print(f"[*] Starting Unified Scan against: {target}")
    print("=" * 60)

    # =========================================================================
    # Phase 1: Reconnaissance (Subdomains, Endpoints, initial scanning)
    # =========================================================================
    print("\n[*] Phase 1: Reconnaissance")
    scan_start = time.time()
    scan_time = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    try:
        # run_recon_zentry will automatically leverage the modules/recon logic
        parsed_data = asyncio.run(run_recon_zentry(target))
        parsed_data.setdefault("scan_info", {})["duration_seconds"] = int(time.time() - scan_start)
    except Exception as e:
        print(f"[-] Reconnaissance failed: {e}")
        sys.exit(1)

    subdomains = parsed_data.get("subdomains", [])
    endpoints = parsed_data.get("endpoints", [])
    print(f"[+] Found {len(subdomains)} subdomains.")
    print(f"[+] Found {len(endpoints)} endpoints.")

    # =========================================================================
    # Phase 2: Vulnerability Validation (DAG Engine)
    # =========================================================================
    print("\n[*] Phase 2: Pipeline DAG Engine Validation")
    pipeline_result = {}
    try:
        # Transform recon state for the Pipeline DAG
        state = build_validation_state(parsed_data)
        
        # Initialize brain and concurrent engine
        dag_brain = DAGBrain(use_graph_engine=True)
        concurrent_engine = ConcurrentValidationEngine(dag_brain=dag_brain, state=state, max_workers=20)
        
        # Run validation engine
        pipeline_result = asyncio.run(concurrent_engine.run_pipeline())
        
        edges_executed = len(pipeline_result.get("results", []))
        print(f"[+] Validation completed. Executed {edges_executed} edges in DAG.")
    except Exception as e:
        print(f"[-] DAG Engine Validation failed: {e}")

    # =========================================================================
    # Phase 3: Reporting
    # =========================================================================
    print("\n[*] Phase 3: Generating Final Report")
    try:
        final_report_file, confirmed_report_file = save_final_reports(
            target=target,
            scan_time=scan_time,
            parsed_data=parsed_data,
            actions=[],
            results=[],
            pipeline_validation_results=_extract_pipeline_validation_records(pipeline_result)
        )
        print(f"[+] Consolidated Final Report: {final_report_file}")
        print(f"[+] Confirmed Vulnerabilities: {confirmed_report_file}")
    except Exception as e:
        print(f"[-] Reporting failed: {e}")

    print("\n" + "=" * 60)
    print("[*] Unified Scan Completed")
    print("=" * 60 + "\n")

if __name__ == "__main__":
    main()
