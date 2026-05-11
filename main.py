#!/usr/bin/env python3
"""Unified entry point for reconnaissance, DAG validation, and reporting."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import textwrap
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import httpx


REPO_ROOT = Path(__file__).resolve().parent
OUTPUT_DIR = REPO_ROOT / "output"
HTML_REPORT_PATH = OUTPUT_DIR / "final_report.html"
PDF_REPORT_PATH = OUTPUT_DIR / "final_report.pdf"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

bin_dir = REPO_ROOT / "bin"
if bin_dir.exists():
    os.environ["PATH"] = f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}"

from core.logger import dashboard, logger
from modules.pipeline.brain.dag_engine_enhanced import ConcurrentValidationEngine, DAGBrain
from modules.pipeline.brain.fact_store import FactStore
from modules.pipeline.integrations.recon_zentry_adapter import run_recon_zentry
from modules.pipeline.main import (  # type: ignore
    _extract_pipeline_validation_records,
    build_validation_state,
    save_final_reports,
)


DEFAULT_TIMEOUT = httpx.Timeout(15.0, connect=5.0)
DEFAULT_HEADERS = {
    "User-Agent": "zentry-unified-scanner/1.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.8",
}


def _ensure_output_dir() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def _normalize_target(target: str) -> str:
  value = (target or "").strip()
  if value.startswith(("http://", "https://")):
    return value.rstrip("/")
  return f"https://{value.lstrip('/')}".rstrip("/")


def _select_scan_profile(target: str, requested: str) -> str:
        profile = (requested or "auto").strip().lower()
        if profile in {"balanced", "aggressive"}:
                return profile

        normalized = _normalize_target(target)
        suffix = normalized.removeprefix("https://").removeprefix("http://")
        if "/" in suffix or "?" in suffix or "#" in suffix:
                return "balanced"
        return "aggressive"


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def _html_escape(value: Any) -> str:
    text = "" if value is None else str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _render_list(items: Iterable[Any]) -> str:
    rows = []
    for item in items:
        rows.append(f"<li>{_html_escape(item)}</li>")
    return "".join(rows) if rows else "<li>None</li>"


def _render_coverage_table(coverage: Dict[str, Any]) -> str:
    categories = coverage.get("categories", []) if isinstance(coverage, dict) else []
    rows = []
    for category in categories:
        if not isinstance(category, dict):
            continue
        tested = ", ".join(category.get("tested_subcases", []) or []) or "None"
        untested = ", ".join(category.get("untested_subcases", []) or []) or "None"
        rows.append(
            "<tr>"
            f"<td>{_html_escape(category.get('owasp_category', ''))}</td>"
            f"<td>{_html_escape(category.get('coverage_percent', 0))}%</td>"
            f"<td>{_html_escape(tested)}</td>"
            f"<td>{_html_escape(untested)}</td>"
            "</tr>"
        )

    header = (
        "<tr>"
        "<th>Category</th>"
        "<th>Coverage</th>"
        "<th>Tested Subcases</th>"
        "<th>Untested Subcases</th>"
        "</tr>"
    )
    return header + "".join(rows)


def _build_html_report(report: Dict[str, Any]) -> str:
    summary = report.get("summary", {}) if isinstance(report, dict) else {}
    coverage = report.get("owasp_depth_coverage", {}) if isinstance(report, dict) else {}
    compliance = report.get("compliance_overview", {}) if isinstance(report, dict) else {}
    confirmed = report.get("confirmed_vulnerabilities", []) if isinstance(report, dict) else []
    potential = report.get("potential_findings", []) if isinstance(report, dict) else []

    owasp = coverage.get("summary", {}) if isinstance(coverage, dict) else {}
    compliance_sections = "".join(
        f"<li><strong>{_html_escape(framework)}</strong>: {_html_escape(', '.join(labels) if labels else 'None')}</li>"
        for framework, labels in compliance.items()
    )

    html = f"""
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>Zentry Final Report</title>
      <style>
        :root {{
          color-scheme: dark;
          --bg: #08111f;
          --panel: #0f172a;
          --panel-2: #111827;
          --text: #e5eefc;
          --muted: #9fb0cb;
          --accent: #37c8b6;
          --accent-2: #7dd3fc;
          --danger: #fb7185;
          --border: rgba(148, 163, 184, 0.2);
        }}
        * {{ box-sizing: border-box; }}
        body {{
          margin: 0;
          font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          background:
            radial-gradient(circle at top left, rgba(55, 200, 182, 0.18), transparent 28%),
            radial-gradient(circle at top right, rgba(125, 211, 252, 0.12), transparent 22%),
            var(--bg);
          color: var(--text);
        }}
        .wrap {{ max-width: 1240px; margin: 0 auto; padding: 40px 24px 64px; }}
        .hero {{ display: grid; gap: 12px; margin-bottom: 28px; }}
        .eyebrow {{ text-transform: uppercase; letter-spacing: 0.18em; color: var(--accent); font-size: 12px; }}
        h1 {{ margin: 0; font-size: clamp(2rem, 4vw, 3.5rem); line-height: 1.05; }}
        .subtitle {{ color: var(--muted); max-width: 80ch; line-height: 1.65; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin: 24px 0; }}
        .card {{ background: linear-gradient(180deg, rgba(255,255,255,0.03), transparent), var(--panel); border: 1px solid var(--border); border-radius: 18px; padding: 18px; box-shadow: 0 18px 48px rgba(0, 0, 0, 0.22); }}
        .metric {{ font-size: 2rem; font-weight: 800; color: var(--accent-2); margin-bottom: 6px; }}
        .label {{ color: var(--muted); font-size: 0.92rem; }}
        section {{ margin-top: 24px; }}
        h2 {{ margin: 0 0 14px; font-size: 1.25rem; }}
        table {{ width: 100%; border-collapse: collapse; overflow: hidden; border-radius: 14px; }}
        th, td {{ text-align: left; padding: 12px 14px; border-bottom: 1px solid var(--border); vertical-align: top; }}
        th {{ background: rgba(255,255,255,0.04); color: #cbe1ff; font-size: 0.9rem; }}
        td {{ color: var(--text); }}
        ul {{ margin: 0; padding-left: 18px; color: var(--text); line-height: 1.7; }}
        .muted {{ color: var(--muted); }}
        .note {{ color: var(--danger); }}
        .split {{ display: grid; grid-template-columns: 1.2fr 0.8fr; gap: 16px; }}
        @media (max-width: 960px) {{ .split {{ grid-template-columns: 1fr; }} }}
      </style>
    </head>
    <body>
      <div class="wrap">
        <div class="hero">
          <div class="eyebrow">Unified Automated Vulnerability Scanner</div>
          <h1>{_html_escape(report.get('target', ''))}</h1>
          <div class="subtitle">Generated at {_html_escape(report.get('generated_at', ''))}. This report merges recon, DAG validation, fact-store chaining, and standardized vulnerability records into a single output pipeline.</div>
        </div>

        <div class="grid">
          <div class="card"><div class="metric">{_html_escape(owasp.get('owasp_top10_category_coverage_percent', 0))}%</div><div class="label">OWASP category coverage</div></div>
          <div class="card"><div class="metric">{_html_escape(owasp.get('overall_subcase_coverage_percent', 0))}%</div><div class="label">OWASP subcase coverage</div></div>
          <div class="card"><div class="metric">{_html_escape(summary.get('confirmed_findings', 0))}</div><div class="label">Confirmed findings</div></div>
          <div class="card"><div class="metric">{_html_escape(summary.get('risk_score', 0))}</div><div class="label">Risk score</div></div>
        </div>

        <div class="split">
          <section class="card">
            <h2>OWASP Coverage</h2>
            <table>
              <thead>{_render_coverage_table(coverage)}</thead>
            </table>
          </section>

          <section class="card">
            <h2>Compliance Mapping</h2>
            <ul>{compliance_sections or '<li>None</li>'}</ul>
          </section>
        </div>

        <div class="split">
          <section class="card">
            <h2>Confirmed Vulnerabilities</h2>
            <ul>{_render_list([item.get('type', 'unknown') for item in confirmed if isinstance(item, dict)])}</ul>
          </section>

          <section class="card">
            <h2>Potential Findings</h2>
            <ul>{_render_list([item.get('vulnerability', 'unknown') for item in potential if isinstance(item, dict)])}</ul>
          </section>
        </div>

        <section class="card">
          <h2>Execution Notes</h2>
          <ul>
            <li>Recon and validation are scheduled through the DAG brain with a shared FactStore.</li>
            <li>Validation records are normalized into a single JSON schema before final reporting.</li>
            <li class="note">If subcase coverage is below 100%, the target did not expose every testable primitive required by the catalog.</li>
          </ul>
        </section>
      </div>
    </body>
    </html>
    """
    return textwrap.dedent(html).strip()


async def _write_report_artifacts(report: Dict[str, Any]) -> None:
    html = _build_html_report(report)
    HTML_REPORT_PATH.write_text(html, encoding="utf-8")

    try:
        from playwright.async_api import async_playwright

        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            page = await browser.new_page(viewport={"width": 1440, "height": 1800})
            await page.set_content(html, wait_until="load")
            await page.pdf(path=str(PDF_REPORT_PATH), format="A4", print_background=True)
            await browser.close()
    except Exception:
        # HTML is the primary artifact; PDF is best-effort.
        pass


async def _scan_target(target: str, max_workers: int, recon_timeout: int) -> Dict[str, Any]:
    normalized_target = _normalize_target(target)
    FactStore.reset()
    fact_store = FactStore()

    async with httpx.AsyncClient(headers=DEFAULT_HEADERS, timeout=DEFAULT_TIMEOUT, follow_redirects=True, verify=False) as client:
        scan_started = time.time()
        scan_time = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        baseline_response = None
        try:
            baseline_response = await client.get(normalized_target)
        except Exception:
            baseline_response = None

        session_context: Dict[str, Any] = {
            "target": normalized_target,
            "cookie": baseline_response.headers.get("set-cookie", "") if baseline_response is not None else "",
            "headers": dict(baseline_response.headers) if baseline_response is not None else {},
            "status_code": baseline_response.status_code if baseline_response is not None else None,
            "scan_time": scan_time,
        }

        dashboard.start()
        logger.info("=" * 72)
        logger.info(f"Starting unified scan against: {normalized_target}")
        logger.info("=" * 72)

        parsed_data: Dict[str, Any] = {}
        pipeline_result: Dict[str, Any] = {}

        async def _sync_validation_progress(validation_progress: Dict[str, Any], stop_event: asyncio.Event) -> None:
            while not stop_event.is_set():
                total = int(validation_progress.get("total", 0) or 0)
                completed = int(validation_progress.get("completed", 0) or 0)
                detail = str(validation_progress.get("detail", "waiting"))
                percent = int(100 * completed / total) if total > 0 else 0
                dashboard.update_validation(percent, detail)
                await asyncio.sleep(0.15)

        try:
            logger.info("Phase 1: Reconnaissance")
            dashboard.update_recon(0, "starting")
            recon_started = time.time()
            try:
                parsed_data = await run_recon_zentry(normalized_target)
            except Exception as exc:
                raise RuntimeError(f"Reconnaissance failed: {type(exc).__name__}: {exc}") from exc

            recon_elapsed = int(time.time() - recon_started)
            if recon_elapsed > recon_timeout:
                logger.warning(
                    f"Reconnaissance exceeded advisory timeout ({recon_elapsed}s > {recon_timeout}s) but completed successfully."
                )

            dashboard.update_recon(100, "recon complete")

            parsed_data = parsed_data or {}
            parsed_data.setdefault("scan_info", {})["duration_seconds"] = int(time.time() - scan_started)
            parsed_data["session_context"] = session_context
            parsed_data["client_state"] = {
                "base_url": normalized_target,
                "cookies": session_context.get("cookie", ""),
                "status_code": session_context.get("status_code"),
            }

            subdomains = parsed_data.get("subdomains", []) or []
            endpoints = parsed_data.get("endpoints", []) or []
            logger.info(f"Found {len(subdomains)} subdomains, {len(endpoints)} endpoints")

            logger.info("Phase 2: DAG Validation")
            dag_state = build_validation_state(parsed_data, session_context=session_context)
            dag_state["http_client"] = client
            dag_state["session_context"] = session_context
            dag_state["fact_store"] = fact_store

            dag_brain = DAGBrain(use_graph_engine=True, fact_store=fact_store)
            concurrent_engine = ConcurrentValidationEngine(dag_brain=dag_brain, state=dag_state, max_workers=max_workers)

            validation_progress: Dict[str, Any] = {"total": 0, "completed": 0, "detail": "starting"}
            validation_stop = asyncio.Event()
            validation_poller = asyncio.create_task(_sync_validation_progress(validation_progress, validation_stop))

            try:
                pipeline_result = await concurrent_engine.run_pipeline(progress=validation_progress)
            finally:
                validation_stop.set()
                validation_poller.cancel()
                try:
                    await validation_poller
                except asyncio.CancelledError:
                    pass

            executed_edges = len(pipeline_result.get("results", []))
            logger.info(f"Validation completed. Executed {executed_edges} DAG edges.")
            dashboard.update_validation(100, "validation complete")

            logger.info("Phase 3: Final Reporting")

            final_report_file, confirmed_report_file = save_final_reports(
                target=normalized_target,
                scan_time=scan_time,
                parsed_data=parsed_data,
                actions=[],
                results=[],
                pipeline_validation_results=_extract_pipeline_validation_records(pipeline_result),
            )

            report = _load_json(Path(final_report_file))
            if report:
                await _write_report_artifacts(report)
                logger.info(f"HTML report: {HTML_REPORT_PATH}")
                if PDF_REPORT_PATH.exists():
                    logger.info(f"PDF report: {PDF_REPORT_PATH}")
            logger.info(f"Consolidated final report: {final_report_file}")
            logger.info(f"Confirmed vulnerabilities: {confirmed_report_file}")

            confirmed_vulns = parsed_data.get("confirmed_vulnerabilities", []) or []
            findings = parsed_data.get("vulnerabilities", []) or []

            logger.info("FINDINGS & VULNERABILITIES DISCOVERED")
            if findings:
                logger.info(f"Nuclei Findings ({len(findings)} total):")
                for i, finding in enumerate(findings[:20], 1):
                    name = finding.get("info", {}).get("name") or finding.get("type") or "Unknown"
                    severity = finding.get("info", {}).get("severity", "info").upper()
                    url = finding.get("matched-at") or finding.get("url") or "N/A"
                    logger.info(f"    [{i:>2}] [{severity:>8}] {name[:40]:40} @ {url[:50]}")

            if confirmed_vulns:
                logger.info(f"Confirmed Vulnerabilities ({len(confirmed_vulns)} total):")
                for i, vuln in enumerate(confirmed_vulns[:20], 1):
                    name = vuln.get("name") or vuln.get("type") or "Unknown"
                    severity = vuln.get("severity", "info").upper()
                    url = vuln.get("url") or "N/A"
                    logger.info(f"    [{i:>2}] [{severity:>8}] {name[:40]:40} @ {url[:50]}")

            logger.info("Unified scan completed successfully")
            dashboard.finish()
            dashboard.stop()
            return report
        finally:
            dashboard.finish()
            dashboard.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="Unified async vulnerability scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL or host")
    parser.add_argument("--max-workers", type=int, default=14, help="Concurrent DAG worker count")
    parser.add_argument("--recon-timeout", type=int, default=1200, help="Recon timeout in seconds")
    parser.add_argument("--profile", choices=("auto", "balanced", "aggressive"), default="auto", help="Recon profile selection")
    args = parser.parse_args()

    _ensure_output_dir()
    try:
        os.environ["YUVA_SCAN_PROFILE"] = _select_scan_profile(args.url, args.profile)
        asyncio.run(_scan_target(args.url, min(16, max(1, args.max_workers)), min(1200, max(1, args.recon_timeout))))
    except KeyboardInterrupt:
        print("[-] Scan interrupted by user")
        raise SystemExit(130)
    except Exception as exc:
        print(f"[-] Scan failed: {exc}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
