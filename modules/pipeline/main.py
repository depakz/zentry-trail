import json
import sys
import time
import argparse
import asyncio
from datetime import datetime, timezone
import threading
import inspect
from urllib.parse import urlsplit
from modules.pipeline.brain.dag_engine_enhanced import DAGBrain, ConcurrentValidationEngine
from modules.pipeline.brain.compliance_mapper import ComplianceMapper
from modules.pipeline.brain.owasp_depth_matrix import build_depth_coverage
from modules.pipeline.brain.exploitability_reporter import ExploitabilityReporter
from modules.pipeline.engine.validation_engine import StateManager, ValidationEngine
import importlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.pipeline.utils.session import save_graph_snapshot
import os
from modules.pipeline.engine.decision import decide_actions
from modules.pipeline.engine.executor import run_sqlmap, test_xss, run_git_extractor, run_ssh_brute, run_config_reader
from modules.pipeline.utils.logger import logger
from core.logger import dashboard
from modules.pipeline.utils.retry import retry
from modules.pipeline.utils.session import save_session
from modules.pipeline.utils.session import load_session
from modules.pipeline.utils.session import capture_session_context
from modules.pipeline.integrations.recon_zentry_adapter import run_recon_zentry


FINAL_REPORT_FILE = "output/final_report.json"
CONFIRMED_VULNS_FILE = "output/confirmed_vulnerabilities.json"


def build_validation_state(report, session_context=None):
    scan_info = report.get("scan_info", {}) if isinstance(report, dict) else {}
    normalized = report if isinstance(report, dict) else {}
    session_target = ""
    if isinstance(session_context, dict):
        raw_session_target = session_context.get("target")
        if isinstance(raw_session_target, str):
            session_target = raw_session_target.strip()

    target = session_target or normalized.get("target") or scan_info.get("target") or ""

    def _collect_http_urls(*collections):
        urls = []
        seen = set()
        for collection in collections:
            if not collection:
                continue
            if isinstance(collection, dict):
                collection = [collection]
            for item in collection:
                candidate = None
                if isinstance(item, str):
                    candidate = item.strip()
                elif isinstance(item, dict):
                    candidate = item.get("url") or item.get("matched_url") or item.get("endpoint") or item.get("sample_url")
                    if not candidate:
                        evidence = item.get("evidence")
                        if isinstance(evidence, dict):
                            candidate = evidence.get("matched_url") or evidence.get("endpoint")
                    if isinstance(candidate, str):
                        candidate = candidate.strip()
                if not isinstance(candidate, str) or not candidate.startswith(("http://", "https://")):
                    continue
                if candidate in seen:
                    continue
                seen.add(candidate)
                urls.append(candidate)
        return urls

    def _collect_ports_protocols(urls):
        ports = []
        protocols = []
        seen_ports = set()
        seen_protocols = set()
        for url_value in urls:
            if not isinstance(url_value, str) or not url_value.startswith(("http://", "https://")):
                continue
            parsed = urlsplit(url_value)
            scheme = (parsed.scheme or "").lower()
            if scheme in ("http", "https"):
                protocol = "http"
            else:
                protocol = scheme
            if protocol and protocol not in seen_protocols:
                seen_protocols.add(protocol)
                protocols.append(protocol)
            port = parsed.port
            if port is None:
                if scheme == "http":
                    port = 80
                elif scheme == "https":
                    port = 443
            if port is not None and port not in seen_ports:
                seen_ports.add(port)
                ports.append(port)
        return sorted(ports), sorted(protocols)

    endpoints = _collect_http_urls(
        normalized.get("endpoints", []),
        normalized.get("alive_hosts", []),
        normalized.get("validation_targets", []),
    )
    ranked_targets = normalized.get("ranked_targets", []) if isinstance(normalized.get("ranked_targets", []), list) else []
    validation_targets = _collect_http_urls(
        normalized.get("validation_targets", []),
        normalized.get("ranked_targets", []),
        endpoints,
        target,
    )

    url = ""
    for candidate in validation_targets:
        if candidate:
            url = candidate
            break
    if not url and target:
        url = target if target.startswith(("http://", "https://")) else "https://" + target

    ports, protocols = _collect_ports_protocols([url, *validation_targets])

    findings = normalized.get("findings", []) if isinstance(normalized.get("findings", []), list) else []
    if not findings:
        findings = normalized.get("vulnerabilities", []) if isinstance(normalized.get("vulnerabilities", []), list) else []
    if not isinstance(findings, list):
        findings = []
    findings = [f for f in findings if isinstance(f, dict)]

    metadata = {
        "scan_info": scan_info if isinstance(scan_info, dict) else {},
        "summary": normalized.get("summary", {}) if isinstance(normalized.get("summary", {}), dict) else {},
    }

    params = normalized.get("params", []) if isinstance(normalized.get("params", []), list) else []
    categories = normalized.get("categories", []) if isinstance(normalized.get("categories", []), list) else []
    response_analysis = normalized.get("response_analysis", {}) if isinstance(normalized.get("response_analysis", {}), dict) else {}

    resolved_session = session_context if isinstance(session_context, dict) else {}
    cookie = resolved_session.get("cookie") if isinstance(resolved_session.get("cookie"), str) else ""
    headers = resolved_session.get("headers") if isinstance(resolved_session.get("headers"), dict) else {}

    return {
        "target": target,
        "ports": ports,
        "protocols": protocols,
        "url": url,
        "endpoints": endpoints,
        "validation_targets": validation_targets,
        "ranked_targets": ranked_targets,
        "params": params,
        "categories": categories,
        "findings": findings,
        "vulnerabilities": findings,
        "response_analysis": response_analysis,
        "source": normalized.get("source", ""),
        "metadata": metadata,
        "cookie": cookie,
        "headers": headers,
        "session_context": resolved_session,
        # feedback loop state
        "validation_results": [],
        "confirmed_vulns": [],
        "signals": [],
    }

def execute_action(action, cookie=None):
    if action["action"] == "test_sqli":
        return run_sqlmap(action["endpoint"], cookie=cookie)

    if action["action"] == "test_xss":
        return test_xss(action["endpoint"], cookie=cookie)

    return {"success": False, "evidence": "Unknown action"}


def _action_to_vuln_type(action_name: str) -> str:
    mapping = {
        "test_sqli": "sql_injection",
        "test_xss": "cross_site_scripting",
    }
    return mapping.get(action_name, action_name or "unknown")


def _build_confirmed_records(actions, results):
    confirmed = []
    seen = set()

    for action, result in zip(actions or [], results or []):
        if not isinstance(action, dict) or not isinstance(result, dict):
            continue
        if not result.get("success"):
            continue

        action_name = action.get("action") or "unknown"
        endpoint = action.get("endpoint") or ""
        base = action.get("base") or ""
        params = action.get("params") or []
        reason = action.get("reason") or ""
        vuln_type = _action_to_vuln_type(action_name)

        key = (vuln_type, base, tuple(params) if isinstance(params, list) else ())
        if key in seen:
            continue
        seen.add(key)

        confirmed.append(
            {
                "type": vuln_type,
                "source_action": action_name,
                "endpoint": endpoint,
                "base": base,
                "params": params if isinstance(params, list) else [],
                "reason": reason,
                "proof": result.get("evidence", {}),
            }
        )

    return confirmed


def _build_confirmed_validator_records(pipeline_validation_results):
    confirmed = []
    seen = set()

    for record in pipeline_validation_results or []:
        if not isinstance(record, dict):
            continue

        success = bool(record.get("success"))
        validation = record.get("validation") or {}
        if not success and isinstance(validation, dict):
            status = str(validation.get("status") or "").strip().lower()
            success = status == "confirmed"

        if not success:
            continue

        vulnerability = str(record.get("vulnerability") or record.get("validator_id") or "unknown")
        validator_id = str(record.get("validator_id") or "")
        key = (vulnerability, validator_id)
        if key in seen:
            continue
        seen.add(key)

        confirmed.append(
            {
                "type": vulnerability,
                "source_action": "validator",
                "endpoint": record.get("target") or record.get("url") or "",
                "base": record.get("target") or record.get("url") or "",
                "params": [],
                "reason": record.get("impact") or record.get("remediation") or "",
                "proof": record.get("evidence", {}),
                "validator_id": validator_id,
                "validator_class": record.get("validator_class") or "",
                "severity": record.get("severity") or (validation.get("severity") if isinstance(validation, dict) else ""),
                "confidence": validation.get("confidence_score") if isinstance(validation, dict) else None,
            }
        )

    return confirmed


def _annotate_records(records):
    annotated = []
    for record in records or []:
        if isinstance(record, dict):
            annotated.append(ComplianceMapper.annotate_record(record))
    return annotated


def _summarize_compliance(records):
    frameworks = {"OWASP": [], "PCI-DSS": [], "SOC2": [], "NIST": []}
    for record in records or []:
        if not isinstance(record, dict):
            continue
        for framework, label in (record.get("compliance_tags") or {}).items():
            bucket = frameworks.setdefault(framework, [])
            if label not in bucket:
                bucket.append(label)
    return frameworks


def _extract_pipeline_validation_records(pipeline_result):
    out = []
    if not isinstance(pipeline_result, dict):
        return out

    for edge_result in pipeline_result.get("results", []) or []:
        if not isinstance(edge_result, dict):
            continue
        
        payload = edge_result.get("result")
        if isinstance(payload, dict):
            out.append(payload)
        elif isinstance(payload, list):
            for item in payload:
                if isinstance(item, dict):
                    out.append(item)

    return out


def save_final_reports(target: str, scan_time: str, parsed_data, actions, results, pipeline_validation_results=None):
    os.makedirs("output", exist_ok=True)

    findings = parsed_data.get("findings", []) if isinstance(parsed_data, dict) else []
    if not isinstance(findings, list):
        findings = []

    summary = parsed_data.get("summary", {}) if isinstance(parsed_data, dict) else {}
    if not isinstance(summary, dict):
        summary = {}

    confirmed = _annotate_records(_build_confirmed_records(actions, results))
    annotated_findings = _annotate_records(findings)
    annotated_results = _annotate_records(results)
    annotated_pipeline_results = _annotate_records(pipeline_validation_results or [])
    confirmed_validator_records = _annotate_records(
        _build_confirmed_validator_records(pipeline_validation_results or [])
    )
    all_report_records = annotated_findings + confirmed + annotated_results + annotated_pipeline_results + confirmed_validator_records
    confirmed_all = confirmed + confirmed_validator_records

    compliance_overview = _summarize_compliance(all_report_records)
    owasp_depth_coverage = build_depth_coverage(all_report_records)

    final_report = {
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "scan_time": scan_time,
        "summary": {
            "potential_findings": len(annotated_findings),
            "confirmed_findings": len(confirmed_all),
            "critical": summary.get("critical", 0),
            "high": summary.get("high", 0),
            "medium": summary.get("medium", 0),
            "low": summary.get("low", 0),
            "info": summary.get("info", 0),
            "risk_score": summary.get("risk_score", 0),
        },
        "compliance_overview": compliance_overview,
        "owasp_depth_coverage": owasp_depth_coverage,
        "confirmed_vulnerabilities": confirmed_all,
        "potential_findings": annotated_findings,
        "validator_findings": annotated_pipeline_results,
        "follow_up_actions": actions or [],
        "follow_up_results": annotated_results,
    }

    with open(FINAL_REPORT_FILE, "w") as f:
        json.dump(final_report, f, indent=2)

    with open(CONFIRMED_VULNS_FILE, "w") as f:
        json.dump(
            {
                "target": target,
                "generated_at": final_report["generated_at"],
                "confirmed_count": len(confirmed_all),
                "confirmed_vulnerabilities": confirmed_all,
            },
            f,
            indent=2,
        )

    if compliance_overview.get("OWASP"):
        logger.info("OWASP compliance labels: %s", ", ".join(compliance_overview["OWASP"]))
    coverage_summary = owasp_depth_coverage.get("summary") or {}
    logger.info(
        "OWASP coverage: %.2f%% categories (%s/10) | %.2f%% subcases (%s/%s)",
        float(coverage_summary.get("owasp_top10_category_coverage_percent", 0.0) or 0.0),
        int(coverage_summary.get("categories_with_any_tested_subcase", 0) or 0),
        float(coverage_summary.get("overall_subcase_coverage_percent", 0.0) or 0.0),
        int(coverage_summary.get("subcases_tested", 0) or 0),
        int(coverage_summary.get("subcases_total", 0) or 0),
    )

    return FINAL_REPORT_FILE, CONFIRMED_VULNS_FILE


def run_with_progress(label, func, *args, **kwargs):
    """Run a potentially long task while showing a simple progress spinner.

    This does not estimate percent complete; it confirms the task is still running
    and shows elapsed time.
    """
    # If not a TTY, run normally.
    if not sys.stdout.isatty():
        return func(*args, **kwargs)

    # Pass a lightweight progress dict when supported by the function.
    progress = {"detail": ""}
    try:
        if "progress" in inspect.signature(func).parameters:
            kwargs = dict(kwargs)
            kwargs["progress"] = progress
    except Exception:
        pass

    start = time.time()
    try:
        dashboard.print_log(f"Starting: {label}")
        value = func(*args, **kwargs)
    except KeyboardInterrupt:
        elapsed = int(time.time() - start)
        dashboard.print_log(f"{label} interrupted by user after {elapsed}s")
        raise
    except Exception as e:
        elapsed = int(time.time() - start)
        dashboard.print_log(f"{label} failed after {elapsed}s: {e}")
        raise
    finally:
        elapsed = int(time.time() - start)
        dashboard.print_log(f"{label} done in {elapsed}s")

    try:
        dashboard.advance_recon(f"run_with_progress:{label}")
    except Exception:
        pass
    return value

def display_terminal_summary(results):
    """Prints a human-readable summary of vulnerabilities and proofs to the terminal."""
    print("\n" + "="*60)
    print(" SECURITY PIPELINE: VULNERABILITY SUMMARY")
    print("="*60)
    
    if not results:
        print("[-] No vulnerabilities confirmed.")
        return

    confirmed_count = 0
    for res in results:
        confidence = res.get('confidence', 0)
        severity = str(res.get('severity', '')).upper()
        
        is_high = severity == 'HIGH' or (isinstance(confidence, (int, float)) and confidence >= 0.8)
        
        if is_high or res.get('vulnerability_confirmed', True):
            confirmed_count += 1
            vuln_type = res.get('type', res.get('vulnerability_type', 'Unknown'))
            endpoint = res.get('endpoint')
            if not endpoint:
                endpoint = res.get('base', 'N/A')
            proof = res.get('proof', 'No proof provided.')
            
            symbol = "[!]" if is_high else "[+]"
            
            print(f"\n{symbol} VULNERABILITY: {vuln_type}")
            print(f"    URL: {endpoint}")
            print(f"    SEVERITY/CONFIDENCE: {severity} / {confidence}")
            print(f"    PROOF OF CONCEPT:")
            
            if isinstance(proof, dict):
                proof_str = json.dumps(proof, indent=2)
            else:
                proof_str = str(proof)
            
            indented_proof = "\n".join("        " + line for line in proof_str.splitlines())
            print(indented_proof)
            print("-" * 60)

    print(f"\n[!] Total Confirmed Vulnerabilities: {confirmed_count}")
    print("="*60 + "\n")

def main():
    parser = argparse.ArgumentParser(
        description="Run the penetration testing pipeline against a target host or URL."
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Target hostname or URL (for example: example.com or https://example.com)",
    )
    parser.add_argument(
        "--cve-report",
        action="store_true",
        help="Generate CVE exploitability report (optional).",
    )
    parser.add_argument(
        "--cookie",
        help="Cookie header value to include in HTTP-based scans (example: 'PHPSESSID=...; security=low').",
    )
    parser.add_argument(
        "--login-url",
        help="Optional login URL to capture a fresh session cookie or token before running the pipeline.",
    )
    parser.add_argument(
        "--login-method",
        default="POST",
        help="HTTP method to use for login capture (default: POST).",
    )
    parser.add_argument(
        "--username",
        help="Username for opt-in login capture.",
    )
    parser.add_argument(
        "--password",
        help="Password for opt-in login capture.",
    )
    parser.add_argument(
        "--auth-type",
        default="session",
        choices=["session", "basic", "bearer"],
        help="Authentication style for session capture.",
    )
    parser.add_argument(
        "--bearer-token",
        help="Optional bearer token to seed the session context directly.",
    )
    args = parser.parse_args()

    if not args.target:
        parser.print_help()
        sys.exit(1)

    target = args.target
    scan_start = time.time()
    scan_time = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    logger.info(f"Starting penetration testing pipeline for target: {target}")

    from validators.integrity import verify_connectivity
    is_alive, working_url = verify_connectivity(target)
    if not is_alive:
        print(f"[-] Aborting: Could not connect to {target}")
        sys.exit(1)
    
    target = working_url

    prior_session = load_session()
    prior_session_context = prior_session.get("session_context") if isinstance(prior_session, dict) else {}
    session_context = capture_session_context(
        target,
        previous=prior_session_context,
        cookie=args.cookie,
        login_url=args.login_url,
        login_method=args.login_method,
        username=args.username,
        password=args.password,
        auth_type=args.auth_type,
        bearer_token=args.bearer_token,
    )
    active_cookie = session_context.get("cookie") or None

    logger.info("Running Recon-ZENTRY integration pipeline...")
    parsed_data = asyncio.run(run_recon_zentry(target))

    try:
        parsed_data.setdefault("scan_info", {})["duration_seconds"] = int(time.time() - scan_start)
    except Exception:
        pass

    if session_context:
        parsed_data["session_context"] = session_context

    save_session(parsed_data)

    # Step 3: DAG-driven Validation & Attack Chaining
    pipeline_result = {}
    try:
        logger.info("Building DAG-driven state machine...")
        state = build_validation_state(parsed_data, session_context=session_context)
        dag_brain = DAGBrain(use_graph_engine=True)
        concurrent_engine = ConcurrentValidationEngine(dag_brain=dag_brain, state=state, max_workers=14)

        logger.info("Starting concurrent DAG execution loop...")
        pipeline_result = asyncio.run(concurrent_engine.run_pipeline())
        snapshot = pipeline_result.get("snapshot", {})
        save_graph_snapshot(snapshot)
        logger.info(
            "Concurrent DAG execution completed with %s executed edges",
            len(pipeline_result.get("results", [])),
        )

    except Exception as e:
        logger.info(f"DAG execution failed: {e}")
        import traceback
        traceback.print_exc()

    # Step 4: Decision Engine
    logger.info("Deciding next actions...")
    actions = decide_actions(parsed_data)
    
    if not actions:
        logger.info("No actionable findings identified.")
        final_report, confirmed_report = save_final_reports(
            target=target,
            scan_time=scan_time,
            parsed_data=parsed_data,
            actions=[],
            results=[],
            pipeline_validation_results=_extract_pipeline_validation_records(pipeline_result),
        )
        logger.info("Saved final report: %s", final_report)
        logger.info("Saved confirmed vulnerabilities report: %s", confirmed_report)
        try:
            with open(confirmed_report, "r") as f:
                data = json.load(f)
                display_terminal_summary(data.get("confirmed_vulnerabilities", []))
        except Exception as e:
            logger.error(f"Could not print terminal summary: {e}")
        return

    # Step 5: Execution
    logger.info("Executing follow-up tests...")
    results = []
    for action in actions:
        logger.info(f"Executing: {action['action']} on {action.get('endpoint')}")
        result = execute_action(action, cookie=active_cookie)
        results.append(result)

    logger.info("Pipeline completed. Summary:")
    print(json.dumps(_annotate_records(results), indent=2))

    final_report, confirmed_report = save_final_reports(
        target=target,
        scan_time=scan_time,
        parsed_data=parsed_data,
        actions=actions,
        results=results,
        pipeline_validation_results=_extract_pipeline_validation_records(pipeline_result),
    )
    logger.info("Saved final report: %s", final_report)
    logger.info("Saved confirmed vulnerabilities report: %s", confirmed_report)
    try:
        with open(confirmed_report, "r") as f:
            data = json.load(f)
            display_terminal_summary(data.get("confirmed_vulnerabilities", []))
    except Exception as e:
        logger.error(f"Could not print terminal summary: {e}")

if __name__ == "__main__":
    main()
