"""
ReconOrchestrator: The main engine for the reconnaissance and validation pipeline.
This module consolidates logic from the original `core/orchestrator.py`.
"""

import asyncio
import uuid
import time
import socket
from typing import Any, Dict, List
from urllib.parse import urlparse
from rich.panel import Panel
from rich.console import Console

from zentry.recon.tool_wrappers import ToolWrappers
from zentry.recon.js_parser import extract_js_endpoints
from zentry.recon.param_miner import mine_parameters
from zentry.reporting.html_reporter import HTMLReporter
from zentry.reporting.json_reporter import JSONReporter
from zentry.reporting.sarif_reporter import SARIFReporter
from zentry.reporting.dedup import dedup_findings, dedup_finding_objects
from zentry.chains.engine import ChainEngine
from zentry.chains.rules import CHAIN_RULES
from zentry.evidence.store import EvidenceStore
from zentry.auth.manager import AuthManager
from zentry.validators.registry import ValidatorRegistry
from zentry.session import ScanSession, Finding, FactStore
from zentry.recon.signal_extractor import extract_signals

# Placeholder for future brain/engine components if they are re-introduced
# For now, validation is simpler.
class AttackChainManager:
    def __init__(self, fact_store): pass
    def validator_completed(self, *args, **kwargs): pass


async def _timed(name: str, coro, timeout: int, progress=None):
    start = time.monotonic()
    if progress:
        progress.console.log(f"   [yellow]⏳ {name}...[/]")
    try:
        result = await asyncio.wait_for(coro, timeout=timeout)
        elapsed = time.monotonic() - start
        n = len(result) if hasattr(result, "__len__") else "?"
        if progress:
            progress.console.log(f"   [green]✓ {name}[/] [dim]({elapsed:.1f}s, {n} results)[/]")
        return result
    except asyncio.TimeoutError:
        if progress:
            progress.console.log(f"   [red]✗ {name} TIMEOUT after {timeout}s — skipped[/]")
        return []
    except Exception as e:
        if progress:
            progress.console.log(f"   [red]✗ {name} ERROR: {e}[/]")
        return []

class ReconOrchestrator:
    def __init__(self, target: str, fast: bool = True, scope: list = None, output_dir: str = "reports"):
        self.target = target
        self.session = ScanSession(target=target)
        self.fast = fast
        self.scope = scope or []
        self.output_dir = output_dir
        self.tools = ToolWrappers()
        self.fact_store = FactStore()
        self.attack_chain_manager = AttackChainManager(self.fact_store)
        self.evidence_store = EvidenceStore(output_dir=f"{self.output_dir}/evidence_bundles")
        self.validator_registry = ValidatorRegistry()
        self._playwright = None
        self._browser = None
        # Pre-scan authentication manager
        self.auth_manager = AuthManager(target=target)
        self._auth_cookies: dict = {}

    def _get_local_ip(self) -> str:
        """Get the local IP address that the OOB server should bind to."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _start_shared_browser(self) -> None:
        try:
            from playwright.sync_api import sync_playwright  # type: ignore
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch(headless=True)
        except Exception:
            self._playwright = None
            self._browser = None

    def _stop_shared_browser(self) -> None:
        try:
            if self._browser is not None:
                self._browser.close()
        except Exception:
            pass
        try:
            if self._playwright is not None:
                self._playwright.stop()
        except Exception:
            pass
        self._browser = None
        self._playwright = None

    def _build_report_payload(
        self,
        signal_bag: Dict[str, Any],
        selection_reasons: Dict[str, List[str]],
        selected_validators: List[Any],
        validation_results: List[Any],
    ) -> Dict[str, Any]:
        finding_details: List[Dict[str, Any]] = []
        for result in validation_results:
            if not isinstance(result, dict) or not result.get("success"):
                continue

            evidence = result.get("evidence") if isinstance(result.get("evidence"), dict) else {}
            request_blob = evidence.get("request") if isinstance(evidence, dict) else {}
            response_blob = evidence.get("response") if isinstance(evidence, dict) else {}
            target_url = ""
            payload = ""
            if isinstance(request_blob, dict):
                target_url = str(request_blob.get("target") or request_blob.get("url") or request_blob.get("probe_url") or "")
                payload = str(request_blob.get("payload") or "")

            snippet = ""
            if isinstance(response_blob, dict):
                snippet = str(response_blob.get("snippet") or response_blob.get("probe_snippet") or response_blob.get("raw") or "")
            elif isinstance(response_blob, str):
                snippet = response_blob[:300]

            # Simplified scoring
            severity_map = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0}
            severity = str(result.get("severity") or "info").lower()
            score = severity_map.get(severity, 0.0)

            cvss = round(min(10.0, max(0.0, score * 10.0)), 1)

            # Extract HTTP method from evidence for evidence capture
            method = "GET"
            if isinstance(request_blob, dict):
                method = str(request_blob.get("method") or "GET").upper()

            # Extract response status and headers for evidence capture
            response_status = None
            response_headers = None
            request_headers = None
            if isinstance(response_blob, dict):
                response_status = response_blob.get("status") or response_blob.get("status_code")
                response_headers = response_blob.get("headers")
            if isinstance(request_blob, dict):
                request_headers = request_blob.get("headers")

            # Extract evidence file paths
            evidence_req_path = ""
            evidence_res_path = ""
            evidence_bundle_data = result.get("evidence_bundle")
            if isinstance(evidence_bundle_data, dict):
                bundle_meta = evidence_bundle_data.get("metadata") or {}
                if isinstance(bundle_meta, dict): # This check is redundant
                    evidence_req_path = str(bundle_meta.get("evidence_req_path") or "")
                    evidence_res_path = str(bundle_meta.get("evidence_res_path") or "")

            finding_details.append(
                {
                    "validator_name": str(result.get("validator_id") or result.get("validator_class") or "unknown_validator"),
                    "vulnerability": str(result.get("vulnerability") or ""),
                    "severity": str(result.get("severity") or "info"),
                    "target_url": target_url,
                    "payload": payload,
                    "response_snippet": snippet,
                    "cvss": cvss,
                    "remediation": str(result.get("remediation") or ""),
                    "score": cvss,
                    "method": method,
                    # Evidence file paths captured at validator confirm time
                    "evidence_req_path": evidence_req_path,
                    "evidence_res_path": evidence_res_path,
                    # Private evidence metadata — consumed by EvidenceCollector fallback
                    "_evidence_response_status": response_status,
                    "_evidence_response_headers": response_headers if isinstance(response_headers, dict) else None,
                    "_evidence_request_headers": request_headers if isinstance(request_headers, dict) else None,
                }
            )

        return {
            "findings": finding_details,
            "attack_chains": [], # To be populated by the new ChainEngine
            "signal_coverage": {
                "detected_signals": signal_bag,
                "selected_validators": {
                    "validators": [v.__class__.__name__ for v in selected_validators],
                    "why": selection_reasons,
                },
            },
        }

    def is_in_scope(self, host: str) -> bool:
        if not self.scope: return True
        domain = urlparse(host if "://" in host else f"http://{host}").netloc.split(":")[0]
        if not domain: domain = host.split(":")[0]
        return any(domain == s or domain.endswith("." + s) for s in self.scope)

    async def run(self, progress, recon_task: int, validation_task: int):
        progress.console.log(Panel(f"🎯 Target: {self.target}  |  Fast mode: {self.fast}", style="bold cyan"))

        progress.console.log("[cyan]► Phase 1: Reconnaissance[/]")
        progress.update(recon_task, advance=5, description="[cyan]Phase 1: Reconnaissance (Subdomain Enumeration)")
        
        subfinder_task = asyncio.create_task(_timed("subfinder", self.tools.run_subfinder(self.target), timeout=90 if self.fast else 120, progress=progress))
        # crtsh is often flaky, let's rely on subfinder and amass

        amass_task = None
        if not self.fast:
            amass_task = asyncio.create_task(_timed("amass-passive", self.tools.run_amass(self.target), timeout=180, progress=progress))

        subfinder_results = await subfinder_task

        progress.update(recon_task, advance=15, description="[cyan]Phase 1: Reconnaissance (Probing Subfinder hosts)")

        initial_targets = sorted(set(subfinder_results)) if subfinder_results else [self.target]
        initial_targets = [t for t in initial_targets if self.is_in_scope(t)]

        httpx_task = asyncio.create_task(_timed("httpx", self.tools.run_httpx(initial_targets), timeout=20 if self.fast else 300, progress=progress))

        amass_results = await amass_task if amass_task else []

        all_recon_results = list(subfinder_results) + list(amass_results)
        merged = sorted(set(r for r in all_recon_results if self.is_in_scope(r)))

        target_no_scheme = urlparse(self.target).netloc or self.target.replace("http://", "").replace("https://", "")
        deep_crawl = False
        if not merged or (len(merged) == 1 and merged[0] in (self.target, target_no_scheme)):
            merged = [self.target] if self.is_in_scope(self.target) else []
            deep_crawl = True

        self.session.subdomains = merged
        progress.console.log(f"   [bold green]→ {len(merged)} unique in-scope subdomains[/]")

        alive = await httpx_task

        untested_domains = [d for d in merged if d not in initial_targets]
        if untested_domains:
            extra_alive = await _timed("httpx (extra)", self.tools.run_httpx(untested_domains), timeout=20 if self.fast else 300, progress=progress)
            alive.extend(extra_alive)

        seen = set()
        unique_alive = []
        for host in alive:
            url = host["url"] if isinstance(host, dict) else host
            if url not in seen and self.is_in_scope(url):
                seen.add(url)
                unique_alive.append(host if isinstance(host, dict) else {"url": host})

        alive = unique_alive
        if not alive:
            fallback_url = self.target if self.target.startswith(("http://", "https://")) else f"http://{self.target}"
            alive = [
                {
                    "url": fallback_url.rstrip("/"),
                    "input": self.target,
                    "status": 200,
                    "title": "fallback-target",
                    "tech": [],
                    "ip": "",
                    "host": urlparse(fallback_url).netloc or self.target,
                    "scheme": urlparse(fallback_url).scheme or "http",
                    "webserver": "",
                    "content_type": "",
                    "content_length": 0,
                    "cdn": False,
                    "cdn_name": "",
                }
            ]

        self.session.alive_hosts = alive
        progress.update(recon_task, advance=20, description="[cyan]Phase 1: Reconnaissance (Probing complete)")

        sem_waf = asyncio.Semaphore(5)
        async def run_waf(host):
            async with sem_waf:
                return host["url"], await _timed(f"wafw00f {host['url']}", self.tools.run_wafw00f(host["url"]), timeout=60, progress=progress)
                
        waf_tasks = [run_waf(host) for host in alive[:3]]
        waf_results = await asyncio.gather(*waf_tasks)
        for url, waf in waf_results:
            self.session.waf[url] = waf or "unknown"
            
        progress.update(recon_task, advance=10, description="[cyan]Phase 1: Reconnaissance (Crawling)")

        endpoints = set()
        sem_katana = asyncio.Semaphore(10)
        async def run_katana(host, depth=2):
            async with sem_katana:
                return await _timed(f"katana {host['url']}", self.tools.run_katana(host["url"], depth=depth), timeout=20 if self.fast else 180, progress=progress)
                
        katana_tasks = [run_katana(host, depth=4 if deep_crawl else 2) for host in alive[:10]]
        katana_results = await asyncio.gather(*katana_tasks)
        for crawled in katana_results:
            if crawled: endpoints.update(crawled)
        
        gau_eps = await _timed("gau", self.tools.run_gau(self.target), timeout=(20 if self.fast else 300), progress=progress)
        if gau_eps: endpoints.update(gau_eps)
        
        endpoints = {ep for ep in endpoints if self.is_in_scope(ep)}
        
        # JS Extraction
        progress.update(recon_task, advance=5, description="[cyan]Phase 1: Reconnaissance (JS Extraction)")
        js_res = extract_js_endpoints(list(endpoints))
        if js_res and js_res.get("endpoints"):
            new_eps = {ep for ep in js_res["endpoints"] if self.is_in_scope(ep)}
            endpoints.update(new_eps)
            progress.console.log(f"   [bold green]→ {len(new_eps)} JS endpoints found[/]")
            
        # Param Miner
        progress.update(recon_task, advance=5, description="[cyan]Phase 1: Reconnaissance (Param Miner)")
        try:
            extra_urls, param_map = await mine_parameters([h["url"] for h in alive], list(endpoints), self.session)
            if extra_urls:
                endpoints.update({ep for ep in extra_urls if self.is_in_scope(ep)})
        except Exception as e:
            progress.console.log(f"   [yellow]⚠ Param Miner skipped/failed: {e}[/]")
            param_map = {}

        self.session.endpoints = sorted(endpoints)

        # Recon summary: show basic counts
        js_count = len(js_res.get("endpoints") or []) if js_res else 0

        recon_summary = {
            "alive_hosts": len(alive),
            "endpoints_found": len(self.session.endpoints),
            "js_endpoints": js_count,
        }
        progress.console.log(f"   [blue]Recon Summary:[/] alive={recon_summary['alive_hosts']} endpoints={recon_summary['endpoints_found']} js={recon_summary['js_endpoints']}")

        # Start lightweight scanning tasks (naabu + nuclei) during recon so we
        # can present a single consolidated recon summary before validators.
        scan_targets = [h["url"] for h in alive]

        tech_tags = set()
        for host in alive:
            if isinstance(host, dict) and host.get("tech"):
                for t in host["tech"]:
                    if isinstance(t, str):
                        tech_tags.add(t.lower())

        async def async_naabu():
            try:
                return await asyncio.get_running_loop().run_in_executor(None, self.tools.run_naabu, self.target)
            except Exception:
                return {}

        naabu_task = asyncio.create_task(_timed("naabu", async_naabu(), timeout=30 if self.fast else 600, progress=progress))
        nuclei_task = asyncio.create_task(_timed("nuclei", self.tools.run_nuclei(scan_targets, tags=list(tech_tags)), timeout=60 if self.fast else 900, progress=progress))

        # Wait for reconnaissance scans to finish so we can print a single summary
        await asyncio.gather(naabu_task, nuclei_task)
        nuclei_findings = await nuclei_task
        port_results = await naabu_task

        # Store nuclei tags in session for downstream use
        nuclei_tags = set()
        for nf in nuclei_findings:
            info = nf.get("info", {}) if isinstance(nf, dict) else {}
            tags = info.get("tags") or info.get("reference") or []
            if isinstance(tags, (list, tuple)):
                for t in tags:
                    if isinstance(t, str):
                        nuclei_tags.add(t.lower())
        if nuclei_tags:
            self.session.nuclei_tags = list(sorted(nuclei_tags))
            self.session.data["nuclei_tags"] = list(sorted(nuclei_tags))

        # Print a single, readable recon summary panel
        panel_lines = [f"Alive hosts: {len(alive)}", f"Subdomains: {len(merged)}", f"Endpoints: {len(self.session.endpoints)}", f"JS endpoints: {js_count}"]
        progress.console.log(Panel("\n".join(panel_lines), title="Recon Summary", style="cyan"))

        # Run targeted validations inferred from recon (params + nuclei tags)
        pre_validated: List[Finding] = []
        try:
            progress.console.log("   [cyan]→ Running targeted recon-inferred validations...[/]")
            sem_target = asyncio.Semaphore(10)
            
            state_for_validation = {"target": self.target, "endpoints": self.session.endpoints} # Simplified state

            async def _run_infer(ep: str, param: str, vuln_type: str):
                async with sem_target:
                    try:
                        validator = self.validator_registry.get_validator_by_vuln_type(vuln_type)
                        if validator and hasattr(validator, "validate"):
                             return vuln_type, ep, param, await validator.validate(ep, param, state=state_for_validation)
                        return vuln_type, ep, param, None
                    except Exception:
                        return vuln_type, ep, param, None

            tasks = []
            for ep in self.session.endpoints:
                params_for_ep = list(param_map.get(ep, [])) if isinstance(param_map, dict) else []
                if not params_for_ep:
                    from urllib.parse import urlsplit, parse_qsl
                    try:
                        qs_pairs = parse_qsl(urlsplit(ep).query or "", keep_blank_values=True)
                        params_for_ep.extend([k for k, _ in qs_pairs])
                    except Exception:
                        pass

                for p in params_for_ep:
                    vuln_types = self.validator_registry.infer_vuln_types(p, nuclei_tags=list(nuclei_tags) if isinstance(nuclei_tags, set) else [])
                    for vt in vuln_types:
                        tasks.append(asyncio.create_task(_run_infer(ep, p, vt)))

            if tasks:
                completed = await asyncio.gather(*tasks)
                for vt, ep, p, res in completed:
                    if res:
                        out = res if isinstance(res, dict) else {"result": res}
                        out.setdefault("validator_id", vt)
                        processed = out # Simplified processing
                        if processed.get("success"):
                            evidence = processed.get("evidence") if isinstance(processed.get("evidence"), dict) else {}
                            request_blob = evidence.get("request") if isinstance(evidence, dict) else {}
                            endpoint = request_blob.get("target") or request_blob.get("url") or ep
                            title = processed.get("vulnerability") or processed.get("validator_id") or vt
                            f = Finding(
                                id=str(uuid.uuid4())[:8],
                                title=str(title),
                                severity=str(processed.get("severity") or "medium"),
                                endpoint=str(endpoint),
                                evidence=str(evidence.get("matched") or ""),
                                validated=True,
                            )
                            sev_score = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0}
                            f.score = sev_score.get(f.severity, 0.0)

                            pre_validated.append(f)
        except Exception:
            pre_validated = []

        validated = list(pre_validated)
        for nf in nuclei_findings:
            info = nf.get("info", {})
            sev = info.get("severity", "info")
            if sev == "info": continue
            f = Finding(
                id=str(uuid.uuid4())[:8],
                title=info.get("name", "Nuclei finding"),
                severity=sev,
                endpoint=nf.get("matched-at", ""),
                evidence=nf.get("template-id", ""),
                validated=True,
                cve=info.get("classification", {}).get("cve-id", []) or [],
            )
            sev_score = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0}
            f.score = sev_score.get(sev, 0.0)
            validated.append(f)

        header_map = {}
        for host in alive:
            if not isinstance(host, dict):
                continue
            webserver = host.get("webserver")
            content_type = host.get("content_type")
            if isinstance(webserver, str) and webserver:
                header_map.setdefault("Server", webserver)
            if isinstance(content_type, str) and content_type:
                header_map.setdefault("Content-Type", content_type)

        signal_bag = extract_signals(alive, port_results, self.session.endpoints, header_map, fact_store=self.fact_store)
        selected_validators, selection_reasons = self.validator_registry.select_validators(signal_bag, auth_manager=self.auth_manager)
        tech_confirmed = bool(signal_bag.get("tech"))

        if tech_confirmed:
            progress.update(validation_task, advance=10, description="[magenta]Phase 2: Validation (Tech fingerprint confirmed)")
        else:
            progress.update(validation_task, description="[magenta]Phase 2: Validation (Awaiting tech fingerprint)")

        if self.fast and len(selected_validators) > 8:
            selected_validators = selected_validators[:8]
            selection_reasons = {validator.__class__.__name__: selection_reasons.get(validator.__class__.__name__, []) for validator in selected_validators}

        if selected_validators:
            progress.console.log(f"   [bold green]→ Selected {len(selected_validators)} validators based on runtime signals[/]")

        recon_report_payload = {
            "findings": [nf for nf in nuclei_findings if isinstance(nf, dict)],
            "signal_coverage": {
                "detected_signals": signal_bag,
                "selected_validators": {
                    "validators": [v.__class__.__name__ for v in selected_validators],
                    "why": selection_reasons,
                },
            },
            "attack_chains": [],
        }
        try:
            recon_report_paths = JSONReporter.write(self.session, out_dir=self.output_dir, report_payload=recon_report_payload)
            self.session.data["recon_report_paths"] = recon_report_paths
            self.session.data["recon_fact_count"] = JSONReporter.load_into_fact_store(recon_report_paths.get("json", ""), self.fact_store)
        except Exception as exc:
            progress.console.log(f"[yellow]► Recon JSON report bridge skipped → {exc}[/]")

        for validator in selected_validators:
            if not getattr(validator, "validator_id", None):
                validator.validator_id = validator.__class__.__name__.replace("Validator", "").lower()

        protocols = sorted({str(h.get("scheme") or "").lower() for h in alive if isinstance(h, dict) and h.get("scheme")})
        target_url = scan_targets[0] if scan_targets else (self.target if self.target.startswith(("http://", "https://")) else f"https://{self.target}")

        # ── Pre-scan authentication ───────────────────────────────────────────
        progress.console.log("   [cyan]→ Attempting pre-scan authentication...[/]")
        try:
            # Auto-detect login endpoint using AuthManager
            login_info = self.auth_manager.detect_login_endpoint(list(self.session.endpoints))
            if login_info:
                login_url = login_info["url"]
                user_field = login_info["user_field"]
                pass_field = login_info["pass_field"]
            else:
                login_url = urljoin(target_url, "/doLogin")
                user_field = "uid"
                pass_field = "passw"

            # Try login
            success = self.auth_manager.login(login_url, user_field, pass_field)
            if success:
                self._auth_cookies = self.auth_manager.auth_cookies
                progress.console.log(
                    f"   [bold green]✓ Authenticated as '{self.auth_manager.credentials.get('username')}' "
                    f"at {login_url}[/]"
                )
                # Attempt second user login if provided
                if self.auth_manager.credentials2:
                    success2 = self.auth_manager.login_user2(login_url, user_field, pass_field)
                    if success2:
                        progress.console.log(
                            f"   [bold green]✓ Authenticated user2 as '{self.auth_manager.credentials2.get('username')}'[/]"
                        )
            else:
                progress.console.log("   [yellow]⚠ Pre-scan auth failed — scanning unauthenticated[/]")
        except Exception as e:
            progress.console.log(f"   [yellow]⚠ Auth manager error: {e}[/]")
            self._auth_cookies = {}

        state = {
            "target": self.target,
            "url": target_url,
            "endpoints": self.session.endpoints,
            "subdomains": self.session.subdomains,
            "findings": [nf for nf in nuclei_findings if isinstance(nf, dict)],
            "ports": signal_bag.get("ports", []),
            "tech": signal_bag.get("tech", []),
            "param_patterns": signal_bag.get("param_patterns", []),
            "endpoint_patterns": signal_bag.get("endpoint_patterns", []),
            "header_patterns": signal_bag.get("header_patterns", []),
            "facts": signal_bag.get("facts", []),
            "headers": header_map,
            "protocols": protocols,
            "fact_store": self.fact_store,
            "browser": None,
            "scan_id": self.session.id,
            # Auth state — propagated to all validators
            "auth_cookies": self._auth_cookies,
            "auth_session": self.auth_manager.session,
            "auth_manager": self.auth_manager,
        }

        self._start_shared_browser()
        state["browser"] = self._browser

        # Simplified validation loop without complex DAG/GNN/MCTS
        try:
            validation_tasks = []
            sem = asyncio.Semaphore(10)
            async def run_validation(validator):
                async with sem:
                    if hasattr(validator, "run"):
                        res = validator.run(state)
                        if asyncio.iscoroutine(res):
                            return await res
                        return res
                    return None

            for validator in selected_validators:
                validation_tasks.append(run_validation(validator))

            results = await asyncio.gather(*validation_tasks)
            flat_results = []
            for r in results:
                if isinstance(r, list):
                    for item in r:
                        if hasattr(item, "to_dict"):
                            flat_results.append(item.to_dict())
                        elif isinstance(item, dict):
                            flat_results.append(item)
                elif r:
                    if hasattr(r, "to_dict"):
                        flat_results.append(r.to_dict())
                    elif isinstance(r, dict):
                        flat_results.append(r)
            results = flat_results

            validation_queue = []
            for result in results:
                if result.get("success"):
                    validator_id = result.get("validator_id") or result.get("validator_class") or "unknown_validator"
                    self.attack_chain_manager.validator_completed(str(validator_id), result)

                if result.get("success"):
                    severity = result.get("severity") or ((result.get("validation") or {}).get("severity")) or "medium"
                    endpoint = ""
                    evidence = result.get("evidence") if isinstance(result.get("evidence"), dict) else {}
                    request_blob = evidence.get("request")
                    if isinstance(request_blob, dict):
                        endpoint = request_blob.get("target") or request_blob.get("url") or ""
                    title = result.get("vulnerability") or result.get("validator_id") or "validated-finding"
                    finding = Finding(
                        id=str(uuid.uuid4())[:8],
                        title=str(title),
                        severity=str(severity),
                        endpoint=str(endpoint),
                        evidence=str(evidence.get("matched") or ""),
                        validated=True,
                    )
                    sev_score = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0}
                    finding.score = sev_score.get(finding.severity, 0.0)
                    
                    try:
                        self.evidence_store.store_http_pair(
                            finding.id,
                            request_blob if isinstance(request_blob, dict) else {"raw": str(request_blob)},
                            response_blob if isinstance(response_blob, dict) else {"raw": str(response_blob)}
                        )
                    except Exception as e:
                        pass
                        
                    validated.append(finding)

            for finding in validated:
                try:
                    self.evidence_store.generate_bundle(finding.id)
                except Exception as e:
                    pass

            progress.update(validation_task, advance=50, description="[magenta]Phase 2: Validation (Complete)")

            self.session.findings = validated
            progress.console.log(f"[bold green]   → {len(validated)} VALIDATED findings[/]")

            # Save and HTML Report
            path = self.session.save()
            try: # Reporting block
                report_payload = self._build_report_payload(signal_bag, selection_reasons, selected_validators, results)

                # ── Deduplicate findings before any report output ─────────
                report_payload["findings"] = dedup_findings(report_payload.get("findings", []))
                self.session.findings = dedup_finding_objects(self.session.findings or [])
                progress.console.log(f"[cyan]► Dedup: {len(report_payload['findings'])} unique findings after deduplication[/]")

                # ── Evaluate Attack Chains ────────────────────────────────
                try: # Chain Engine
                    chain_engine = ChainEngine(CHAIN_RULES)
                    attack_chains = chain_engine.evaluate(report_payload.get("findings", []))
                    report_payload["attack_chains"] = attack_chains
                    progress.console.log(f"[cyan]► Attack Chains: {len(attack_chains)} chains correlated[/]")
                except Exception as ce_exc:
                    progress.console.log(f"[yellow]► Attack Chain Engine evaluation failed (non-fatal): {ce_exc}[/]")

                html_reporter = HTMLReporter()
                report_paths = html_reporter.write(self.session, out_dir=self.output_dir, report_payload=report_payload)
                
                try:
                    sarif_reporter = SARIFReporter()
                    sarif_dict = sarif_reporter.generate(
                        findings=report_payload.get("findings", []),
                        target=self.target,
                        evidence_store=self.evidence_store,
                        scan_id=self.session.id if hasattr(self.session, "id") else None,
                        attack_chains=report_payload.get("attack_chains", []),
                    )
                    sarif_path = f"{self.output_dir}/{self.session.id}.sarif" if hasattr(self.session, "id") else f"{self.output_dir}/scan_results.sarif"
                    sarif_written = sarif_reporter.write(sarif_dict, sarif_path)
                    report_paths["sarif"] = sarif_written
                    progress.console.log(f"[green]► SARIF Report generated → {sarif_written}[/]")
                except Exception as e:
                    progress.console.log(f"[yellow]► SARIF Report failed → {e}[/]")

                self.session.data["report_paths"] = report_paths
                self.session.save()
                progress.console.log(f"[green]► HTML Report generated → {report_paths.get('html', '')}[/]")
                # JSON report is part of HTML reporter output

            except Exception as e:
                progress.console.log(f"[red]► HTML Report failed → {e}[/]")
            finally:
                self._stop_shared_browser()

            progress.console.log(f"[green]► Session saved → {path}[/]")

        except Exception as validation_exc:
            progress.console.log(f"[red]► Validation pipeline error: {validation_exc}[/]")
            self._stop_shared_browser()

        return self.session
