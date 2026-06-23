import asyncio
import uuid
import time
import socket
from typing import Any, Dict, List
from urllib.parse import urlparse
from rich.panel import Panel

from modules.pipeline.recon import subfinder_runner, amass_runner, crtsh_runner
from modules.pipeline.probing import httpx_probe, waf_detect
from modules.pipeline.discovery import katana_crawler, gau_runner
from modules.recon.config import settings as recon_settings
from modules.pipeline.scanning import nuclei_runner

from modules.recon.modules.js_extractor import extract_js_endpoints
from modules.recon.modules.param_miner import mine_parameters
from modules.recon.reporting import html_report, json_report
from modules.pipeline.brain.attack_chain_manager import AttackChainManager
from modules.pipeline.brain.fact_store import FactStore, FactCategory
from modules.pipeline.brain.dag_engine_enhanced import DAGBrain
from modules.pipeline.engine.validation_engine_enhanced import ValidationEngine

from core.session import Session, Finding
from core.scoring import score_finding
from core.signal_extractor import extract_signals
from core.validator_selector import discover_validators, select_validators
from core.chain_expander import ChainExpander
from modules.pipeline.validation import registry
from core.evidence_store import EvidenceStore
from core.self_training import OutcomeDB, AttackSelector, PostScanFineTuner
from core.auth_manager import AuthManager
from core.dedup import dedup_findings, dedup_finding_objects
from core.evidence_collector import EvidenceCollector

try:
    from avvp.services.oob_canary import start_oob_server, stop_oob_server
except Exception:
    start_oob_server = None
    stop_oob_server = None

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

class Orchestrator:
    def __init__(self, target: str, fast: bool = True, scope: list = None, output_dir: str = "reports", enable_oob: bool = True):
        self.target = target
        self.session = Session(target=target)
        self.fast = fast
        self.scope = scope or []
        self.output_dir = output_dir
        self.enable_oob = enable_oob

        self.fact_store = FactStore()
        self.attack_chain_manager = AttackChainManager(self.fact_store)
        self.dag_brain = DAGBrain(use_graph_engine=True, fact_store=self.fact_store)
        self.validation_engine = ValidationEngine(
            fact_store=self.fact_store,
            attack_chain_manager=self.attack_chain_manager,
        )
        self.chain_expander = ChainExpander(self.attack_chain_manager)
        self.evidence_store = EvidenceStore(output_dir=f"{self.output_dir}/evidence")
        self.evidence_collector = EvidenceCollector(base_dir="_output/evidence")

        # Wire evidence collector into BaseValidator so all validators can
        # capture raw HTTP evidence at confirmation time (Part D).
        try:
            from modules.pipeline.validators.base import BaseValidator as _BV
            _BV.set_evidence_collector(self.evidence_collector)
        except Exception:
            pass
        self.outcome_db = OutcomeDB(db_path=f"data/outcomes.db")
        self.attack_selector = AttackSelector(self.outcome_db)
        self.fine_tuner = PostScanFineTuner()
        self._playwright = None
        self._browser = None
        self._oob_server = None
        self._oob_base_url = None
        # Pre-scan authentication manager
        self.auth_manager = AuthManager(target=target)
        self._auth_cookies: dict = {}

        # Ensure validators are imported and registered
        try:
            registry.auto_discover()
        except Exception:
            pass

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

    async def _start_oob_server(self) -> None:
        """Start the OOB canary server."""
        if not self.enable_oob or not start_oob_server:
            return

        try:
            local_ip = self._get_local_ip()
            self._oob_server = await start_oob_server(host=local_ip, port=8877)
            self._oob_base_url = f"http://{local_ip}:8877"
            from rich.console import Console
            console = Console()
            console.log(f"[green]✓ OOB Canary ready[/] at {self._oob_base_url}")
        except Exception as e:
            from rich.console import Console
            console = Console()
            console.log(f"[yellow]⚠ OOB Canary failed to start: {e}[/]")
            self._oob_server = None
            self._oob_base_url = None

    async def _stop_oob_server(self) -> None:
        """Stop the OOB canary server."""
        if self._oob_server and stop_oob_server:
            try:
                await stop_oob_server()
                self._oob_server = None
                self._oob_base_url = None
            except Exception as e:
                from rich.console import Console
                console = Console()
                console.log(f"[yellow]⚠ OOB Canary failed to stop: {e}[/]")

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

    def _collect_attack_chain_report(self) -> List[Dict[str, Any]]:
        chains: List[Dict[str, Any]] = []
        for fact in self.fact_store.get_facts_by_category(FactCategory.CONFIRMED_VULNERABILITY):
            metadata = fact.metadata if isinstance(fact.metadata, dict) else {}
            chain_id = metadata.get("chain_id")
            if not chain_id:
                continue
            action = metadata.get("next_action") or "execute follow-up action"
            chains.append(
                {
                    "chain_id": chain_id,
                    "narrative_steps": [
                        f"Trigger fact observed: {fact.key}",
                        f"Chain manager selected action: {action}",
                        f"New chain fact emitted with confidence {fact.confidence}",
                    ],
                    "evidence": str(metadata),
                }
            )
        return chains

    def _build_report_payload(
        self,
        signal_bag: Dict[str, Any],
        selection_reasons: Dict[str, List[str]],
        selected_validators: List[Any],
        validation_results: List[Dict[str, Any]],
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

            score = float((result.get("validation") or {}).get("confidence_score") or result.get("confidence") or 0.0)
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

            # Extract evidence file paths if captured at confirm time (Part D)
            evidence_req_path = ""
            evidence_res_path = ""
            evidence_bundle_data = result.get("evidence_bundle")
            if isinstance(evidence_bundle_data, dict):
                bundle_meta = evidence_bundle_data.get("metadata") or {}
                if isinstance(bundle_meta, dict):
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
            "attack_chains": self._collect_attack_chain_report(),
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
        progress.update(recon_task, advance=5, description="[cyan]Phase 1: Reconnaissance (Starting tools)")
        
        subfinder_task = asyncio.create_task(_timed("subfinder", subfinder_runner.run(self.target), timeout=90 if self.fast else 120, progress=progress))
        crtsh_task = asyncio.create_task(_timed("crtsh", crtsh_runner.run(self.target), timeout=30 if self.fast else 45, progress=progress))

        amass_task = None
        if not self.fast:
            amass_task = asyncio.create_task(_timed("amass-passive", amass_runner.run(self.target), timeout=180, progress=progress))

        subfinder_results = await subfinder_task

        progress.update(recon_task, advance=15, description="[cyan]Phase 1: Reconnaissance (Probing Subfinder hosts)")

        initial_targets = sorted(set(subfinder_results)) if subfinder_results else [self.target]
        initial_targets = [t for t in initial_targets if self.is_in_scope(t)]

        httpx_task = asyncio.create_task(_timed("httpx", httpx_probe.probe(initial_targets, max_tiers=1 if self.fast else 3), timeout=20 if self.fast else 300, progress=progress))

        crtsh_results = await crtsh_task
        amass_results = await amass_task if amass_task else []

        all_recon_results = list(subfinder_results) + list(crtsh_results) + list(amass_results)
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
            extra_alive = await _timed("httpx (extra)", httpx_probe.probe(untested_domains, max_tiers=1 if self.fast else 3), timeout=20 if self.fast else 300, progress=progress)
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
                return host["url"], await _timed(f"wafw00f {host['url']}", waf_detect.detect(host["url"]), timeout=60, progress=progress)
                
        waf_tasks = [run_waf(host) for host in alive[:3]]
        waf_results = await asyncio.gather(*waf_tasks)
        for url, waf in waf_results:
            self.session.waf[url] = waf or "unknown"
            
        progress.update(recon_task, advance=10, description="[cyan]Phase 1: Reconnaissance (WAF complete)")

        endpoints = set()
        sem_katana = asyncio.Semaphore(10)
        async def run_katana(host, depth=2):
            async with sem_katana:
                return await _timed(f"katana {host['url']}", katana_crawler.crawl(host["url"], depth=depth), timeout=20 if self.fast else 180, progress=progress)
                
        # Use configured tool timeout if available (longer than fast-mode default)
        katana_timeout = getattr(recon_settings, "TOOL_TIMEOUT", 180)
        # wrap run_katana to pass a per-call timeout via the _timed helper
        async def run_katana_with_timeout(host, depth=2):
            return await _timed(f"katana {host['url']}", katana_crawler.crawl(host["url"], depth=depth), timeout=katana_timeout if katana_timeout else (20 if self.fast else 180), progress=progress)

        katana_tasks = [run_katana_with_timeout(host, depth=4 if deep_crawl else 2) for host in alive[:10]]
        katana_results = await asyncio.gather(*katana_tasks)
        for crawled in katana_results:
            if crawled: endpoints.update(crawled)
            
        gau_timeout = getattr(recon_settings, "TOOL_TIMEOUT", 180)
        gau_eps = await _timed("gau", gau_runner.run(self.target), timeout=gau_timeout if gau_timeout else (20 if self.fast else 300), progress=progress)
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

        # Build a compact inference map: endpoint -> param -> inferred vuln types (pre-nuclei)
        inference_map: Dict[str, Dict[str, List[str]]] = {}
        try:
            from urllib.parse import urlsplit, parse_qsl

            for ep in list(endpoints)[:200]:
                params_for_ep = []
                if isinstance(param_map, dict) and ep in param_map:
                    params_for_ep = param_map.get(ep) or []
                else:
                    try:
                        qs_pairs = parse_qsl(urlsplit(ep).query or "", keep_blank_values=True)
                        params_for_ep = [k for k, _ in qs_pairs]
                    except Exception:
                        params_for_ep = []

                if not params_for_ep:
                    continue

                local = {}
                for p in params_for_ep:
                    try:
                        inferred = registry.infer_vuln_types(p, nuclei_tags=None) or []
                    except Exception:
                        inferred = []
                    if inferred:
                        local[p] = inferred
                if local:
                    inference_map[ep] = local
        except Exception:
            inference_map = {}

        # Prepare a single recon panel with counts and inferred vuln hints
        recon_lines: List[str] = []
        try:
            if inference_map:
                cnt = sum(len(v) for v in inference_map.values())
                recon_lines.append(f"Inferred {cnt} vuln-hints across {len(inference_map)} endpoints")
                shown = 0
                for ep, params in list(inference_map.items())[:12]:
                    parts = [f"{p}->[{', '.join(params[p])}]" for p in params]
                    recon_lines.append(f"  {ep} : {', '.join(parts)}")
                    shown += 1
                    if shown >= 12:
                        break
        except Exception:
            recon_lines.append("(inference unavailable)")

        self.session.endpoints = sorted(endpoints)

        # Recon summary: show basic counts
        try:
            js_count = len(js_res.get("endpoints") or []) if js_res else 0
        except Exception:
            js_count = 0

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

        from modules.pipeline.recon.naabu_scan import run_naabu

        async def async_naabu():
            try:
                return await asyncio.get_running_loop().run_in_executor(None, run_naabu, self.target)
            except Exception:
                return {}

        naabu_task = asyncio.create_task(_timed("naabu", async_naabu(), timeout=30 if self.fast else 600, progress=progress))
        nuclei_task = asyncio.create_task(_timed("nuclei", nuclei_runner.scan(scan_targets, tags=list(tech_tags)), timeout=60 if self.fast else 900, progress=progress))

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

        # Recompute inference map using nuclei tags to refine suggestions and add to recon_lines
        try:
            if inference_map and nuclei_tags:
                recon_lines.append(f"Refined with nuclei tags: {', '.join(sorted(list(nuclei_tags))[:6])}")
                refined_cnt = 0
                shown = 0
                for ep, params in list(inference_map.items())[:12]:
                    new_parts = []
                    for p in params:
                        try:
                            new_inferred = registry.infer_vuln_types(p, nuclei_tags=list(nuclei_tags)) or []
                        except Exception:
                            new_inferred = []
                        if new_inferred:
                            new_parts.append(f"{p}->[{', '.join(new_inferred)}]")
                            refined_cnt += len(new_inferred)
                    if new_parts:
                        recon_lines.append(f"  {ep} : {', '.join(new_parts)}")
                        shown += 1
                    if shown >= 12:
                        break
                if refined_cnt == 0:
                    recon_lines.append("  (no additional refinements from nuclei tags)")
        except Exception:
            recon_lines.append("(refinement unavailable)")

        # Print a single, readable recon summary panel
        try:
            from rich.panel import Panel as _Panel
            panel_lines = [f"Alive hosts: {len(alive)}", f"Subdomains: {len(merged)}", f"Endpoints: {len(self.session.endpoints)}", f"JS endpoints: {js_count}"]
            panel_lines.extend(recon_lines[:50])
            progress.console.log(_Panel("\n".join(panel_lines), title="Recon Summary", style="cyan"))
        except Exception:
            # Fallback to simple logging
            progress.console.log(f"   Recon: hosts={len(alive)} subs={len(merged)} endpoints={len(self.session.endpoints)} js={js_count}")

        # Run targeted validations inferred from recon (params + nuclei tags)
        pre_validated: List[Finding] = []
        try:
            progress.console.log("   [cyan]→ Running targeted recon-inferred validations...[/]")
            sem_target = asyncio.Semaphore(10)

            async def _run_infer(ep: str, param: str, vuln_type: str):
                async with sem_target:
                    try:
                        return vuln_type, ep, param, await registry.validate(vuln_type, ep, param, state=state)
                    except Exception:
                        return vuln_type, ep, param, None

            tasks = []
            for ep in self.session.endpoints:
                params_for_ep = param_map.get(ep, []) if isinstance(param_map, dict) else []
                if not params_for_ep:
                    from urllib.parse import urlsplit, parse_qsl
                    try:
                        qs_pairs = parse_qsl(urlsplit(ep).query or "", keep_blank_values=True)
                        params_for_ep = [k for k, _ in qs_pairs]
                    except Exception:
                        params_for_ep = []

                for p in params_for_ep:
                    vuln_types = registry.infer_vuln_types(p, nuclei_tags=list(nuclei_tags) if isinstance(nuclei_tags, set) else nuclei_tags)
                    for vt in vuln_types:
                        tasks.append(asyncio.create_task(_run_infer(ep, p, vt)))

            if tasks:
                completed = await asyncio.gather(*tasks)
                for vt, ep, p, res in completed:
                    if res:
                        out = res if isinstance(res, dict) else {"result": res}
                        out.setdefault("validator_id", vt)
                        out.setdefault("vulnerability", out.get("type") or vt)
                        try:
                            processed = self.validation_engine.result_processor.process_result(out)
                        except Exception:
                            processed = out
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
                            f.score = score_finding({"severity": f.severity, "validated": True})
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
            f.score = score_finding({"severity": sev, "validated": True})
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
        discovered_validators = discover_validators(auth_manager=self.auth_manager)
        selected_validators, selection_reasons = select_validators(signal_bag, discovered_validators, return_reasons=True)
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
            recon_report_paths = json_report.write(self.session, out_dir=self.output_dir, report_payload=recon_report_payload)
            self.session.data["recon_report_paths"] = recon_report_paths
            self.session.data["recon_fact_count"] = json_report.load_into_fact_store(recon_report_paths.get("json", ""), self.fact_store)
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

        # Start OOB canary server
        await self._start_oob_server()

        try:
            from core.normalized_client import NormalizedHTTPClient
            normalized_client = NormalizedHTTPClient(profile_name="chrome124", timer_mode="web")
        except Exception as e:
            normalized_client = None

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
            "oob_server": self._oob_server,
            "oob_base_url": self._oob_base_url,
            "scan_id": self.session.id,
            "normalized_client": normalized_client,
            "attack_selector": self.attack_selector,
            "outcome_db": self.outcome_db,
            # Auth state — propagated to all validators
            "auth_cookies": self._auth_cookies,
            "auth_session": self.auth_manager.session,
            "auth_manager": self.auth_manager,
        }

        self._start_shared_browser()
        state["browser"] = self._browser

        try:
            from core.gnn_model import SimpleGNN
            from core.mcts_planner import DeadlineAwareMCTS
            from core.attack_graph import AttackGraphNode
            
            nodes = []
            for i, val in enumerate(selected_validators):
                score = getattr(val, "priority", 0) / 100.0
                vid = getattr(val, "validator_id", val.__class__.__name__)
                nodes.append(AttackGraphNode(
                    node_id=f"val_{i}",
                    url=target_url,
                    priority_score=score,
                    tags=[vid]
                ))
            
            self.outcome_db.record_scan(self.session.id, target_url, int(time.time()))
            
            gnn = SimpleGNN()
            mcts = DeadlineAwareMCTS(gnn, scan_deadline_epoch=time.time() + 300)
            ordered_nodes = mcts.plan(nodes, budget_seconds=300)
            
            ordered_validators = []
            for node in ordered_nodes:
                idx = int(node.node_id.split("_")[1])
                ordered_validators.append(selected_validators[idx])
                
            plan = self.dag_brain.build_plan(state, ordered_validators)
            results = self.validation_engine.run(plan, state)

            validation_queue = []
            for result in results:
                if not isinstance(result, dict):
                    continue

                if result.get("success"):
                    validator_id = result.get("validator_id") or result.get("validator_class") or "unknown_validator"
                    self.attack_chain_manager.validator_completed(str(validator_id), result)
                    self.chain_expander.check_and_expand(self.fact_store, validation_queue)

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
                    finding.score = score_finding({"severity": finding.severity, "validated": True})
                    
                    try:
                        self.evidence_store.store_http_pair(
                            finding.id,
                            request_blob if isinstance(request_blob, dict) else {"raw": str(request_blob)},
                            response_blob if isinstance(response_blob, dict) else {"raw": str(response_blob)}
                        )
                    except Exception as e:
                        pass
                        
                    validated.append(finding)

            try:
                for order, node in enumerate(ordered_nodes):
                    idx = int(node.node_id.split("_")[1])
                    val = selected_validators[idx]
                    vid = getattr(val, "validator_id", val.__class__.__name__)
                    led = 1 if any(getattr(r, "validator_id", getattr(r, "validator_class", "")) == vid for r in results if isinstance(r, dict) and r.get("success")) else 0
                    self.outcome_db.record_node_decision(self.session.id, node.node_id, node.priority_score, order, led, node.featurize())
                
                for f in validated:
                    self.outcome_db.record_finding(f.id, self.session.id, f.severity, f.endpoint, f.score)
                asyncio.create_task(self.fine_tuner.run_in_background(gnn, self.session.id, self.outcome_db))
            except Exception as e:
                pass

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
            try:
                report_payload = self._build_report_payload(signal_bag, selection_reasons, selected_validators, results)

                # ── Deduplicate findings before any report output ─────────
                report_payload["findings"] = dedup_findings(report_payload.get("findings", []))
                self.session.findings = dedup_finding_objects(self.session.findings or [])
                progress.console.log(f"[cyan]► Dedup: {len(report_payload['findings'])} unique findings after deduplication[/]")

                # ── Evaluate Attack Chains ────────────────────────────────
                try:
                    from chains.rules import CHAIN_RULES
                    from chains.engine import ChainEngine
                    chain_engine = ChainEngine(CHAIN_RULES)
                    attack_chains = chain_engine.evaluate(report_payload.get("findings", []))
                    report_payload["attack_chains"] = attack_chains
                    progress.console.log(f"[cyan]► Attack Chains: {len(attack_chains)} chains correlated[/]")
                except Exception as ce_exc:
                    progress.console.log(f"[yellow]► Attack Chain Engine evaluation failed (non-fatal): {ce_exc}[/]")
                    report_payload["attack_chains"] = []

                # ── Save evidence bundles to disk ─────────────────────────
                try:
                    self.evidence_collector.save_evidence(report_payload.get("findings", []))
                    evidence_dir = self.evidence_collector.directory
                    progress.console.log(f"[cyan]► Evidence: {len(report_payload['findings'])} bundles saved → {evidence_dir}[/]")
                except Exception as ev_exc:
                    progress.console.log(f"[yellow]► Evidence capture failed (non-fatal): {ev_exc}[/]")

                report_paths = html_report.write(self.session, out_dir=self.output_dir, report_payload=report_payload)
                
                try:
                    from core.sarif_reporter import SARIFReporter
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
                progress.console.log(f"[green]► JSON Report generated → {report_paths.get('json', '')}[/]")

                try:
                    import subprocess
                    import sys
                    sub_res = subprocess.run([sys.executable, "generate_report_pdf.py"], capture_output=True, text=True)
                    if sub_res.returncode == 0:
                        lines = sub_res.stdout.strip().split("\n")
                        pdf_line = [line for line in lines if "PDF report saved" in line]
                        if pdf_line:
                            progress.console.log(f"[green]► {pdf_line[0].strip()}[/]")
                        else:
                            progress.console.log(f"[green]► PDF Report generated successfully[/]")
                    else:
                        progress.console.log(f"[yellow]► PDF Report failed: {sub_res.stderr.strip()}[/]")
                except Exception as pe:
                    progress.console.log(f"[yellow]► PDF Report failed: {pe}[/]")
            except Exception as e:
                progress.console.log(f"[red]► HTML Report failed → {e}[/]")
            finally:
                self._stop_shared_browser()

            progress.console.log(f"[green]► Session saved → {path}[/]")
        finally:
            await self._stop_oob_server()

        return self.session
