import asyncio
import uuid
import time
from typing import Any, Dict, List
from urllib.parse import urlparse
from rich.panel import Panel

from modules.pipeline.recon import subfinder_runner, amass_runner, crtsh_runner
from modules.pipeline.probing import httpx_probe, waf_detect
from modules.pipeline.discovery import katana_crawler, gau_runner
from modules.pipeline.scanning import nuclei_runner

from modules.recon.modules.js_extractor import extract_js_endpoints
from modules.recon.modules.param_miner import mine_parameters
from modules.recon.reporting import html_report
from modules.pipeline.brain.attack_chain_manager import AttackChainManager
from modules.pipeline.brain.fact_store import FactStore, FactCategory
from modules.pipeline.brain.dag_engine_enhanced import DAGBrain
from modules.pipeline.engine.validation_engine_enhanced import ValidationEngine

from core.session import Session, Finding
from core.scoring import score_finding
from core.signal_extractor import extract_signals
from core.validator_selector import discover_validators, select_validators
from core.chain_expander import ChainExpander

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
    def __init__(self, target: str, fast: bool = True, scope: list = None, output_dir: str = "reports"):
        self.target = target
        self.session = Session(target=target)
        self.fast = fast
        self.scope = scope or []
        self.output_dir = output_dir
        
        self.fact_store = FactStore()
        self.attack_chain_manager = AttackChainManager(self.fact_store)
        self.dag_brain = DAGBrain(use_graph_engine=True, fact_store=self.fact_store)
        self.validation_engine = ValidationEngine(
            fact_store=self.fact_store,
            attack_chain_manager=self.attack_chain_manager,
        )
        self.chain_expander = ChainExpander(self.attack_chain_manager)
        self._playwright = None
        self._browser = None

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
                
        katana_tasks = [run_katana(host, depth=4 if deep_crawl else 2) for host in alive[:10]]
        katana_results = await asyncio.gather(*katana_tasks)
        for crawled in katana_results:
            if crawled: endpoints.update(crawled)
            
        gau_eps = await _timed("gau", gau_runner.run(self.target), timeout=20 if self.fast else 300, progress=progress)
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
        progress.console.log(f"   [bold green]→ {len(self.session.endpoints)} total endpoints found[/]")

        progress.console.log("[cyan]► Phase 2: Validation[/]")
        progress.update(validation_task, advance=10, description="[magenta]Phase 2: Validation (Nuclei)")
        scan_targets = [h["url"] for h in alive]
        
        tech_tags = set()
        for host in alive:
            if isinstance(host, dict) and host.get("tech"):
                for t in host["tech"]:
                    if isinstance(t, str): tech_tags.add(t.lower())
        
        from modules.pipeline.recon.naabu_scan import run_naabu
        async def async_naabu():
            try: return await asyncio.get_running_loop().run_in_executor(None, run_naabu, self.target)
            except Exception: return {}
        
        naabu_task = asyncio.create_task(_timed("naabu", async_naabu(), timeout=30 if self.fast else 600, progress=progress))
        nuclei_task = asyncio.create_task(_timed("nuclei", nuclei_runner.scan(scan_targets, tags=list(tech_tags)), timeout=60 if self.fast else 900, progress=progress))
        
        await asyncio.gather(naabu_task, nuclei_task)
        nuclei_findings = await nuclei_task
        port_results = await naabu_task

        validated = []
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

        progress.update(validation_task, advance=20, description="[magenta]Phase 2: Validation (Signal Selection)")

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
        discovered_validators = discover_validators()
        selected_validators, selection_reasons = select_validators(signal_bag, discovered_validators, return_reasons=True)

        if self.fast and len(selected_validators) > 8:
            selected_validators = selected_validators[:8]
            selection_reasons = {validator.__class__.__name__: selection_reasons.get(validator.__class__.__name__, []) for validator in selected_validators}

        if selected_validators:
            progress.console.log(f"   [bold green]→ Selected {len(selected_validators)} validators based on runtime signals[/]")

        for validator in selected_validators:
            if not getattr(validator, "validator_id", None):
                validator.validator_id = validator.__class__.__name__.replace("Validator", "").lower()

        protocols = sorted({str(h.get("scheme") or "").lower() for h in alive if isinstance(h, dict) and h.get("scheme")})
        target_url = scan_targets[0] if scan_targets else (self.target if self.target.startswith(("http://", "https://")) else f"https://{self.target}")

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
        }

        self._start_shared_browser()
        state["browser"] = self._browser

        plan = self.dag_brain.build_plan(state, selected_validators)
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
                validated.append(finding)

        progress.update(validation_task, advance=50, description="[magenta]Phase 2: Validation (Complete)")

        self.session.findings = validated
        progress.console.log(f"[bold green]   → {len(validated)} VALIDATED findings[/]")

        # Save and HTML Report
        path = self.session.save()
        try:
            report_payload = self._build_report_payload(signal_bag, selection_reasons, selected_validators, results)
            report_paths = html_report.write(self.session, out_dir=self.output_dir, report_payload=report_payload)
            self.session.data["report_paths"] = report_paths
            self.session.save()
            progress.console.log(f"[green]► HTML Report generated → {report_paths.get('html', '')}[/]")
            progress.console.log(f"[green]► JSON Report generated → {report_paths.get('json', '')}[/]")
        except Exception as e:
            progress.console.log(f"[red]► HTML Report failed → {e}[/]")
        finally:
            self._stop_shared_browser()
            
        progress.console.log(f"[green]► Session saved → {path}[/]")
        return self.session
