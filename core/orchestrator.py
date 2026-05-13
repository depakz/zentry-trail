import asyncio
import uuid
import time
from urllib.parse import urlparse
from rich.panel import Panel

# Import paths matching requirements
from modules.pipeline.recon import subfinder_runner, amass_runner, crtsh_runner
from modules.pipeline.probing import httpx_probe, waf_detect
from modules.pipeline.discovery import katana_crawler, gau_runner
from modules.pipeline.scanning import nuclei_runner
from modules.pipeline.validation import base_validator

from core.session import Session, Finding
from core.scoring import score_finding


async def _timed(name: str, coro, timeout: int, progress=None):
    """Wrap a coroutine with timing, timeout & live status."""
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
    def __init__(self, target: str, fast: bool = True):
        self.target = target
        self.session = Session(target=target)
        self.fast = fast

    async def run(self, progress, recon_task: int, validation_task: int):
        progress.console.log(Panel(f"🎯 Target: {self.target}  |  Fast mode: {self.fast}", style="bold cyan"))

        # ----- 1. RECON (Streaming) -----
        progress.console.log("[cyan]► Phase 1: Reconnaissance[/]")
        progress.update(recon_task, advance=5, description="[cyan]Phase 1: Reconnaissance (Starting tools)")
        
        # Start subfinder first to stream to httpx
        subfinder_task = asyncio.create_task(_timed("subfinder", subfinder_runner.run(self.target), timeout=120, progress=progress))
        crtsh_task = asyncio.create_task(_timed("crt.sh", crtsh_runner.run(self.target), timeout=45, progress=progress))
        
        amass_task = None
        if not self.fast:
            amass_task = asyncio.create_task(_timed("amass-passive", amass_runner.run(self.target), timeout=180, progress=progress))

        # Wait for subfinder to finish so we can stream to httpx immediately
        subfinder_results = await subfinder_task
        
        # ----- 2. PROBING (Streaming from subfinder) -----
        progress.update(recon_task, advance=15, description="[cyan]Phase 1: Reconnaissance (Probing Subfinder hosts)")
        
        initial_targets = sorted(set(subfinder_results)) if subfinder_results else [self.target]
        httpx_task = asyncio.create_task(_timed("httpx", httpx_probe.probe(initial_targets), timeout=300, progress=progress))

        # While httpx runs, wait for other recon tools
        crtsh_results = await crtsh_task
        amass_results = await amass_task if amass_task else []
        
        all_recon_results = list(subfinder_results) + list(crtsh_results) + list(amass_results)
        merged = sorted(set(all_recon_results))
        
        # The Logic Fix: force deep crawl if only root target is found
        # Compare effectively by stripping scheme if necessary
        target_no_scheme = urlparse(self.target).netloc or self.target.replace("http://", "").replace("https://", "")
        
        deep_crawl = False
        if not merged or (len(merged) == 1 and merged[0] in (self.target, target_no_scheme)):
            merged = [self.target]
            deep_crawl = True
            
        self.session.subdomains = merged
        progress.console.log(f"   [bold green]→ {len(merged)} unique subdomains[/]")

        alive = await httpx_task
        
        # Check if crtsh/amass added any new domains not checked by httpx
        untested_domains = [d for d in merged if d not in initial_targets]
        if untested_domains:
             extra_alive = await _timed("httpx (extra)", httpx_probe.probe(untested_domains), timeout=300, progress=progress)
             alive.extend(extra_alive)
             
        # Dedup alive hosts to ensure clean state
        seen = set()
        unique_alive = []
        for host in alive:
            if isinstance(host, dict) and "url" in host:
                if host["url"] not in seen:
                    seen.add(host["url"])
                    unique_alive.append(host)
            elif isinstance(host, str):
                if host not in seen:
                    seen.add(host)
                    unique_alive.append({"url": host})

        alive = unique_alive
        self.session.alive_hosts = alive
        progress.update(recon_task, advance=20, description="[cyan]Phase 1: Reconnaissance (Probing complete)")
        progress.console.log(f"   [bold green]→ {len(alive)} alive hosts[/]")

        if not alive:
            progress.console.log("[red]No alive hosts — aborting[/]")
            self.session.save()
            return self.session

        # ----- 3. WAF DETECT (Concurrency) -----
        progress.update(recon_task, advance=10, description="[cyan]Phase 1: Reconnaissance (WAF detection)")
        
        # Fastening the Work: Use asyncio.gather with Semaphore
        sem_waf = asyncio.Semaphore(5)
        async def run_waf(host):
            async with sem_waf:
                return host["url"], await _timed(f"wafw00f {host['url']}", waf_detect.detect(host["url"]), timeout=60, progress=progress)
                
        waf_tasks = [run_waf(host) for host in alive[:3]]
        waf_results = await asyncio.gather(*waf_tasks)
        for url, waf in waf_results:
            self.session.waf[url] = waf or "unknown"
            
        progress.update(recon_task, advance=10, description="[cyan]Phase 1: Reconnaissance (WAF complete)")

        # ----- 4. CRAWL/DISCOVER (Concurrency) -----
        progress.update(recon_task, advance=10, description="[cyan]Phase 1: Reconnaissance (Endpoint discovery)")
        endpoints = set()
        
        # Fastening the Work: Use asyncio.gather with Semaphore for Katana
        sem_katana = asyncio.Semaphore(10)
        async def run_katana(host, depth=2):
            async with sem_katana:
                return await _timed(f"katana {host['url']}", katana_crawler.crawl(host["url"], depth=depth), timeout=180, progress=progress)
                
        katana_tasks = [run_katana(host, depth=4 if deep_crawl else 2) for host in alive[:10]]
        katana_results = await asyncio.gather(*katana_tasks)
        for crawled in katana_results:
            if crawled:
                endpoints.update(crawled)
            
        progress.update(recon_task, advance=15, description="[cyan]Phase 1: Reconnaissance (Katana complete)")
        
        gau_eps = await _timed("gau", gau_runner.run(self.target), timeout=300, progress=progress)
        if gau_eps:
            endpoints.update(gau_eps)
            
        progress.update(recon_task, advance=15, description="[cyan]Phase 1: Reconnaissance (Complete)")
        
        self.session.endpoints = sorted(endpoints)
        progress.console.log(f"   [bold green]→ {len(self.session.endpoints)} endpoints found[/]")

        # ----- 5. NUCLEI SCAN -----
        progress.console.log("[cyan]► Phase 2: Validation[/]")
        progress.update(validation_task, advance=10, description="[magenta]Phase 2: Validation (Nuclei scan)")
        scan_targets = [h["url"] for h in alive]
        nuclei_findings = await _timed("nuclei", nuclei_runner.scan(scan_targets), timeout=1800, progress=progress)

        # ----- 6. VALIDATION -----
        validated: list[Finding] = []

        for nf in nuclei_findings:
            info = nf.get("info", {})
            sev = info.get("severity", "info")
            if sev == "info":
                continue
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

        progress.update(validation_task, advance=40, description="[magenta]Phase 2: Validation (Nuclei complete)")

        # Live XSS/SQLi only on parameterized URLs
        param_eps = [e for e in self.session.endpoints if "?" in e and "=" in e][:30]
        
        if param_eps:
            progress.console.log(f"   [yellow]Validating {len(param_eps)} parameterized endpoints...[/]")
            sem_val = asyncio.Semaphore(10)
            async def run_val(ep, param, ptype):
                async with sem_val:
                    return ep, ptype, await base_validator.validate(ptype, ep, param)
                    
            val_tasks = []
            for ep in param_eps:
                try:
                    param = ep.split("?", 1)[1].split("&")[0].split("=")[0]
                except Exception:
                    continue
                for ptype in ("xss", "sqli"):
                    val_tasks.append(run_val(ep, param, ptype))
                    
            val_results = await asyncio.gather(*val_tasks)
            
            for ep, ptype, result in val_results:
                if result and result.get("validated"):
                    f = Finding(
                        id=str(uuid.uuid4())[:8],
                        title=result["type"],
                        severity="high" if ptype == "sqli" else "medium",
                        endpoint=ep,
                        payload=result.get("payload", ""),
                        evidence=result.get("evidence", ""),
                        validated=True,
                        reproduction=[f"Open: {result.get('url', ep)}"],
                        impact="Confirmed via headless browser / time-based oracle",
                    )
                    f.score = score_finding({"severity": f.severity, "validated": True})
                    validated.append(f)
                    progress.console.log(f"   [bold red]🔥 VALIDATED {ptype.upper()}[/] on {ep}")
        else:
            progress.console.log("   [yellow]No parameterized endpoints found for deep validation.[/]")

        progress.update(validation_task, advance=50, description="[magenta]Phase 2: Validation (Complete)")

        self.session.findings = validated
        progress.console.log(f"[bold green]   → {len(validated)} VALIDATED findings[/]")

        # ----- 7. PERSIST -----
        path = self.session.save()
        progress.console.log(f"[green]► Session saved → {path}[/]")
        return self.session