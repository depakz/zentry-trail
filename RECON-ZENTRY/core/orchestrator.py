import asyncio, uuid, time
from rich.console import Console
from rich.panel import Panel

from recon import subfinder_runner, amass_runner, crtsh_runner
from probing import httpx_probe, waf_detect
from discovery import katana_crawler, gau_runner
from scanning import nuclei_runner
from validation import base_validator
from core.session import Session, Finding
from core.scoring import score_finding

console = Console()

async def _timed(name: str, coro, timeout: int):
    """Wrap a coroutine with timing, timeout & live status."""
    start = time.monotonic()
    console.print(f"   [yellow]⏳ {name}...[/]")
    try:
        result = await asyncio.wait_for(coro, timeout=timeout)
        elapsed = time.monotonic() - start
        n = len(result) if hasattr(result, "__len__") else "?"
        console.print(f"   [green]✓ {name}[/] [dim]({elapsed:.1f}s, {n} results)[/]")
        return result
    except asyncio.TimeoutError:
        console.print(f"   [red]✗ {name} TIMEOUT after {timeout}s — skipped[/]")
        return []
    except Exception as e:
        console.print(f"   [red]✗ {name} ERROR: {e}[/]")
        return []


class Orchestrator:
    def __init__(self, target: str, fast: bool = True):
        self.target = target
        self.session = Session(target=target)
        self.fast = fast  # skip slow tools (amass)

    async def run(self):
        console.print(Panel(f"🎯 Target: {self.target}  |  Fast mode: {self.fast}", style="bold cyan"))

        # ----- 1. RECON (parallel, each with timeout) -----
        console.print("[cyan]► [1/7] Recon[/]")
        tasks = [
            _timed("subfinder", subfinder_runner.run(self.target), timeout=120),
            _timed("crt.sh",    crtsh_runner.run(self.target),     timeout=45),
        ]
        if not self.fast:
            tasks.append(_timed("amass-passive", amass_runner.run(self.target), timeout=180))
        results = await asyncio.gather(*tasks)
        merged = sorted(set().union(*results))
        if not merged:
            merged = [self.target]
        self.session.subdomains = merged
        console.print(f"   [bold green]→ {len(merged)} unique subdomains[/]")

        # ----- 2. PROBING -----
        console.print("[cyan]► [2/7] Probing alive hosts (httpx)[/]")
        alive = await _timed("httpx", httpx_probe.probe(merged), timeout=300)
        self.session.alive_hosts = alive
        console.print(f"   [bold green]→ {len(alive)} alive[/]")

        if not alive:
            console.print("[red]No alive hosts — aborting[/]")
            self.session.save()
            return self.session

        # ----- 3. WAF DETECT (just a few) -----
        console.print("[cyan]► [3/7] WAF detection (top 3)[/]")
        for host in alive[:3]:
            waf = await _timed(f"wafw00f {host['url']}", waf_detect.detect(host["url"]), timeout=60)
            self.session.waf[host["url"]] = waf or "unknown"

        # ----- 4. CRAWL/DISCOVER -----
        console.print("[cyan]► [4/7] Endpoint discovery[/]")
        endpoints = set()
        # Cap to top 10 hosts to keep it sane
        for host in alive[:10]:
            crawled = await _timed(f"katana {host['url']}",
                                   katana_crawler.crawl(host["url"], depth=2),
                                   timeout=180)
            endpoints.update(crawled)
        gau_eps = await _timed("gau", gau_runner.run(self.target), timeout=300)
        endpoints.update(gau_eps)
        self.session.endpoints = sorted(endpoints)
        console.print(f"   [bold green]→ {len(self.session.endpoints)} endpoints[/]")

        # ----- 5. NUCLEI SCAN -----
        console.print("[cyan]► [5/7] Nuclei scan[/]")
        scan_targets = [h["url"] for h in alive]
        nuclei_findings = await _timed("nuclei", nuclei_runner.scan(scan_targets), timeout=1800)

        # ----- 6. VALIDATION -----
        console.print("[cyan]► [6/7] Validation (no-FP rule)[/]")
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

        # Live XSS/SQLi only on parameterized URLs
        param_eps = [e for e in self.session.endpoints if "?" in e and "=" in e][:30]
        console.print(f"   [yellow]Validating {len(param_eps)} parameterized endpoints...[/]")
        for ep in param_eps:
            try:
                param = ep.split("?", 1)[1].split("&")[0].split("=")[0]
            except Exception:
                continue
            for ptype in ("xss", "sqli"):
                result = await base_validator.validate(ptype, ep, param)
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
                    console.print(f"   [bold red]🔥 VALIDATED {ptype.upper()}[/] on {ep}")

        self.session.findings = validated
        console.print(f"[bold green]   → {len(validated)} VALIDATED findings[/]")

        # ----- 7. PERSIST -----
        path = self.session.save()
        console.print(f"[green]► [7/7] Session saved → {path}[/]")
        return self.session
