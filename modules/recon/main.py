#!/usr/bin/env python3
"""HACK WITH YUVA v4.0 — Elite Bug Bounty Weapon"""
import asyncio, sys
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

from core.session import Session
from core.logger import logger
from core.runner import have

# Existing modules (your current code)
from modules.recon.modules import recon, probe, discovery
# New modules
from modules.recon.modules import param_miner, smart_filter, fuzzer, exploiter
from modules.recon.modules import nuclei_scanner, response_analyzer, validator, reporter

# === YUVA PATCH: URL filter for param mining ===
_SKIP_EXT = ('.html', '.htm', '.json', '.js', '.css', '.png', '.jpg', '.jpeg',
             '.gif', '.ico', '.svg', '.woff', '.woff2', '.ttf', '.eot',
             '.axd', '.pdf', '.zip', '.xml', '.txt', '.map')
_SKIP_PATHS = ('/.well-known/', '/images/', '/Images/', '/static/',
               '/assets/', '/img/', '/css/', '/js/', '/fonts/',
               'CaptchaImage', 'WebResource.axd', 'ScriptResource.axd')

def _yuva_should_mine(url: str) -> bool:
    try:
        low = url.lower().split('?')[0]
        if low.endswith(_SKIP_EXT):
            return False
        if any(p.lower() in url.lower() for p in _SKIP_PATHS):
            return False
        return True
    except Exception:
        return False
# === END YUVA PATCH ===


console = Console()

BANNER = r"""
[bold red]██╗  ██╗ █████╗  ██████╗██╗  ██╗    ██╗    ██╗██╗████████╗██╗  ██╗
██║  ██║██╔══██╗██╔════╝██║ ██╔╝    ██║    ██║██║╚══██╔══╝██║  ██║
███████║███████║██║     █████╔╝     ██║ █╗ ██║██║   ██║   ███████║
██╔══██║██╔══██║██║     ██╔═██╗     ██║███╗██║██║   ██║   ██╔══██║
██║  ██║██║  ██║╚██████╗██║  ██╗    ╚███╔███╔╝██║   ██║   ██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝     ╚══╝╚══╝ ╚═╝   ╚═╝   ╚═╝  ╚═╝[/]
[bold cyan]                       Y U V A   v4.0   ELITE[/]
[yellow]   Recon→Discovery→ParamMine→Fuzz→Exploit→Nuclei→Validate[/]
"""

def banner():
    console.print(BANNER)
    console.print(Panel(
        "[bold red]LEGAL:[/] Authorized testing only. By continuing you confirm written permission.",
        border_style="red"))

def check_tools():
    tools = ["subfinder","httpx","katana","gau","nuclei","ffuf","arjun",
             "paramspider","dalfox","sqlmap"]
    t = console.print
    for x in tools:
        ok = have(x)
        t(f"  {'[green]✓[/]' if ok else '[red]✗[/]'} {x}")


async def run_recon_pipeline(target, fast=True):
    session = Session(target)

    subs = recon.run_recon(target, fast=fast)
    session.update("subdomains", subs)

    alive = probe.run_probe(subs)
    session.update("alive_hosts", alive)
    if not alive:
        result = {
            "target": target,
            "subdomains": subs,
            "alive_hosts": alive,
            "endpoints": [],
            "validation_targets": [],
            "ranked_targets": [],
            "params": [],
            "categories": [],
            "findings": [],
            "vulnerabilities": [],
            "response_analysis": {},
            "source": "recon_zentry",
        }
        session.update("normalized_state", result)
        return result

    endpoints = discovery.run_discovery(alive)
    session.update("endpoints", endpoints)

    extra_urls, params = await param_miner.mine_parameters(
        [a.replace("http://", "").replace("https://", "") for a in alive],
        endpoints,
        session,
    )
    all_urls = list(set(endpoints + extra_urls + alive))
    session.update("endpoints", all_urls)

    ranked = smart_filter.filter_and_rank(all_urls)
    cats = smart_filter.summarize(ranked, session)

    top_urls = [r["url"] for r in ranked[:30]]
    response_summary = await response_analyzer.analyze(top_urls, session)
    nuclei_findings = await nuclei_scanner.scan_with_nuclei(all_urls, session)

    validation_targets = []
    seen = set()
    for candidate in [*(r.get("url") for r in ranked if isinstance(r, dict)), *all_urls, target]:
        if not isinstance(candidate, str):
            continue
        candidate = candidate.strip()
        if not candidate.startswith(("http://", "https://")):
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        validation_targets.append(candidate)

    result = {
        "target": target,
        "subdomains": subs,
        "alive_hosts": alive,
        "endpoints": all_urls,
        "validation_targets": validation_targets,
        "ranked_targets": ranked,
        "params": params,
        "categories": sorted(cats.keys()) if isinstance(cats, dict) else [],
        "findings": nuclei_findings,
        "vulnerabilities": list(nuclei_findings),
        "response_analysis": response_summary,
        "source": "recon_zentry",
    }

    session.update("normalized_state", result)
    return result

async def full_scan(target, fast=True):
    session = Session(target)
    console.print(Panel(f"🎯 Target: [bold]{target}[/]  Fast: {fast}", border_style="cyan"))

    # 1. Recon
    console.rule("[bold]1/9 RECON")
    subs = recon.run_recon(target, fast=fast)
    session.update("subdomains", subs)

    # 2. Probe
    console.rule("[bold]2/9 PROBE")
    alive = probe.run_probe(subs)
    session.update("alive_hosts", alive)
    if not alive:
        console.print("[red]No alive hosts. Aborting.[/]"); return

    # 3. Discovery
    console.rule("[bold]3/9 DISCOVERY")
    endpoints = discovery.run_discovery(alive)
    session.update("endpoints", endpoints)

    # 4. Param Mining
    console.rule("[bold]4/9 PARAM MINING")
    extra_urls, params = await param_miner.mine_parameters(
        [a.replace("http://","").replace("https://","") for a in alive],
        endpoints, session)
    all_urls = list(set(endpoints + extra_urls))
    session.update("endpoints", all_urls)

    # 5. Smart Filter
    console.rule("[bold]5/9 SMART FILTER")
    ranked = smart_filter.filter_and_rank(all_urls)
    cats = smart_filter.summarize(ranked, session)

    # 6. Fuzzing
    console.rule("[bold]6/9 FUZZING")
    top_urls = [r["url"] for r in ranked[:30]]
    await fuzzer.fuzz_all(alive, top_urls, session)

    # 7. Response Analysis (must run BEFORE exploit to feed reflections)
    console.rule("[bold]7/9 RESPONSE ANALYSIS")
    await response_analyzer.analyze(top_urls, session)

    # 8. Exploitation (reflection-driven)
    console.rule("[bold]8/9 EXPLOITATION")
    exploit_findings = await exploiter.exploit(cats, session)

    # 9. Nuclei (full coverage)
    console.rule("[bold]9/9 NUCLEI")
    nuclei_findings = await nuclei_scanner.scan_with_nuclei(all_urls, session)

    # Validation
    console.rule("[bold]VALIDATION")
    await validator.validate_all(
        {"nuclei": nuclei_findings, "exploits": exploit_findings}, session)

    # Report
    console.rule("[bold]REPORT")
    reporter.report(session)
    console.print(f"💾 Session: [cyan]{session.path}[/]")

def menu():
    banner()
    console.print("""
[bold cyan]MENU[/]
 [1] 🚀 Full scan (all 9 phases)
 [2] 🔍 Recon only
 [3] 💥 Nuclei only (paste URL list)
 [4] 🔧 Tool check
 [0] Exit
""")
    return Prompt.ask("Select", choices=["0","1","2","3","4"], default="1")

def main():
    while True:
        opt = menu()
        if opt == "0": break
        if opt == "4": check_tools(); continue
        target = Prompt.ask("🎯 Target domain (e.g. vulnweb.com)")
        if not Confirm.ask(f"Authorized to test {target}?", default=False):
            console.print("[red]Aborted.[/]"); continue
        if opt == "1":
            fast = Confirm.ask("Fast mode?", default=True)
            asyncio.run(full_scan(target, fast))
        elif opt == "2":
            subs = recon.run_recon(target, fast=True)
            console.print(f"Found {len(subs)} subs")
        elif opt == "3":
            urls = Prompt.ask("Path to URL file").strip()
            try:
                with open(urls) as f: lst = [l.strip() for l in f if l.strip()]
                s = Session(target)
                asyncio.run(nuclei_scanner.scan_with_nuclei(lst, s))
                reporter.report(s)
            except FileNotFoundError:
                console.print("[red]File not found[/]")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/]"); sys.exit(0)
