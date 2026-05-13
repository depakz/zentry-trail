import sys

with open('modules/pipeline/integrations/recon_zentry_adapter.py', 'r') as f:
    content = f.read()

# Add run_binary and imports
content = content.replace("import asyncio",
"""import asyncio
from rich.progress import Progress""")

# Update run_recon_zentry signature
content = content.replace("async def run_recon_zentry(target: str) -> Dict[str, Any]:",
"""async def _run_binary(cmd: List[str]) -> str:
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await process.communicate()
        return stdout.decode(errors="ignore") if stdout else ""
    except Exception:
        return ""

async def run_recon_zentry(target: str, progress: Progress = None, recon_task: int = None) -> Dict[str, Any]:
    def _update_prog(detail: str):
        if progress and recon_task is not None:
            progress.update(recon_task, advance=10, description=f"[cyan]Reconnaissance: {detail}")
""")

# replace the synchronous execution block
old_exec = """    recon = modules["recon"]
    probe = modules["probe"]
    discovery = modules["discovery"]
    param_miner = modules["param_miner"]
    smart_filter = modules["smart_filter"]
    response_analyzer = modules["response_analyzer"]
    nuclei_scanner = modules["nuclei_scanner"]

    subdomains = await asyncio.to_thread(recon.run_recon, target_domain)
    if not isinstance(subdomains, list):
        subdomains = []
    subdomains = subdomains[: limits["subdomains"]]

    alive_hosts = await asyncio.to_thread(probe.run_probe, subdomains)
    if not isinstance(alive_hosts, list):
        alive_hosts = []
    alive_hosts = _limit_urls(alive_hosts, limits["alive"])

    endpoints = await asyncio.to_thread(discovery.run_discovery, alive_hosts)
    if not isinstance(endpoints, list):
        endpoints = []
    endpoints = _limit_urls(endpoints, limits["endpoints"])"""

new_exec = """    recon = modules["recon"]
    probe = modules["probe"]
    discovery = modules["discovery"]
    param_miner = modules["param_miner"]
    smart_filter = modules["smart_filter"]
    response_analyzer = modules["response_analyzer"]
    nuclei_scanner = modules["nuclei_scanner"]

    _update_prog("running subfinder and assetfinder concurrently")
    # A. Concurrent Recon using subprocess.PIPE with non-blocking reads and asyncio.gather
    subfinder_cmd = ["subfinder", "-d", target_domain, "-silent"]
    assetfinder_cmd = ["assetfinder", "--subs-only", target_domain]
    
    results = await asyncio.gather(
        _run_binary(subfinder_cmd),
        _run_binary(assetfinder_cmd),
        return_exceptions=True
    )
    
    sub_set = set()
    for res in results:
        if isinstance(res, str):
            for line in res.splitlines():
                if line.strip():
                    sub_set.add(line.strip())
                    
    subdomains = list(sub_set)[: limits["subdomains"]]
    if not subdomains:
        subdomains = await asyncio.to_thread(recon.run_recon, target_domain)
        subdomains = subdomains[: limits["subdomains"]] if isinstance(subdomains, list) else []

    _update_prog("probing alive hosts")
    alive_hosts = await asyncio.to_thread(probe.run_probe, subdomains)
    if not isinstance(alive_hosts, list):
        alive_hosts = []
    alive_hosts = _limit_urls(alive_hosts, limits["alive"])

    _update_prog("running gau and discovery concurrently")
    # discovery concurrently
    gau_cmd = ["gau", "--subs", target_domain]
    disc_results = await asyncio.gather(
        _run_binary(gau_cmd),
        asyncio.to_thread(discovery.run_discovery, alive_hosts),
        return_exceptions=True
    )
    
    end_set = set()
    for res in disc_results:
        if isinstance(res, str):
            for line in res.splitlines():
                if line.strip():
                    end_set.add(line.strip())
        elif isinstance(res, list):
            for item in res:
                if isinstance(item, str):
                    end_set.add(item)
                    
    endpoints = list(end_set)[: limits["endpoints"]]"""

content = content.replace(old_exec, new_exec)

# Now find where nuclei_scanner is called and add _update_prog
old_nuclei = """    nuclei_scan_urls = _limit_urls([*ranked_urls, *all_endpoints], limits["nuclei"])
    nuclei_findings = await nuclei_scanner.scan_with_nuclei(nuclei_scan_urls, session)"""

new_nuclei = """    _update_prog("scanning with nuclei")
    nuclei_scan_urls = _limit_urls([*ranked_urls, *all_endpoints], limits["nuclei"])
    nuclei_findings = await nuclei_scanner.scan_with_nuclei(nuclei_scan_urls, session)"""

content = content.replace(old_nuclei, new_nuclei)

with open('modules/pipeline/integrations/recon_zentry_adapter.py', 'w') as f:
    f.write(content)
