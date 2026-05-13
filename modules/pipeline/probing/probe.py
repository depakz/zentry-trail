"""
Production-grade HTTP probing engine.
Auto-detects the correct httpx binary (Go, not Python lib).
"""
import asyncio
import os
import shutil
import socket
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable

from modules.recon.probing.parser import sanitize_domains, parse_httpx_output
from modules.recon.probing.retry import TIER_FAST, TIER_SAFE, TIER_DEEP, ProbeTier
from modules.recon.probing.waf import detect_with_wafw00f
from modules.recon.utils.logger import get_logger

log = get_logger("probe")


# ---------- HTTPX BINARY RESOLVER ----------
def find_httpx_binary() -> str:
    """
    Find the REAL ProjectDiscovery httpx, not the Python lib.
    Priority: $HTTPX_BIN env > common Go paths > PATH > refuse.
    """
    # 1. Env override
    env_bin = os.environ.get("HTTPX_BIN")
    if env_bin and Path(env_bin).is_file():
        if _is_go_httpx(env_bin):
            return env_bin

    # 2. Known Go paths
    candidates = [
        Path.home() / "bin" / "httpx",
        Path.home() / "go" / "bin" / "httpx",
        Path("/usr/local/bin/httpx"),
        Path("/usr/bin/httpx"),
        Path("/root/go/bin/httpx"),
        Path("/snap/bin/httpx"),
    ]
    for c in candidates:
        try:
            if c.is_file() and _is_go_httpx(str(c)):
                return str(c)
        except PermissionError:
            continue

    # 3. PATH lookup (but verify it's Go version)
    path_bin = shutil.which("httpx")
    if path_bin and _is_go_httpx(path_bin):
        return path_bin

    raise RuntimeError(
        "❌ ProjectDiscovery httpx not found!\n"
        "   Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest\n"
        "   Or set HTTPX_BIN=/path/to/httpx"
    )


def _is_go_httpx(path: str) -> bool:
    """Verify binary is Go httpx (not Python lib)."""
    try:
        r = subprocess.run([path, "-version"], capture_output=True, timeout=5, text=True)
        combined = (r.stdout + r.stderr).lower()
        return "projectdiscovery" in combined or "current version" in combined
    except Exception:
        return False


# ---------- DNS PRE-FILTER ----------
async def _resolve(domain: str) -> str | None:
    loop = asyncio.get_event_loop()
    try:
        host = domain.split(":")[0]
        info = await asyncio.wait_for(
            loop.getaddrinfo(host, None, family=socket.AF_INET), timeout=5,
        )
        return info[0][4][0]
    except Exception:
        return None


async def dns_filter(domains: list[str], concurrency: int = 100) -> dict[str, str]:
    sem = asyncio.Semaphore(concurrency)
    resolved: dict[str, str] = {}

    async def _check(d: str):
        async with sem:
            ip = await _resolve(d)
            if ip:
                resolved[d] = ip

    await asyncio.gather(*(_check(d) for d in domains))
    return resolved


# ---------- HTTPX RUNNER ----------
async def _run_httpx(domains: list[str], tier: ProbeTier, httpx_bin: str) -> tuple[str, str]:
    in_file = Path(tempfile.mktemp(suffix=".txt"))
    in_file.write_text("\n".join(domains))

    cmd = [
        httpx_bin,
        "-l", str(in_file),
        "-json",
        "-silent",
        "-status-code",
        "-title",
        "-tech-detect",
        "-ip",
        "-follow-redirects",
        "-timeout", str(tier.timeout),
        "-retries", str(tier.retries),
        "-rate-limit", str(tier.rate_limit),
        "-threads", str(tier.threads),
        "-no-color",
    ]
    if tier.extra_flags:
        import shlex
        cmd.extend(shlex.split(tier.extra_flags))

    log.info(f"   [dim]$ {' '.join(cmd[:6])}...[/dim]")

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
    except asyncio.TimeoutError:
        proc.kill()
        log.error("   httpx global timeout (600s)")
        return "", "timeout"
    finally:
        in_file.unlink(missing_ok=True)

    out = stdout.decode(errors="ignore")
    err = stderr.decode(errors="ignore")
    return out, err


# ---------- MAIN PROBE ----------
async def probe(
    domains: Iterable[str],
    enable_waf_detect: bool = True,
    verbose: bool = True,
) -> list[dict]:
    # Resolve binary once
    try:
        httpx_bin = find_httpx_binary()
        log.info(f"🔧 Using httpx: {httpx_bin}")
    except RuntimeError as e:
        log.error(str(e))
        return []

    domains_list = list(domains)
    cleaned = sanitize_domains(domains_list)
    log.info(f"📥 Input: {len(domains_list)} → sanitized: {len(cleaned)}")
    if not cleaned:
        return []

    log.info(f"🌐 DNS resolving {len(cleaned)} domains...")
    resolved = await dns_filter(cleaned)
    log.info(f"🌐 Resolved: {len(resolved)}/{len(cleaned)}")
    if not resolved:
        return []

    candidates = list(resolved.keys())
    results: list[dict] = []

    for tier in (TIER_FAST, TIER_SAFE, TIER_DEEP):
        log.info(f"🚀 Probing with {tier.name}")
        stdout, stderr = await _run_httpx(candidates, tier, httpx_bin)

        raw_lines = [l for l in stdout.splitlines() if l.strip()]
        results = parse_httpx_output(stdout)

        log.info(f"   raw stdout lines: {len(raw_lines)} | parsed alive: {len(results)}")

        # Always show stderr on failure so user knows WHY
        if not results and stderr.strip():
            log.warning(f"   httpx stderr:\n{stderr.strip()[:500]}")
        if not results and stdout.strip() and len(raw_lines) > 0:
            log.warning(f"   stdout sample: {stdout[:300]}")

        if results:
            log.info(f"✅ {tier.name}: {len(results)} alive hosts")
            break
        log.warning(f"⚠️ {tier.name} got nothing — escalating")

    if not results:
        log.error("❌ All tiers exhausted — 0 alive hosts")
        return []

    if enable_waf_detect:
        log.info("🛡️ WAF detection (top 5)...")
        for r in results[:5]:
            waf = await detect_with_wafw00f(r["url"], timeout=45)
            r["waf"] = waf
            log.info(f"   {r['url']} → {waf}")

    return results


def probe_domains(input_source) -> list[dict]:
    if isinstance(input_source, str) and Path(input_source).is_file():
        domains = Path(input_source).read_text().splitlines()
    elif isinstance(input_source, (list, tuple, set)):
        domains = list(input_source)
    else:
        raise ValueError("input_source must be a file path or list")
    return asyncio.run(probe(domains))
