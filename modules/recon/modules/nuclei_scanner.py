"""Upgraded Nuclei: tag-targeted, full coverage with fallbacks"""
import asyncio
import tempfile
import json
from pathlib import Path
from core.runner import run_cmd
from core.logger import logger, dashboard
from modules.recon.config.settings import NUCLEI_RATE, NUCLEI_BATCH_SIZE
from modules.pipeline.utils.binaries import resolve_binary


async def run_nuclei_batch(urls, tags=None, severity="low,medium,high,critical", batch_id=1):
    nuclei_bin = resolve_binary("nuclei")
    if not nuclei_bin:
        logger.warning("⚠️  nuclei not found in ./bin or PATH")
        return []
    
    if not urls:
        return []
    
    inp = Path(tempfile.gettempdir()) / f"nuclei_in_{batch_id}.txt"
    out = Path(tempfile.gettempdir()) / f"nuclei_out_{batch_id}.json"
    inp.write_text("\n".join(urls))
    
    tag_arg = f"-tags {tags}" if tags else ""
    cmd = (f"{nuclei_bin} -l {inp} {tag_arg} -severity {severity} "
           f"-rate-limit {NUCLEI_RATE} -c 50 -bulk-size 30 "
           f"-jsonl -o {out} -silent -timeout 10 -retries 1 2>/dev/null")
    
    try:
        await run_cmd(cmd, timeout=1800)
        findings = []
        if out.exists():
            try:
                for line in out.read_text().splitlines():
                    if line.strip():
                        try:
                            findings.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
            except Exception as e:
                logger.debug(f"Error reading nuclei output: {e}")
            out.unlink(missing_ok=True)
        inp.unlink(missing_ok=True)
        return findings
    except Exception as e:
        logger.debug(f"Nuclei batch error: {e}")
        inp.unlink(missing_ok=True)
        out.unlink(missing_ok=True)
        return []


async def scan_with_nuclei(all_urls, session):
    logger.info("☢️  NUCLEI SCAN (FULL COVERAGE)")
    if not all_urls:
        session.update("nuclei_findings", [])
        return []
    
    if not resolve_binary("nuclei"):
        logger.warning("⚠️  nuclei tool not found in ./bin or PATH - skipping nuclei scan")
        session.update("nuclei_findings", [])
        return []
    
    unique = list(set(all_urls))
    logger.info(f"   Total URLs: {len(unique)}")

    all_findings = []
    # Batch full set, no 50-URL cap
    batches = [unique[i:i+NUCLEI_BATCH_SIZE] for i in range(0, len(unique), NUCLEI_BATCH_SIZE)]
    
    for i, batch in enumerate(batches, 1):
        logger.info(f"   ├─ Batch {i}/{len(batches)} ({len(batch)} URLs) — tags: xss,sqli,ssrf,lfi,rce")
        f = await run_nuclei_batch(batch, tags="xss,sqli,ssrf,lfi,rce,oob,redirect,exposure", batch_id=i)
        if f:
            logger.info(f"   │  └─ {len(f)} findings")
            all_findings.extend(f)
        else:
            logger.info(f"   │  └─ 0 findings")
        try:
            dashboard.advance_recon(f"nuclei:batch{i}")
        except Exception:
            pass

    session.update("nuclei_findings", all_findings)
    
    if all_findings:
        logger.info(f"   ✓ Nuclei total: {len(all_findings)} findings")
        # Log summary by severity
        severity_count = {}
        for f in all_findings:
            sev = f.get("info", {}).get("severity", "unknown").lower()
            severity_count[sev] = severity_count.get(sev, 0) + 1
        for sev in sorted(severity_count.keys()):
            logger.info(f"      • {sev.upper()}: {severity_count[sev]}")
    else:
        logger.info(f"   ⚠️  Nuclei: no findings detected")
    
    return all_findings
