"""Upgraded Nuclei: tag-targeted, full coverage"""
import asyncio, tempfile, json
from pathlib import Path
from core.runner import run_cmd, have
from core.logger import logger
from config.settings import NUCLEI_RATE, NUCLEI_BATCH_SIZE

async def run_nuclei_batch(urls, tags=None, severity="low,medium,high,critical", batch_id=1):
    if not have("nuclei") or not urls: return []
    inp = Path(tempfile.gettempdir()) / f"nuclei_in_{batch_id}.txt"
    out = Path(tempfile.gettempdir()) / f"nuclei_out_{batch_id}.json"
    inp.write_text("\n".join(urls))
    tag_arg = f"-tags {tags}" if tags else ""
    cmd = (f"nuclei -l {inp} {tag_arg} -severity {severity} "
           f"-rate-limit {NUCLEI_RATE} -c 50 -bulk-size 30 "
           f"-jsonl -o {out} -silent -timeout 10 -retries 1 2>/dev/null")
    await run_cmd(cmd, timeout=1800)
    findings = []
    if out.exists():
        for line in out.read_text().splitlines():
            try: findings.append(json.loads(line))
            except: pass
        out.unlink(missing_ok=True)
    inp.unlink(missing_ok=True)
    return findings

async def scan_with_nuclei(all_urls, session):
    logger.info("☢️  NUCLEI SCAN (FULL COVERAGE)")
    if not all_urls:
        session.update("nuclei_findings", [])
        return []
    unique = list(set(all_urls))
    logger.info(f"   Total URLs: {len(unique)}")

    all_findings = []
    # Batch full set, no 50-URL cap
    batches = [unique[i:i+NUCLEI_BATCH_SIZE] for i in range(0, len(unique), NUCLEI_BATCH_SIZE)]
    for i, batch in enumerate(batches, 1):
        logger.info(f"   ├─ Batch {i}/{len(batches)} ({len(batch)} URLs) — tags: xss,sqli,ssrf,lfi,rce,oob")
        f = await run_nuclei_batch(batch, tags="xss,sqli,ssrf,lfi,rce,oob,redirect,exposure", batch_id=i)
        logger.info(f"   │  └─ {len(f)} findings")
        all_findings.extend(f)

    session.update("nuclei_findings", all_findings)
    logger.info(f"   ✓ Nuclei total: {len(all_findings)} findings")
    return all_findings
