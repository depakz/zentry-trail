"""
Optimized Nuclei Runner
"""
import subprocess
import logging
import json
import shutil
import tempfile
import os
from typing import List, Dict
from core.logger import dashboard

logger = logging.getLogger(__name__)


def _filter_high_value(urls: List[str]) -> List[str]:
    """Filter for URLs worth scanning."""
    keep = []
    seen = set()
    keywords = ("api", "graphql", "auth", "login", "admin", "v1", "v2",
                "rest", "user", "account", "oauth", "token", "upload",
                "internal", "config", "debug")
    for u in urls:
        if u in seen:
            continue
        seen.add(u)
        ul = u.lower()
        if "?" in u or any(k in ul for k in keywords):
            keep.append(u)
    return keep


def run_nuclei(
    urls: List[str],
    severity: str = "critical,high",
    rate_limit: int = 150,
    concurrency: int = 50,
    timeout: int = 5,
    retries: int = 1,
    batch_size: int = 1000,
    only_high_value: bool = True,
) -> List[Dict]:
    """Run nuclei against URL list, return parsed findings."""
    if not shutil.which("nuclei"):
        logger.error("[NUCLEI] nuclei binary not found")
        return []

    if not urls:
        logger.warning("[NUCLEI] No URLs provided")
        return []

    if only_high_value:
        targets = _filter_high_value(urls)
        logger.info(f"[NUCLEI] Filtered {len(urls)} -> {len(targets)} high-value URLs")
    else:
        targets = list(dict.fromkeys(urls))

    if not targets:
        return []

    findings: List[Dict] = []

    for i in range(0, len(targets), batch_size):
        batch = targets[i : i + batch_size]
        logger.info(f"[NUCLEI] Batch {i // batch_size + 1} ({len(batch)} URLs)")

        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as tin:
            tin.write("\n".join(batch))
            in_path = tin.name

        out_path = tempfile.NamedTemporaryFile("w", delete=False, suffix=".jsonl").name

        cmd = [
            "nuclei",
            "-l", in_path,
            "-severity", severity,
            "-rate-limit", str(rate_limit),
            "-c", str(concurrency),
            "-timeout", str(timeout),
            "-retries", str(retries),
            "-silent",
            "-jsonl",
            "-o", out_path,
        ]

        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=3600, check=False)
        except subprocess.TimeoutExpired:
            logger.warning("[NUCLEI] batch timed out")
        except Exception as e:
            logger.error(f"[NUCLEI] error: {e}")

        try:
            if os.path.exists(out_path):
                with open(out_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                            findings.append({
                                "template": obj.get("template-id") or obj.get("templateID"),
                                "name": (obj.get("info") or {}).get("name"),
                                "severity": (obj.get("info") or {}).get("severity"),
                                "url": obj.get("matched-at") or obj.get("host"),
                                "type": obj.get("type"),
                                "tags": (obj.get("info") or {}).get("tags"),
                            })
                        except Exception:
                            continue
        finally:
            for p in (in_path, out_path):
                try:
                    os.unlink(p)
                except Exception:
                    pass
        try:
            batch_no = (i // batch_size) + 1
            dashboard.advance_recon(f"nuclei:batch{batch_no}")
        except Exception:
            pass

    logger.info(f"[NUCLEI] Total findings: {len(findings)}")
    return findings


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(run_nuclei(["https://example.com/api/v1/users"]))
