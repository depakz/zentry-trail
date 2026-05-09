"""
Standalone test of deep pipeline
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logging
import json
from modules.recon.modules.deep_pipeline import run_deep_pipeline
from modules.recon.modules.nuclei_runner import run_nuclei

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

if __name__ == "__main__":
    katana_urls = [
        "https://example.com/",
        "https://example.com/login",
        "https://example.com/main.js",
    ]
    tier1_hosts = ["example.com"]

    deep = run_deep_pipeline(
        katana_urls=katana_urls,
        tier1_hosts=tier1_hosts,
        enable_post_test=True,
    )

    print(json.dumps({
        "urls": len(deep["merged_urls"]),
        "apis": len(deep["apis"]),
        "params": len(deep["params"]),
        "post_findings": len(deep["post_findings"]),
    }, indent=2))

    findings = run_nuclei(deep["merged_urls"])
    print(f"Nuclei findings: {len(findings)}")
