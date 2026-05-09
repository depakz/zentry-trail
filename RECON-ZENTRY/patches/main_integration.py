"""
INTEGRATION SNIPPET for main.py
Insert after the crawl (katana) stage and before filter/nuclei stages.
"""

# === ADD AT TOP OF main.py ===
from modules.deep_pipeline import run_deep_pipeline
from modules.nuclei_runner import run_nuclei
import json
import os
import logging

# === INSERT AFTER KATANA CRAWL ===
# Assumes you already have:
#   all_endpoints : List[str]   (katana output)
#   tier1_hosts   : List[str]   (prioritized hosts)
#   output_dir    : str

logging.info("[PIPELINE] >>> DEEP PIPELINE STAGE <<<")
deep = run_deep_pipeline(
    katana_urls=all_endpoints,
    tier1_hosts=tier1_hosts,
    enable_post_test=True,
)

all_endpoints = deep["merged_urls"]

# Persist deep results
os.makedirs(output_dir, exist_ok=True)
with open(os.path.join(output_dir, "deep_apis.json"), "w") as f:
    json.dump(deep["apis"], f, indent=2)
with open(os.path.join(output_dir, "deep_params.json"), "w") as f:
    json.dump(deep["params"], f, indent=2)
with open(os.path.join(output_dir, "deep_post_findings.json"), "w") as f:
    json.dump(deep["post_findings"], f, indent=2)
with open(os.path.join(output_dir, "deep_js_endpoints.txt"), "w") as f:
    f.write("\n".join(deep["js_endpoints"]))
with open(os.path.join(output_dir, "merged_urls.txt"), "w") as f:
    f.write("\n".join(deep["merged_urls"]))

logging.info(f"[PIPELINE] Deep stage complete. {len(all_endpoints)} URLs ready for filter/nuclei.")

# === REPLACE / WRAP YOUR EXISTING NUCLEI CALL WITH ===
nuclei_findings = run_nuclei(
    urls=filtered_endpoints,
    severity="critical,high",
    rate_limit=150,
    concurrency=50,
    timeout=5,
    retries=1,
    only_high_value=True,
)

with open(os.path.join(output_dir, "nuclei_findings.json"), "w") as f:
    json.dump(nuclei_findings, f, indent=2)

logging.info(f"[PIPELINE] Nuclei finished: {len(nuclei_findings)} findings")
