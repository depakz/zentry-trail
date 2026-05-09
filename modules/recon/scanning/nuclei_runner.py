import json, tempfile
from pathlib import Path
from modules.recon.utils.runner import run_cmd

SEVERITY = "critical,high,medium,low"

async def scan(targets: list[str]) -> list[dict]:
    if not targets:
        return []
    out_file = Path(tempfile.mktemp(suffix=".jsonl"))
    inp = "\n".join(targets)
    cmd = f"nuclei -silent -severity {SEVERITY} -jsonl -o {out_file} -rl 50 -c 25"
    await run_cmd(cmd, timeout=1800, input_data=inp)
    findings = []
    if out_file.exists():
        for line in out_file.read_text().splitlines():
            try:
                findings.append(json.loads(line))
            except Exception:
                continue
        out_file.unlink()
    return findings
