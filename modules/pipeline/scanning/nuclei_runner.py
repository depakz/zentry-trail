import json, tempfile
from pathlib import Path
from modules.recon.utils.runner import run_cmd

async def scan(targets: list[str], tags: list[str] = None) -> list[dict]:
    if not targets:
        return []
    out_file = Path(tempfile.mktemp(suffix=".jsonl"))
    inp = "\n".join(targets)
    
    tags_flag = f"-tags {','.join(tags)}" if tags else ""
    # Smart filtering & Performance tuning
    cmd = f"nuclei -silent {tags_flag} -severity critical,high -jsonl -o {out_file} -rl 150 -c 50 -bs 25"
    
    await run_cmd(cmd, timeout=900, input_data=inp)
    findings = []
    if out_file.exists():
        for line in out_file.read_text().splitlines():
            try:
                findings.append(json.loads(line))
            except Exception:
                continue
        out_file.unlink()
    return findings
