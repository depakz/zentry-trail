import json, tempfile
from pathlib import Path
from modules.recon.utils.runner import run_cmd
from modules.pipeline.utils.binaries import resolve_binary

async def scan(targets: list[str], tags: list[str] = None) -> list[dict]:
    if not targets:
        return []
    
    if tags is None:
        tags = []
    # Always include base tags for critical/high severity generic templates
    base_tags = {"generic", "misconfig", "exposure"}
    tags = list(set(tags).union(base_tags))

    nuclei_bin = resolve_binary("nuclei")
    if not nuclei_bin:
        return []
    
    out_file = Path(tempfile.mktemp(suffix=".jsonl"))
    inp = "\n".join(targets)
    
    tags_flag = f"-tags {','.join(tags)}" if tags else ""
    # Smart filtering & Performance tuning
    cmd = f"{nuclei_bin} -silent {tags_flag} -severity critical,high,medium -jsonl -o {out_file} -rl 150 -c 50 -bs 25"
    
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
