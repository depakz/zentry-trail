import json
from pathlib import Path
from dataclasses import asdict

def write(session, out_dir="reports") -> str:
    Path(out_dir).mkdir(exist_ok=True)
    p = Path(out_dir) / f"{session.target.replace('.','_')}.json"
    p.write_text(json.dumps(asdict(session), indent=2, default=str))
    return str(p)
