import json, tempfile
from pathlib import Path
from utils.runner import run_cmd

HIGH_VALUE = {"id","search","url","redirect","file","path","cmd","exec","query","page","include"}

async def find_params(url: str) -> list[str]:
    out_file = Path(tempfile.mktemp(suffix=".json"))
    cmd = f"arjun -u {url} -oJ {out_file} -t 10 --stable"
    await run_cmd(cmd, timeout=300)
    if not out_file.exists():
        return []
    try:
        data = json.loads(out_file.read_text())
        params = []
        for entry in (data if isinstance(data, list) else [data]):
            params.extend(entry.get("params", []))
        return params
    except Exception:
        return []
    finally:
        out_file.unlink(missing_ok=True)

def prioritize(params: list[str]) -> list[str]:
    return sorted(params, key=lambda p: p.lower() not in HIGH_VALUE)
