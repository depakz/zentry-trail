"""Amass passive — short timeout because it's notoriously slow."""
from utils.runner import run_cmd

async def run(target: str, passive: bool = True, timeout: int = 120) -> list[str]:
    mode = "-passive" if passive else ""
    # -timeout is in MINUTES for amass
    cmd = f"amass enum {mode} -d {target} -timeout 2 -silent"
    code, out, err = await run_cmd(cmd, timeout=timeout)
    return [s.strip() for s in out.splitlines() if s.strip() and target in s]
