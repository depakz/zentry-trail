from modules.recon.utils.runner import run_cmd
from core.logger import dashboard

async def run(target: str, timeout: int = 90) -> list[str]:
    cmd = f"subfinder -d {target} -silent -timeout 30"
    code, out, _ = await run_cmd(cmd, timeout=timeout)
    results = [s.strip() for s in out.splitlines() if s.strip()]
    try:
        dashboard.advance_recon("subfinder finished")
    except Exception:
        pass
    return results
