from utils.runner import run_cmd

async def run(target: str, timeout: int = 90) -> list[str]:
    cmd = f"subfinder -d {target} -silent -timeout 30"
    code, out, _ = await run_cmd(cmd, timeout=timeout)
    return [s.strip() for s in out.splitlines() if s.strip()]
