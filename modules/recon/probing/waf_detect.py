from modules.recon.utils.runner import run_cmd

async def detect(url: str) -> str:
    code, out, _ = await run_cmd(f"wafw00f {url} -a", timeout=60)
    for line in out.splitlines():
        if "is behind" in line.lower():
            return line.strip()
    return "none"
