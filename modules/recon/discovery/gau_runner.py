from modules.recon.utils.runner import run_cmd

async def run(target: str) -> list[str]:
    code, out, _ = await run_cmd(f"gau --threads 5 --subs {target}", timeout=600)
    return list({l.strip() for l in out.splitlines() if l.strip()})
