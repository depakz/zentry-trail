from utils.runner import run_cmd

async def crawl(url: str, depth: int = 3) -> list[str]:
    cmd = f"katana -u {url} -d {depth} -silent -jc -kf all -aff"
    code, out, _ = await run_cmd(cmd, timeout=600)
    return list({l.strip() for l in out.splitlines() if l.strip()})
