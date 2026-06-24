from .tool_wrappers import katana, gau

async def crawl(target: str, fast: bool = False) -> list[str]:
    """
    Run katana and gau to find URLs.
    """
    endpoints = set()

    katana_urls = await katana(target, depth=2 if fast else 4)
    if katana_urls:
        endpoints.update(katana_urls)

    if not fast:
        gau_urls = await gau(target)
        if gau_urls:
            endpoints.update(gau_urls)

    return sorted(list(endpoints))
