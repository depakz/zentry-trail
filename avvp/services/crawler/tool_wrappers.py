import asyncio
import shutil
from typing import List

class GospiderRunner:
    def __init__(self, binary_path: str = "bin/gospider"):
        self.binary = shutil.which(binary_path) or binary_path

    async def run(self, url: str) -> List[str]:
        proc = await asyncio.create_subprocess_exec(self.binary, "-s", url, "-o", "-",
                                                    stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await proc.communicate()
        out = stdout.decode().splitlines() if stdout else []
        return [line.strip() for line in out if line.strip()]

class FfufRunner:
    def __init__(self, binary_path: str = "bin/ffuf"):
        self.binary = shutil.which(binary_path) or binary_path

    async def run(self, url: str, wordlist: str) -> List[str]:
        proc = await asyncio.create_subprocess_exec(self.binary, "-u", url, "-w", wordlist,
                                                    "-silent",
                                                    stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await proc.communicate()
        out = stdout.decode().splitlines() if stdout else []
        return [line.strip() for line in out if line.strip()]
