import asyncio
import shutil
import subprocess
from typing import List

class SubfinderRunner:
    def __init__(self, binary_path: str = "bin/subfinder"):
        self.binary = shutil.which(binary_path) or binary_path

    async def run(self, domain: str) -> List[str]:
        # Run subfinder and collect domain results (one per line)
        proc = await asyncio.create_subprocess_exec(self.binary, "-d", domain, "-silent",
                                                    stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await proc.communicate()
        out = stdout.decode().splitlines() if stdout else []
        return [line.strip() for line in out if line.strip()]
