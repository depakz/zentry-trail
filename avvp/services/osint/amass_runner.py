import asyncio
import shutil
from typing import List

class AmassRunner:
    def __init__(self, binary_path: str = "amass"):
        self.binary = shutil.which(binary_path) or binary_path

    async def run(self, domain: str) -> List[str]:
        # Run amass in passive mode
        proc = await asyncio.create_subprocess_exec(self.binary, "enum", "-passive", "-d", domain,
                                                    "-silent",
                                                    stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await proc.communicate()
        out = stdout.decode().splitlines() if stdout else []
        return [line.strip() for line in out if line.strip()]
