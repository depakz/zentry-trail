import asyncio
import shlex
from typing import Tuple, Optional

async def run_cmd(cmd: str, timeout: int = 300, input_data: Optional[str] = None) -> Tuple[int, str, str]:
    """Run shell command async. Returns (returncode, stdout, stderr)."""
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdin=asyncio.subprocess.PIPE if input_data else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=input_data.encode() if input_data else None),
            timeout=timeout,
        )
        return proc.returncode, stdout.decode(errors="ignore"), stderr.decode(errors="ignore")
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        try:
            # Ensure the process is reaped to avoid dangling transports
            await proc.wait()
        except Exception:
            pass
        return -1, "", f"Timeout after {timeout}s"

def which(tool: str) -> bool:
    import shutil
    return shutil.which(tool) is not None
