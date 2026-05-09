"""Async runner with retries + rate limit"""
import asyncio
import shutil
import subprocess
from core.logger import logger
from config.settings import TOOL_TIMEOUT, RETRY_COUNT

def have(tool):
    return shutil.which(tool) is not None

async def run_cmd(cmd, timeout=TOOL_TIMEOUT, retries=RETRY_COUNT):
    """Async command exec with retry"""
    for attempt in range(retries + 1):
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return stdout.decode(errors="ignore"), stderr.decode(errors="ignore"), proc.returncode
        except asyncio.TimeoutError:
            logger.warning(f"⏱️  TIMEOUT (attempt {attempt+1}): {cmd[:80]}")
            try: proc.kill()
            except: pass
            if attempt == retries:
                return "", "timeout", -1
        except Exception as e:
            logger.error(f"Run error: {e}")
            return "", str(e), -1

async def run_parallel(tasks, max_concurrent=20):
    """Run async tasks with concurrency cap"""
    sem = asyncio.Semaphore(max_concurrent)
    async def _wrap(t):
        async with sem:
            return await t
    return await asyncio.gather(*[_wrap(t) for t in tasks], return_exceptions=True)
