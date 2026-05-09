import asyncio
import re
from core.logger import setup_logger

logger = setup_logger("gobuster_wrapper")

class GobusterWrapper:
    DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"

    def __init__(self, timeout=300):
        self.timeout = timeout

    async def dir_scan(self, target, wordlist=None, extensions=None, threads=50):
        wl = wordlist or self.DEFAULT_WORDLIST
        parts = ["gobuster", "dir", "-u", target, "-w", wl, "-t", str(threads), "--no-progress", "-q"]
        if extensions: parts.extend(["-x", extensions])
        cmd = " ".join(parts)
        return await self._run(cmd, "dir_scan")

    async def dns_scan(self, domain, wordlist=None, threads=50):
        wl = wordlist or self.DEFAULT_WORDLIST
        cmd = f"gobuster dns -d {domain} -w {wl} -t {threads} --no-progress -q"
        return await self._run(cmd, "dns_scan")

    async def _run(self, cmd, scan_type):
        try:
            proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            output = stdout.decode("utf-8", errors="replace")
            results = []
            for line in output.strip().split("\n"):
                line = line.strip()
                if not line: continue
                m = re.match(r"(/\S*)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]", line)
                if m:
                    results.append({"path": m.group(1), "status": int(m.group(2)), "size": int(m.group(3))})
            return {"success": True, "scan_type": scan_type, "raw_output": output, "results": results, "total_found": len(results), "command": cmd}
        except asyncio.TimeoutError:
            return {"success": False, "error": "Timed out", "command": cmd}
        except Exception as e:
            return {"success": False, "error": str(e), "command": cmd}
