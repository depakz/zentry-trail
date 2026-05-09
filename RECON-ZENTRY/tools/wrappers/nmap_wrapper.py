import asyncio
import re
from core.logger import Logger

logger = Logger("nmap_wrapper")

class NmapWrapper:
    def __init__(self, timeout=300):
        self.timeout = timeout

    async def quick_scan(self, target):
        return await self._run(f"-T4 -F {target}", "quick_scan")

    async def full_scan(self, target):
        return await self._run(f"-sV -sC -O -T4 -p- {target}", "full_scan")

    async def service_scan(self, target, ports=None):
        pa = f"-p {ports}" if ports else "-p-"
        return await self._run(f"-sV -sC {pa} {target}", "service_scan")

    async def vuln_scan(self, target, ports=None):
        pa = f"-p {ports}" if ports else ""
        return await self._run(f"--script=vuln {pa} {target}", "vuln_scan")

    async def os_detection(self, target):
        return await self._run(f"-O -T4 {target}", "os_detection")

    async def _run(self, args, scan_type):
        cmd = f"nmap {args}"
        try:
            proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            output = stdout.decode("utf-8", errors="replace")
            if proc.returncode != 0 and not output:
                return {"scan_type": scan_type, "success": False, "error": stderr.decode(), "raw_output": "", "command": cmd}
            parsed = self._parse(output)
            parsed.update({"scan_type": scan_type, "success": True, "raw_output": output, "command": cmd})
            return parsed
        except asyncio.TimeoutError:
            return {"scan_type": scan_type, "success": False, "error": "Timed out", "raw_output": "", "command": cmd}
        except Exception as e:
            return {"scan_type": scan_type, "success": False, "error": str(e), "raw_output": "", "command": cmd}

    def _parse(self, output):
        result = {"ports": [], "os_info": [], "scripts": [], "host_status": "unknown"}
        if "Host is up" in output: result["host_status"] = "up"
        elif "Host seems down" in output: result["host_status"] = "down"
        for m in re.finditer(r"(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)\s*(.*)", output):
            result["ports"].append({"port": int(m.group(1)), "protocol": m.group(2), "state": m.group(3), "service": m.group(4), "version": m.group(5).strip()})
        for m in re.finditer(r"OS details?:\s*(.+)", output):
            result["os_info"].append(m.group(1).strip())
        return result
