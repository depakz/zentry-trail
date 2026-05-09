import asyncio
from core.logger import setup_logger

logger = setup_logger("nikto_wrapper")

class NiktoWrapper:
    def __init__(self, timeout=600):
        self.timeout = timeout

    async def scan(self, target, port=None, ssl=False):
        parts = ["nikto", "-h", target, "-Format", "txt", "-nointeractive"]
        if port: parts.extend(["-p", str(port)])
        if ssl: parts.append("-ssl")
        cmd = " ".join(parts)
        try:
            proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            output = stdout.decode("utf-8", errors="replace")
            findings = []
            for line in output.split("\n"):
                line = line.strip()
                if line.startswith("+") and ":" in line and "Target" not in line:
                    f = line.lstrip("+ ").strip()
                    if f and len(f) > 10:
                        findings.append({"description": f, "severity": "medium"})
            return {"success": True, "target": target, "raw_output": output, "findings": findings, "finding_count": len(findings), "command": cmd}
        except asyncio.TimeoutError:
            return {"success": False, "error": "Timed out", "command": cmd}
        except Exception as e:
            return {"success": False, "error": str(e), "command": cmd}
