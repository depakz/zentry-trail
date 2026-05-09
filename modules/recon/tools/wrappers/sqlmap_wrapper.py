import asyncio
from core.logger import setup_logger

logger = setup_logger("sqlmap_wrapper")

class SqlmapWrapper:
    def __init__(self, timeout=600):
        self.timeout = timeout

    async def test_url(self, url, level=1, risk=1):
        cmd = f"sqlmap -u '{url}' --batch --level={level} --risk={risk} --no-color"
        return await self._run(cmd, "url_test")

    async def test_form(self, url, data, level=2, risk=2):
        cmd = f"sqlmap -u '{url}' --data='{data}' --batch --level={level} --risk={risk} --no-color"
        return await self._run(cmd, "form_test")

    async def enumerate_dbs(self, url):
        cmd = f"sqlmap -u '{url}' --batch --dbs --no-color"
        return await self._run(cmd, "db_enum")

    async def _run(self, cmd, scan_type):
        try:
            proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            output = stdout.decode("utf-8", errors="replace")
            vuln = any(x in output for x in ["is vulnerable", "sqlmap identified the following injection"])
            types = [l.strip().replace("Type: ", "") for l in output.split("\n") if l.strip().startswith("Type:")]
            return {"success": True, "scan_type": scan_type, "vulnerable": vuln, "raw_output": output, "injection_types": types, "command": cmd}
        except asyncio.TimeoutError:
            return {"success": False, "error": "Timed out", "command": cmd}
        except Exception as e:
            return {"success": False, "error": str(e), "command": cmd}
