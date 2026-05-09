import asyncio
import re
from core.logger import setup_logger

logger = setup_logger("whois_wrapper")

class WhoisWrapper:
    def __init__(self, timeout=30):
        self.timeout = timeout

    async def lookup(self, domain):
        cmd = f"whois {domain}"
        try:
            proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            output = stdout.decode("utf-8", errors="replace")
            parsed = {}
            for key, pattern in {"registrar": r"Registrar:\s*(.+)", "creation_date": r"Creation Date:\s*(.+)", "expiry_date": r"(?:Registry Expiry|Expir(?:y|ation)) Date:\s*(.+)", "name_servers": r"Name Server:\s*(.+)"}.items():
                m = re.findall(pattern, output, re.IGNORECASE)
                if m: parsed[key] = m if len(m)>1 else m[0].strip()
            return {"success": True, "domain": domain, "parsed": parsed, "raw_output": output, "command": cmd}
        except asyncio.TimeoutError:
            return {"success": False, "error": "Timed out", "command": cmd}
        except Exception as e:
            return {"success": False, "error": str(e), "command": cmd}

    async def dns_lookup(self, domain, record_type="ANY"):
        cmd = f"dig {domain} {record_type} +noall +answer"
        try:
            proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            output = stdout.decode("utf-8", errors="replace")
            records = []
            for line in output.strip().split("\n"):
                line = line.strip()
                if line and not line.startswith(";"):
                    parts = line.split()
                    if len(parts) >= 5:
                        records.append({"name": parts[0], "ttl": parts[1], "class": parts[2], "type": parts[3], "value": " ".join(parts[4:])})
            return {"success": True, "domain": domain, "records": records, "raw_output": output, "command": cmd}
        except asyncio.TimeoutError:
            return {"success": False, "error": "Timed out", "command": cmd}
        except Exception as e:
            return {"success": False, "error": str(e), "command": cmd}
