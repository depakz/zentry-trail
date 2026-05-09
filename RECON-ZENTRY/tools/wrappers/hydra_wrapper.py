import asyncio
from core.logger import Logger

logger = Logger("hydra_wrapper")

class HydraWrapper:
    def __init__(self, timeout=600):
        self.timeout = timeout

    async def brute_force(self, target, service, username=None, username_list=None, password_list="/usr/share/wordlists/rockyou.txt", port=None, threads=16):
        parts = ["hydra"]
        if username: parts.extend(["-l", username])
        elif username_list: parts.extend(["-L", username_list])
        else: parts.extend(["-l", "admin"])
        parts.extend(["-P", password_list, "-t", str(threads), "-f"])
        if port: parts.extend(["-s", str(port)])
        parts.extend([target, service])
        cmd = " ".join(parts)
        try:
            proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            output = stdout.decode("utf-8", errors="replace")
            creds = []
            for line in output.split("\n"):
                if "host:" in line.lower() and ("login:" in line.lower() or "password:" in line.lower()):
                    p = line.strip().split()
                    c = {}
                    for i, part in enumerate(p):
                        if part.lower() == "login:" and i+1 < len(p): c["username"] = p[i+1]
                        elif part.lower() == "password:" and i+1 < len(p): c["password"] = p[i+1]
                    if c: creds.append(c)
            return {"success": True, "target": target, "service": service, "credentials_found": len(creds)>0, "credentials": creds, "raw_output": output, "command": cmd}
        except asyncio.TimeoutError:
            return {"success": False, "error": "Timed out", "command": cmd}
        except Exception as e:
            return {"success": False, "error": str(e), "command": cmd}
