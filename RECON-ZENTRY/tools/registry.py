import shutil
from core.logger import Logger

logger = Logger("tool_registry")

class ToolRegistry:
    TOOLS = {
        "nmap": {"name": "Nmap", "description": "Network scanner", "command": "nmap", "category": "recon"},
        "nikto": {"name": "Nikto", "description": "Web vuln scanner", "command": "nikto", "category": "vuln"},
        "gobuster": {"name": "Gobuster", "description": "Dir brute-forcer", "command": "gobuster", "category": "recon"},
        "sqlmap": {"name": "SQLMap", "description": "SQL injection tool", "command": "sqlmap", "category": "exploit"},
        "hydra": {"name": "Hydra", "description": "Password brute-forcer", "command": "hydra", "category": "exploit"},
        "whois": {"name": "Whois", "description": "Domain lookup", "command": "whois", "category": "recon"},
        "dig": {"name": "Dig", "description": "DNS lookup", "command": "dig", "category": "recon"},
        "curl": {"name": "cURL", "description": "HTTP client", "command": "curl", "category": "recon"},
        "whatweb": {"name": "WhatWeb", "description": "Web fingerprinting", "command": "whatweb", "category": "recon"},
    }

    def __init__(self):
        self._cache = {}

    def check_tool(self, name):
        if name not in self.TOOLS:
            return {"installed": False, "path": None}
        path = shutil.which(self.TOOLS[name]["command"])
        result = {"installed": path is not None, "path": path or "Not found", "name": self.TOOLS[name]["name"], "description": self.TOOLS[name]["description"], "category": self.TOOLS[name]["category"]}
        self._cache[name] = result
        return result

    def check_all_tools(self):
        return {name: self.check_tool(name) for name in self.TOOLS}

    def is_available(self, name):
        if name in self._cache: return self._cache[name]["installed"]
        return self.check_tool(name)["installed"]

    def get_available_tools(self, category=None):
        return [n for n, t in self.TOOLS.items() if (not category or t["category"] == category) and self.is_available(n)]
