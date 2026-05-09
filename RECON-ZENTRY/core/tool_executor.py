import subprocess, shlex
from pathlib import Path

class ToolExecutor:
    def __init__(self, workspace="/workspace", timeout=600):
        self.workspace = Path(workspace)
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.registry = self._load_registry()

    def _load_registry(self):
        return {
            "nmap":       {"bin": "nmap", "risk": "low"},
            "subfinder":  {"bin": "subfinder", "risk": "low"},
            "httpx":      {"bin": "httpx", "risk": "low"},
            "naabu":      {"bin": "naabu", "risk": "low"},
            "nuclei":     {"bin": "nuclei", "risk": "med"},
            "ffuf":       {"bin": "ffuf", "risk": "med"},
            "gobuster":   {"bin": "gobuster", "risk": "med"},
            "dirsearch":  {"bin": "dirsearch", "risk": "med"},
            "arjun":      {"bin": "arjun", "risk": "med"},
            "sqlmap":     {"bin": "sqlmap", "risk": "high"},
            "wapiti":     {"bin": "wapiti", "risk": "med"},
            "semgrep":    {"bin": "semgrep", "risk": "low"},
            "bandit":     {"bin": "bandit", "risk": "low"},
            "gitleaks":   {"bin": "gitleaks", "risk": "low"},
            "trufflehog": {"bin": "trufflehog", "risk": "low"},
            "jwt_tool":   {"bin": "jwt_tool", "risk": "med"},
            "xsstrike":   {"bin": "xsstrike", "risk": "med"},
            "commix":     {"bin": "commix", "risk": "high"},
            "curl":       {"bin": "curl", "risk": "low"},
            "wget":       {"bin": "wget", "risk": "low"},
            "grep":       {"bin": "grep", "risk": "low"},
            "cat":        {"bin": "cat", "risk": "low"},
            "ls":         {"bin": "ls", "risk": "low"},
            "find":       {"bin": "find", "risk": "low"},
        }

    def schemas(self, allowed):
        schemas = []
        for name in allowed:
            if name in self.registry:
                schemas.append({
                    "type": "function",
                    "function": {
                        "name": name,
                        "description": f"Execute {name}. Pass args string and target.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "args": {"type": "string", "description": "CLI arguments"},
                                "target": {"type": "string", "description": "Target url/host/file"}
                            },
                            "required": ["args"]
                        }
                    }
                })
        return schemas

    def execute(self, tool, args, allowed):
        if tool not in allowed:
            return f"ERROR: tool '{tool}' not permitted for this agent"
        entry = self.registry.get(tool)
        if not entry:
            return f"ERROR: unknown tool {tool}"
        cli_args = args.get("args", "") if isinstance(args, dict) else ""
        target = args.get("target", "") if isinstance(args, dict) else ""
        cmd = f"{entry['bin']} {cli_args} {target}".strip()
        print(f"  [exec] {cmd}")
        try:
            proc = subprocess.run(
                shlex.split(cmd),
                capture_output=True, text=True,
                timeout=self.timeout, cwd=str(self.workspace)
            )
            out = (proc.stdout + "\n" + proc.stderr).strip()
            return out[-8000:] if out else "(no output)"
        except subprocess.TimeoutExpired:
            return f"TIMEOUT after {self.timeout}s"
        except FileNotFoundError:
            return f"ERROR: {entry['bin']} not installed"
        except Exception as e:
            return f"ERROR: {e}"
