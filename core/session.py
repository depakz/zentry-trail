import re
import os
import json
from datetime import datetime
from dataclasses import dataclass, field, asdict

@dataclass
class Finding:
    id: str
    title: str
    severity: str
    endpoint: str = ""
    payload: str = ""
    evidence: str = ""
    validated: bool = False
    reproduction: list = field(default_factory=list)
    impact: str = ""
    cve: list = field(default_factory=list)
    score: float = 0.0

class Session:
    def __init__(self, target, base_dir="data/sessions"):
        # Sanitize target: strip protocol and replace special chars
        safe_target = re.sub(r'^https?://', '', target)
        safe_target = safe_target.rstrip('/')
        safe_target = re.sub(r'[^\w\-.]', '_', safe_target)

        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"session_{safe_target}_{timestamp}.json"

        # Ensure base directory exists
        os.makedirs(base_dir, exist_ok=True)

        self.path = os.path.join(base_dir, filename)
        self.target = target
        self.data = {"target": target, "created": timestamp}
        self.waf = {}
        self.save()

    def update(self, key, value):
        self.data[key] = value
        self.save()

    def get(self, key, default=None):
        return self.data.get(key, default)

    def save(self):
        # Serialize dynamically added attributes
        for attr in ["subdomains", "alive_hosts", "endpoints", "waf", "nuclei_tags"]:
            if hasattr(self, attr):
                self.data[attr] = getattr(self, attr)
        if hasattr(self, "findings"):
            self.data["findings"] = [asdict(f) if hasattr(f, "__dataclass_fields__") else f for f in getattr(self, "findings")]
            
        # Ensure parent directory exists before writing
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w") as f:
            json.dump(self.data, f, indent=2, default=str)
        return self.path
