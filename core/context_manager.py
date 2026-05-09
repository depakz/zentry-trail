from dataclasses import dataclass, field
import json, pickle
from pathlib import Path

@dataclass
class Finding:
    title: str
    severity: str = "info"
    url: str = ""
    evidence: str = ""
    poc: dict = field(default_factory=dict)
    cwe: str = ""
    cvss: float = 0.0
    validated: bool = False

class Context:
    def __init__(self, target, mode, scope="*"):
        self.target = target
        self.mode = mode
        self.scope = scope
        self.assets = []
        self.candidates = []
        self.confirmed = []
        self.source_code_path = None
        self.notes = []
        self.workspace = Path("/workspace")

    def summary(self) -> str:
        return json.dumps({
            "target": self.target,
            "mode": self.mode,
            "scope": self.scope,
            "source_code_path": self.source_code_path,
            "assets_count": len(self.assets),
            "assets_sample": self.assets[:20],
            "candidates": [{"title": c.title, "url": c.url, "severity": c.severity} for c in self.candidates],
            "confirmed": [{"title": c.title, "url": c.url, "severity": c.severity} for c in self.confirmed],
            "notes": self.notes[-10:],
        }, indent=2)

    def save(self, path="context.pkl"):
        with open(path, "wb") as f:
            pickle.dump(self, f)

    @staticmethod
    def load(path="context.pkl"):
        with open(path, "rb") as f:
            return pickle.load(f)
