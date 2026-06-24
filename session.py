"""
ScanSession: Dataclass for storing scan state, findings, and metadata.
Includes methods for saving and loading session state to/from JSON.
"""

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class Finding:
    """A single validated vulnerability finding."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str = ""
    severity: str = "info"
    endpoint: str = ""
    evidence: str = ""
    validated: bool = False
    cve: List[str] = field(default_factory=list)
    score: float = 0.0


@dataclass
class ScanSession:
    """Stores the state of a single scan session."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: str = ""
    started_at: int = field(default_factory=lambda: int(time.time()))
    subdomains: List[str] = field(default_factory=list)
    alive_hosts: List[Dict[str, Any]] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)
    waf: Dict[str, str] = field(default_factory=dict)
    nuclei_tags: List[str] = field(default_factory=list)

    def save(self, out_dir: str = "data/sessions") -> str:
        """Save session to a JSON file."""
        out_path = Path(out_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime(self.started_at))
        safe_target = self.target.replace("http://", "").replace("https://", "").replace("/", "_")
        filename = out_path / f"session_{safe_target}_{ts}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(asdict(self), f, indent=2)
        return str(filename)