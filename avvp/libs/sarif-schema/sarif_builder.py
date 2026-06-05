from dataclasses import dataclass, asdict
from typing import List, Dict, Any
import uuid
import json

@dataclass
class SARIFLocation:
    uri: str
    region: Dict[str, Any]

    def to_dict(self):
        return {
            "physicalLocation": {
                "artifactLocation": {"uri": self.uri},
                "region": self.region,
            }
        }

@dataclass
class SARIFResult:
    rule_id: str
    message: str
    level: str
    locations: List[SARIFLocation]

    def to_dict(self):
        return {
            "ruleId": self.rule_id,
            "message": {"text": self.message},
            "level": self.level,
            "locations": [loc.to_dict() for loc in self.locations],
        }

@dataclass
class SARIFRun:
    tool_name: str
    results: List[SARIFResult]

    def to_dict(self):
        return {
            "tool": {"driver": {"name": self.tool_name}},
            "results": [r.to_dict() for r in self.results],
        }


def build_sarif_report(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    # findings: list of dicts with keys: finding_id, vuln_class, severity, uri, region
    results = []
    for f in findings:
        loc = SARIFLocation(uri=f.get("uri", ""), region=f.get("region", {}))
        r = SARIFResult(rule_id=f.get("vuln_class", "VULN"),
                        message=f.get("summary", f.get("vuln_class", "")),
                        level=(f.get("severity", "warning") or "warning"),
                        locations=[loc])
        results.append(r)

    run = SARIFRun(tool_name="avvp", results=results)
    sarif = {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "runs": [run.to_dict()],
    }
    return sarif


def validate_sarif(sarif: Dict[str, Any]) -> None:
    # Minimal validation: version and runs
    if sarif.get("version") != "2.1.0":
        raise ValueError("SARIF version must be 2.1.0")
    if "runs" not in sarif or not isinstance(sarif["runs"], list):
        raise ValueError("SARIF must contain a 'runs' array")
    # More thorough validation can be added using the SARIF JSON schema + jsonschema.validate
