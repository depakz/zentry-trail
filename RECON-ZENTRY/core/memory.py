import json
from datetime import datetime
from typing import Optional
from collections import deque
from core.logger import Logger

logger = Logger("memory")

class Memory:
    def __init__(self, max_messages=50):
        self.max_messages = max_messages
        self.messages = deque(maxlen=max_messages)
        self.scan_results = {}
        self.findings = []
        self.target_info = {}
        self.created_at = datetime.now().isoformat()

    def add_message(self, role, content):
        self.messages.append({"role": role, "content": content, "timestamp": datetime.now().isoformat()})

    def get_context(self, last_n=None):
        messages = list(self.messages)
        if last_n:
            messages = messages[-last_n:]
        return [{"role": m["role"], "content": m["content"]} for m in messages]

    def store_scan_result(self, scan_type, target, result):
        key = f"{scan_type}_{target}"
        self.scan_results[key] = {"type": scan_type, "target": target, "result": result, "timestamp": datetime.now().isoformat()}

    def get_scan_result(self, scan_type, target):
        return self.scan_results.get(f"{scan_type}_{target}")

    def get_all_scan_results(self):
        return self.scan_results

    def add_finding(self, finding):
        finding["timestamp"] = datetime.now().isoformat()
        finding["id"] = len(self.findings) + 1
        self.findings.append(finding)

    def get_findings(self, severity=None):
        if severity:
            return [f for f in self.findings if f.get("severity", "").lower() == severity.lower()]
        return self.findings

    def set_target_info(self, target, info):
        self.target_info[target] = info

    def get_target_info(self, target):
        return self.target_info.get(target, {})

    def get_summary(self):
        return {
            "total_messages": len(self.messages),
            "total_scans": len(self.scan_results),
            "total_findings": len(self.findings),
            "targets": list(self.target_info.keys()),
            "finding_breakdown": {
                "critical": len(self.get_findings("critical")),
                "high": len(self.get_findings("high")),
                "medium": len(self.get_findings("medium")),
                "low": len(self.get_findings("low")),
                "info": len(self.get_findings("info")),
            },
        }

    def export(self):
        return {"created_at": self.created_at, "messages": list(self.messages), "scan_results": self.scan_results, "findings": self.findings, "target_info": self.target_info}

    def clear(self):
        self.messages.clear()
        self.scan_results.clear()
        self.findings.clear()
        self.target_info.clear()
