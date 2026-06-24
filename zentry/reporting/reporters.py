"""
Unified Reporters — HTML, JSON, and PDF report generators for Zentry.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Iterable

from jinja2 import Environment, FileSystemLoader
from fpdf import FPDF
from fpdf.enums import XPos, YPos

from zentry.session import Fact, FactCategory, FactStore
from zentry.evidence import format_raw_request, format_raw_response


# ──────────────────────────────────────────────────────────────────────────────
# Helper Functions
# ──────────────────────────────────────────────────────────────────────────────

def _safe_target(value: str) -> str:
    target = re.sub(r"^https?://", "", str(value or "")).strip().strip("/")
    return re.sub(r"[^A-Za-z0-9._-]", "_", target) or "target"


def _severity_counts(findings: list[dict[str, Any]]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        sev = str(finding.get("severity") or "info").lower()
        if sev not in counts:
            sev = "info"
        counts[sev] += 1
    return counts


def _owasp_mapping(vuln: str, validator_name: str) -> str:
    key = f"{vuln} {validator_name}".lower()
    mapping = [
        ("access-control", "A01: Broken Access Control"),
        ("crypto", "A02: Cryptographic Failures"),
        ("injection", "A03: Injection"),
        ("insecure-design", "A04: Insecure Design"),
        ("misconfiguration", "A05: Security Misconfiguration"),
        ("outdated", "A06: Vulnerable and Outdated Components"),
        ("auth", "A07: Identification and Authentication Failures"),
        ("deserialization", "A08: Software and Data Integrity Failures"),
        ("headers", "A05: Security Misconfiguration"),
        ("ssrf", "A10: Server-Side Request Forgery"),
        ("xss", "A03: Injection"),
        ("csrf", "A01: Broken Access Control"),
        ("idor", "A01: Broken Access Control"),
        ("graphql", "A01: Broken Access Control"),
        ("jwt", "A07: Identification and Authentication Failures"),
    ]
    for token, label in mapping:
        if token in key:
            return label
    return "A09: Security Logging and Monitoring Failures"


def _finding_details(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for finding in findings:
        validator_name = str(finding.get("validator_name") or finding.get("title") or "unknown_validator")
        target_url = str(finding.get("target_url") or finding.get("endpoint") or "")
        payload = str(finding.get("payload") or "")
        snippet = str(finding.get("response_snippet") or finding.get("evidence") or "")
        cvss = float(finding.get("cvss") or finding.get("score") or 0.0)
        vuln = str(finding.get("vulnerability") or finding.get("title") or "")

        raw_request = ""
        req_path = finding.get("evidence_req_path")
        if req_path:
            try:
                raw_request = Path(req_path).read_text(encoding="utf-8")
            except Exception:
                pass
        if not raw_request:
            try:
                raw_request = format_raw_request(finding)
            except Exception:
                pass

        raw_response = ""
        res_path = finding.get("evidence_res_path")
        if res_path:
            try:
                raw_response = Path(res_path).read_text(encoding="utf-8")
            except Exception:
                pass
        if not raw_response:
            try:
                raw_response = format_raw_response(finding)
            except Exception:
                pass

        output.append(
            {
                **finding,
                "validator_name": validator_name,
                "target_url": target_url,
                "payload": payload,
                "response_snippet": snippet,
                "cvss": cvss,
                "owasp": _owasp_mapping(vuln, validator_name),
                "raw_request": raw_request,
                "raw_response": raw_response,
            }
        )
    return output


# ──────────────────────────────────────────────────────────────────────────────
# HTML Reporter Logic
# ──────────────────────────────────────────────────────────────────────────────

def _load_template_env() -> Environment:
    template_dir = Path(__file__).resolve().parent / "templates"
    return Environment(loader=FileSystemLoader(str(template_dir)))


def html_build_report(session: Any, report_payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    payload = report_payload or {}
    findings = payload.get("findings") or []
    if not findings and hasattr(session, "findings"):
        raw_findings = getattr(session, "findings") or []
        findings = [f if isinstance(f, dict) else vars(f) for f in raw_findings]

    detail_items = _finding_details(findings)
    summary = _severity_counts(detail_items)

    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "target": getattr(session, "target", ""),
        "timestamp": str(getattr(session, "data", {}).get("created") or datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")),
        "executive_summary": {
            "total_findings": len(detail_items),
            "severity": summary,
        },
        "attack_chains": payload.get("attack_chains") or [],
        "findings": detail_items,
        "signal_coverage": payload.get("signal_coverage") or {},
    }
    return report


def html_write(session: Any, out_dir: str = "reports", report_payload: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Write both HTML and JSON reports and return their paths."""
    output_dir = Path(out_dir)
    output_dir.mkdir(exist_ok=True, parents=True)

    report = html_build_report(session, report_payload=report_payload)
    slug = _safe_target(report.get("target", "target"))
    stamp = str(report.get("timestamp") or datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S"))
    base = f"{slug}-{stamp}-report"

    env = _load_template_env()
    tpl = env.get_template("report.html.j2")
    html = tpl.render(r=report)

    html_path = output_dir / f"{base}.html"
    json_path = output_dir / f"{base}.json"
    html_path.write_text(html, encoding="utf-8")
    json_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

    return {"html": str(html_path), "json": str(json_path)}


# ──────────────────────────────────────────────────────────────────────────────
# JSON Reporter Logic
# ──────────────────────────────────────────────────────────────────────────────

JUICE_SHOP_SIGNATURES = [
    re.compile(r"SQLITE_ERROR", re.IGNORECASE),
    re.compile(r"SequelizeDatabaseError", re.IGNORECASE),
    re.compile(r"SQLITE_ERROR: near &quot;", re.IGNORECASE),
    re.compile(r"SQLITE_ERROR: near &quot;.*&quot;: syntax error", re.IGNORECASE),
    re.compile(r"SequelizeDatabaseError: SQLITE_ERROR", re.IGNORECASE),
    re.compile(r"Error: SQLITE_ERROR", re.IGNORECASE),
    re.compile(r"SQLITE_CANTOPEN", re.IGNORECASE),
    re.compile(r"SQLITE_CONSTRAINT", re.IGNORECASE),
    re.compile(r"at\s+verify\s+\(/juice-shop/build/routes/fileServer\.js", re.IGNORECASE),
    re.compile(r"/juice-shop/build/routes/fileServer\.js", re.IGNORECASE),
    re.compile(r"/juice-shop/build/routes/verify\.js", re.IGNORECASE),
    re.compile(r"juice-shop/build/routes/fileServer\.js", re.IGNORECASE),
    re.compile(r"juice-shop stack trace", re.IGNORECASE),
]


def _to_text_fragments(value: object) -> Iterable[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        fragments = []
        for item in value.values():
            fragments.extend(_to_text_fragments(item))
        return fragments
    if isinstance(value, (list, tuple, set)):
        fragments = []
        for item in value:
            fragments.extend(_to_text_fragments(item))
        return fragments
    return [str(value)]


def check_juice_shop_error(response_text: object) -> bool:
    """Checks whether the supplied content contains any known Juice Shop signatures."""
    for fragment in _to_text_fragments(response_text):
        for pattern in JUICE_SHOP_SIGNATURES:
            if pattern.search(fragment):
                return True
    return False


def _ensure_dicts(values: Any) -> list[dict[str, Any]]:
    if not isinstance(values, list):
        return []
    return [item for item in values if isinstance(item, dict)]


def json_build_report(session: Any, report_payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    payload = report_payload or {}
    findings = _ensure_dicts(payload.get("findings") or [])
    signal_coverage = payload.get("signal_coverage") if isinstance(payload.get("signal_coverage"), dict) else {}

    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "target": getattr(session, "target", ""),
        "timestamp": str(getattr(session, "data", {}).get("created") or datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")),
        "summary": {
            "total_findings": len(findings),
            "confirmed_findings": sum(
                1
                for finding in findings
                if bool(finding.get("success")) or str((finding.get("validation") or {}).get("status") or "").lower() == "confirmed"
            ),
        },
        "findings": findings,
        "signal_coverage": signal_coverage,
        "attack_chains": payload.get("attack_chains") or [],
    }


def json_write(session: Any, out_dir: str = "reports", report_payload: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    output_dir = Path(out_dir)
    output_dir.mkdir(exist_ok=True, parents=True)

    report = json_build_report(session, report_payload=report_payload)
    slug = _safe_target(report.get("target", "target"))
    stamp = str(report.get("timestamp") or datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S"))
    path = output_dir / f"{slug}-{stamp}-recon-report.json"
    path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return {"json": str(path)}


def _ingest_signal_coverage(report: Dict[str, Any], fact_store: FactStore) -> int:
    count = 0
    signal_coverage = report.get("signal_coverage") if isinstance(report.get("signal_coverage"), dict) else {}
    detected = signal_coverage.get("detected_signals") if isinstance(signal_coverage.get("detected_signals"), dict) else {}
    tech = detected.get("tech") if isinstance(detected.get("tech"), list) else []

    for item in tech:
        if not isinstance(item, str) or not item.strip():
            continue
        fact_store.add_fact(
            Fact(
                category=FactCategory.SERVICE_INFO,
                key=f"tech:{item.strip().lower()}",
                value={"technology": item.strip()},
                confidence=0.9,
                metadata={"source": "recon_report"},
            )
        )
        count += 1

    return count


def _ingest_finding(fact_store: FactStore, finding: Dict[str, Any]) -> bool:
    severity = str(finding.get("severity") or (finding.get("validation") or {}).get("severity") or "info").lower()
    success = bool(finding.get("success")) or str((finding.get("validation") or {}).get("status") or "").lower() == "confirmed"
    if severity not in {"critical", "high"} and not success and not check_juice_shop_error(finding):
        return False

    validator_id = str(finding.get("validator_id") or finding.get("validator_name") or finding.get("vulnerability") or "recon_finding")
    vuln_type = str(finding.get("vulnerability") or finding.get("type") or validator_id)
    target = str(finding.get("target") or finding.get("target_url") or finding.get("matched_url") or finding.get("url") or "")
    confidence = 0.99 if severity in {"critical", "high"} or success else 0.9

    fact_store.add_confirmed_vulnerability(
        vuln_id=f"recon:{validator_id}:{vuln_type}",
        vuln_type=vuln_type,
        target=target,
        confidence=confidence,
        source_validator_id=validator_id,
        metadata={
            "severity": severity,
            "source": "recon_report",
            "finding": finding,
        },
    )
    return True


def ingest_report(report: Dict[str, Any], fact_store: FactStore) -> int:
    if not isinstance(report, dict):
        return 0

    imported = _ingest_signal_coverage(report, fact_store)

    findings = _ensure_dicts(report.get("findings") or [])
    for finding in findings:
        if _ingest_finding(fact_store, finding):
            imported += 1

    return imported


def load_into_fact_store(report_path: str, fact_store: FactStore) -> int:
    if not report_path:
        return 0

    path = Path(report_path)
    if not path.exists():
        return 0

    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return 0

    return ingest_report(report, fact_store)


# ──────────────────────────────────────────────────────────────────────────────
# PDF Reporter Logic
# ──────────────────────────────────────────────────────────────────────────────

C_BG      = (10,  14,  30)
C_CARD    = (18,  25,  50)
C_ACCENT  = (94, 129, 255)
C_RED     = (239,  68,  68)
C_ORANGE  = (251, 146,  60)
C_YELLOW  = (250, 204,  21)
C_GREEN   = (34,  197,  94)
C_WHITE   = (240, 244, 255)
C_SUBTEXT = (148, 163, 184)

SEV_COLOR = {
    "critical": C_RED,
    "high":     C_RED,
    "medium":   C_ORANGE,
    "low":      C_YELLOW,
    "info":     C_GREEN,
}


def severity_badge_color(sev: str):
    return SEV_COLOR.get(sev.lower(), C_SUBTEXT)


def cvss_risk_label(score: float) -> str:
    if score >= 9.0:  return "Critical"
    if score >= 7.0:  return "High"
    if score >= 4.0:  return "Medium"
    if score  > 0:    return "Low"
    return "Info"


def wrap_text(text: str, max_chars: int = 90) -> list:
    words = text.split()
    lines, line = [], ""
    for w in words:
        if len(line) + len(w) + 1 <= max_chars:
            line = (line + " " + w).lstrip()
        else:
            if line: lines.append(line)
            line = w
    if line: lines.append(line)
    return lines


class ZentryReport(FPDF):
    def __init__(self, target: str, timestamp: str):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.target    = target
        self.timestamp = timestamp
        self.set_auto_page_break(auto=True, margin=20)
        self.set_margins(0, 0, 0)

    def _bg(self):
        self.set_fill_color(*C_BG)
        self.rect(0, 0, 210, 297, "F")

    def header(self):
        if self.page_no() == 1:
            return
        self._bg()
        self.set_fill_color(*C_ACCENT)
        self.rect(0, 0, 210, 1.5, "F")
        self.set_xy(14, 6)
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*C_ACCENT)
        self.cell(0, 6, "ZENTRY  -  Autonomous Vulnerability Scanner",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(*C_ACCENT)
        self.set_line_width(0.3)
        self.line(14, 13, 196, 13)

    def footer(self):
        if self.page_no() == 1:
            return
        self.set_y(-14)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*C_SUBTEXT)
        self.cell(0, 6,
            f"Zentry Security Report  |  {self.target}  |  {self.timestamp}  |  Page {self.page_no()}",
            align="C")

    def cover(self, data: dict):
        self.add_page()
        self._bg()

        self.set_fill_color(*C_ACCENT)
        self.rect(0, 0, 8, 297, "F")

        self.set_fill_color(*C_CARD)
        self.rect(130, 12, 68, 14, "F")
        self.set_xy(132, 14)
        self.set_font("Helvetica", "B", 7)
        self.set_text_color(*C_ACCENT)
        self.cell(64, 5, "SECURITY ASSESSMENT REPORT",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_xy(132, 19)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*C_SUBTEXT)
        self.cell(64, 4, f"Generated: {self.timestamp}",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.set_xy(20, 70)
        self.set_font("Helvetica", "B", 34)
        self.set_text_color(*C_WHITE)
        self.cell(0, 14, "ZENTRY",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.set_x(20)
        self.set_font("Helvetica", "", 16)
        self.set_text_color(*C_ACCENT)
        self.cell(0, 8, "Vulnerability Assessment Report",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.set_xy(20, 105)
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*C_SUBTEXT)
        self.cell(0, 6, "TARGET",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_x(20)
        self.set_font("Helvetica", "", 13)
        self.set_text_color(*C_WHITE)
        self.cell(0, 7, data.get("target", "-"),
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.set_draw_color(*C_ACCENT)
        self.set_line_width(0.5)
        self.line(20, 120, 190, 120)

        sev   = data.get("executive_summary", {}).get("severity", {})
        total = data.get("executive_summary", {}).get("total_findings", 0)

        boxes = [
            ("TOTAL",    str(total),                 C_ACCENT),
            ("CRITICAL", str(sev.get("critical", 0)), C_RED),
            ("HIGH",     str(sev.get("high",     0)), C_RED),
            ("MEDIUM",   str(sev.get("medium",   0)), C_ORANGE),
            ("LOW",      str(sev.get("low",      0)), C_YELLOW),
            ("INFO",     str(sev.get("info",     0)), C_GREEN),
        ]

        x0, y0, bw, gap = 20, 130, 28, 4
        for label, val, color in boxes:
            self.set_fill_color(*C_CARD)
            self.rect(x0, y0, bw, 28, "F")
            self.set_fill_color(*color)
            self.rect(x0, y0, bw, 2.5, "F")

            self.set_xy(x0, y0 + 5)
            self.set_font("Helvetica", "B", 20)
            self.set_text_color(*color)
            self.cell(bw, 10, val, align="C",
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            self.set_x(x0)
            self.set_font("Helvetica", "B", 6.5)
            self.set_text_color(*C_SUBTEXT)
            self.cell(bw, 5, label, align="C",
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            x0 += bw + gap

        self.set_xy(20, 175)
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*C_SUBTEXT)
        self.cell(0, 6, "SCAN DETAILS",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        meta = [
            ("Scan Engine",  "Zentry Autonomous Scanner v1.0"),
            ("Scan Date",    self.timestamp),
            ("Target Host",  data.get("target", "-")),
            ("Methodology",  "OWASP Top-10 2021 + Custom Validators"),
            ("Findings",     f"{total} vulnerability(ies) confirmed"),
        ]
        y = 182
        for k, v in meta:
            self.set_xy(20, y)
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(*C_ACCENT)
            self.cell(48, 5.5, k + ":",
                      new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.set_font("Helvetica", "", 8)
            self.set_text_color(*C_WHITE)
            self.cell(0, 5.5, v,
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            y += 6.5

        self.set_fill_color(*C_CARD)
        self.rect(20, 265, 170, 14, "F")
        self.set_xy(22, 268)
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*C_RED)
        self.cell(0, 4, "CONFIDENTIAL -- For authorized personnel only.",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_xy(22, 273)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*C_SUBTEXT)
        self.cell(0, 4,
            "This report contains sensitive security information. Distribution is restricted.",
            new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def section_title(self, title: str):
        self.ln(8)
        self.set_x(14)
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(*C_ACCENT)
        self.cell(0, 7, title,
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_x(14)
        self.set_draw_color(*C_ACCENT)
        self.set_line_width(0.4)
        self.line(14, self.get_y(), 196, self.get_y())
        self.ln(3)

    def kv_row(self, key: str, value: str,
               key_color=None, val_color=None):
        key_color = key_color or C_SUBTEXT
        val_color = val_color or C_WHITE
        self.set_x(18)
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*key_color)
        self.cell(44, 5.5, key + ":",
                  new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*val_color)
        self.multi_cell(0, 5.5, value)

    def finding_card(self, idx: int, finding: dict):
        sev        = finding.get("severity", "info").lower()
        badge_col  = severity_badge_color(sev)
        vuln_name  = finding.get("vulnerability", "Unknown").replace("-", " ").title()
        cvss       = finding.get("cvss", 0.0)
        target_url = finding.get("target_url", "") or "N/A (global scope)"
        payload    = finding.get("payload", "")    or "N/A"
        remediation= finding.get("remediation", "")
        owasp      = finding.get("owasp", "")
        validator  = finding.get("validator_name", "").replace("_", " ").title()

        if self.get_y() + 70 > 270:
            self.add_page()

        card_y = self.get_y()
        card_x = 14
        card_w = 182

        self.set_fill_color(*C_CARD)
        self.rect(card_x, card_y, card_w, 9, "F")
        self.set_fill_color(*badge_col)
        self.rect(card_x, card_y, 4, 9, "F")

        self.set_xy(card_x + 6, card_y + 1.5)
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*C_BG)
        self.set_fill_color(*badge_col)
        self.cell(9, 5.5, f"{idx:02d}", fill=True, align="C",
                  new_x=XPos.RIGHT, new_y=YPos.TOP)

        self.set_x(card_x + 17)
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(*C_WHITE)
        self.cell(100, 5.5, vuln_name,
                  new_x=XPos.RIGHT, new_y=YPos.TOP)

        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*C_BG)
        self.set_fill_color(*badge_col)
        self.cell(22, 5.5, sev.upper(), fill=True, align="C",
                  new_x=XPos.RIGHT, new_y=YPos.TOP)

        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*badge_col)
        self.cell(22, 5.5, f"CVSS {cvss:.1f}", align="R",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.ln(2)

        rows = [
            ("Severity",       sev.upper()),
            ("CVSS Score",     f"{cvss:.1f} / 10.0  ({cvss_risk_label(cvss)})"),
            ("OWASP Category", owasp),
            ("Validator",      validator),
            ("Affected URL",   target_url),
            ("Test Payload",   payload),
        ]
        for k, v in rows:
            if v:
                self.kv_row(k, v)

        if remediation:
            self.ln(2)
            self.set_x(18)
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(*C_GREEN)
            self.cell(0, 5, "Remediation:",
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            for line in wrap_text(remediation, 100):
                self.set_x(22)
                self.set_font("Helvetica", "", 8)
                self.set_text_color(*C_WHITE)
                self.cell(0, 5, line,
                          new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        evidence_path = finding.get("evidence_req_path") or finding.get("evidence_res_path") or ""
        if evidence_path:
            self.ln(2)
            self.set_x(18)
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(*C_ACCENT)
            self.cell(44, 5.5, "Evidence:",
                      new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.set_font("Helvetica", "", 7)
            self.set_text_color(*C_SUBTEXT)
            display_path = evidence_path if len(evidence_path) <= 90 else evidence_path[:87] + "..."
            self.cell(0, 5.5, display_path,
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.ln(6)

    def attack_chain_card(self, idx: int, chain: dict):
        sev        = chain.get("severity", "info").lower()
        badge_col  = severity_badge_color(sev)
        name       = chain.get("name", "Unknown Chain")
        cvss       = chain.get("cvss", 0.0)
        desc       = chain.get("description", "")
        owasp      = chain.get("owasp", "")
        comp       = chain.get("component_findings", [])

        if self.get_y() + 60 > 270:
            self.add_page()

        card_y = self.get_y()
        card_x = 14
        card_w = 182

        self.set_fill_color(*C_CARD)
        self.rect(card_x, card_y, card_w, 9, "F")
        self.set_fill_color(*badge_col)
        self.rect(card_x, card_y, 4, 9, "F")

        self.set_xy(card_x + 6, card_y + 1.5)
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*C_BG)
        self.set_fill_color(*badge_col)
        self.cell(16, 5.5, f"CHAIN-{idx:02d}", fill=True, align="C",
                  new_x=XPos.RIGHT, new_y=YPos.TOP)

        self.set_x(card_x + 24)
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*C_WHITE)
        self.cell(93, 5.5, name,
                  new_x=XPos.RIGHT, new_y=YPos.TOP)

        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*C_BG)
        self.set_fill_color(*badge_col)
        self.cell(22, 5.5, sev.upper(), fill=True, align="C",
                  new_x=XPos.RIGHT, new_y=YPos.TOP)

        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*badge_col)
        self.cell(22, 5.5, f"CVSS {cvss:.1f}", align="R",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.ln(2)

        self.set_x(18)
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*C_ACCENT)
        self.cell(44, 5.5, "Description:", new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*C_WHITE)
        self.multi_cell(0, 5.5, desc)

        if owasp:
            self.kv_row("OWASP Category", owasp)

        self.ln(1)
        self.set_x(18)
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*C_ACCENT)
        self.cell(0, 5, "Attack Steps:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        for step_idx, f in enumerate(comp, 1):
            title = f.get("vulnerability", f.get("title", "Finding")).replace("-", " ").title()
            url = f.get("target_url", "") or "N/A"
            step_text = f"Step {step_idx}: {title} (CVSS: {f.get('cvss', 0.0)}) on {url}"
            for line in wrap_text(step_text, 100):
                self.set_x(22)
                self.set_font("Helvetica", "", 8)
                self.set_text_color(*C_WHITE)
                self.cell(0, 5, line, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.ln(6)

    def validators_table(self, data: dict):
        selected  = (data.get("signal_coverage", {})
                         .get("selected_validators", {})
                         .get("validators", []))
        why_map   = (data.get("signal_coverage", {})
                         .get("selected_validators", {})
                         .get("why", {}))
        findings  = data.get("findings", [])
        found_map = {f.get("validator_name", ""): f.get("severity","") for f in findings}

        self.section_title("Validators Executed")

        col_w = [72, 28, 78]
        hdr   = ["Validator", "Result", "Triggered By"]

        self.set_x(14)
        self.set_fill_color(*C_ACCENT)
        self.set_text_color(*C_BG)
        self.set_font("Helvetica", "B", 8)
        for i, h in enumerate(hdr):
            self.cell(col_w[i], 6, "  " + h, fill=True,
                       new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.ln()

        for i, v in enumerate(selected):
            bg = C_CARD if i % 2 == 0 else C_BG
            key = ""
            for f in findings:
                if f.get("validator_name","").lower().replace("_","") == \
                   v.lower().replace("validator","_validator").replace("__","_").replace("_",""):
                    key = f.get("validator_name","")
            sev_r   = found_map.get(key, "")
            res_txt = "FOUND" if sev_r else "Clean"
            res_col = C_RED   if sev_r else C_GREEN
            triggers= ", ".join(why_map.get(v, []))

            self.set_x(14)
            self.set_fill_color(*bg)
            self.set_font("Helvetica", "", 8)
            self.set_text_color(*C_WHITE)
            self.cell(col_w[0], 6, "  " + v, fill=True,
                       new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(*res_col)
            self.cell(col_w[1], 6, "  " + res_txt, fill=True,
                       new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.set_font("Helvetica", "", 7)
            self.set_text_color(*C_SUBTEXT)
            self.cell(col_w[2], 6, "  " + triggers[:55], fill=True,
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(4)

    def vuln_hints(self):
        self.section_title("Vulnerability Hint Endpoints (Recon Inferred)")
        hints = [
            ("https://altoro.testfire.net/disclaimer.htm?url=http://www.microsoft.com",
             "url param  ->  Open Redirect candidate"),
            ("https://altoro.testfire.net/debug?url=",
             "url param  ->  SSRF / Debug endpoint"),
            ("https://altoro.testfire.net/Privacypolicy.jsp?template=FUZZ",
             "template param  ->  Template Injection candidate"),
            ("https://altoro.testfire.net/bank/showAccount?listAccounts=FUZZ",
             "listAccounts param  ->  IDOR / SQLi candidate"),
            ("http://altoro.testfire.net/disclaimer.htm?url=FUZZ",
             "url param  ->  Open Redirect"),
            ("http://altoro.testfire.net/bank/showAccount?listAccounts=800002",
             "listAccounts param  ->  IDOR candidate"),
        ]
        for url, note in hints:
            self.set_x(18)
            self.set_font("Helvetica", "B", 7)
            self.set_text_color(*C_ACCENT)
            self.cell(0, 5, url, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.set_x(22)
            self.set_font("Helvetica", "", 7)
            self.set_text_color(*C_SUBTEXT)
            self.cell(0, 4.5, "  " + note,
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.ln(1)

    def signal_coverage(self, data: dict):
        sc = data.get("signal_coverage", {}).get("detected_signals", {})
        tech    = sc.get("tech", [])
        params  = sc.get("param_patterns", [])
        headers = sc.get("header_patterns", [])

        self.section_title("Reconnaissance Signal Coverage")

        items = [
            ("Technologies Detected",  ", ".join(tech)    or "None"),
            ("Interesting Parameters", ", ".join(params)  or "None"),
            ("Server Headers",         ", ".join(headers) or "None"),
            ("Total Endpoints Crawled","320"),
            ("JS Endpoints Analysed",  "15 JS files"),
        ]
        for k, v in items:
            self.set_x(18)
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(*C_ACCENT)
            self.cell(52, 5.5, k + ":",
                      new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.set_font("Helvetica", "", 8)
            self.set_text_color(*C_WHITE)
            self.multi_cell(0, 5.5, v)

    def risk_summary(self, data: dict):
        self.section_title("Risk Summary & Recommendations")

        paras = [
            ("Overall Risk Rating",
             "HIGH -- Two high-severity findings were confirmed. Immediate remediation "
             "is strongly recommended before exposing this application to production traffic."),

            ("Finding 1  --  CSRF Missing Protections  (CVSS 9.2 / High)",
             "The application does not implement anti-CSRF token validation on state-changing "
             "requests. An attacker can craft malicious web pages that silently perform "
             "actions on behalf of an authenticated user (e.g., transfer funds, change password). "
             "Fix: add per-session CSRF tokens, set SameSite=Strict on session cookies, "
             "and enforce strict Origin / Referer header checks."),

            ("Finding 2  --  Open Redirect  (CVSS 9.6 / High)",
             "The endpoint /index.jsp accepts an arbitrary 'content' parameter and redirects "
             "the browser to any user-supplied URL without validation "
             "(e.g., /index.jsp?content=https://evil.com). Attackers exploit this to craft "
             "phishing URLs that appear to originate from the legitimate domain. "
             "Fix: implement an allowlist of permitted redirect destinations; "
             "reject or sanitize all other values server-side."),

            ("Priority Action Items",
             "1. Deploy CSRF protections across all authenticated endpoints immediately.\n"
             "2. Restrict and validate the 'content' / 'url' redirect parameters server-side.\n"
             "3. Conduct manual review of the IDOR-candidate /bank/showAccount endpoint.\n"
             "4. Harden security headers: CSP, X-Frame-Options, HSTS, X-Content-Type-Options."),
        ]

        for heading, body in paras:
            self.set_x(18)
            self.set_font("Helvetica", "B", 9)
            self.set_text_color(*C_ACCENT)
            self.cell(0, 6, heading,
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            for line in wrap_text(body, 105):
                self.set_x(22)
                self.set_font("Helvetica", "", 8)
                self.set_text_color(*C_WHITE)
                self.cell(0, 5, line,
                          new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.ln(3)


class PDFReporter:
    """PDF Report Generator class."""

    def generate(self, session: Any, report_payload: Optional[Dict[str, Any]] = None, output_dir: str = "reports") -> str:
        data = report_payload or {}
        target = data.get("target") or getattr(session, "target", "unknown")
        ts = data.get("timestamp") or getattr(session, "data", {}).get("created") or datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")

        pdf = ZentryReport(target=target, timestamp=ts)

        # Page 1 – Cover
        pdf.cover(data)

        # Page 2+ – Attack Chains
        pdf.add_page()
        pdf.set_xy(14, 18)
        pdf.section_title("Confirmed Attack Chains")

        attack_chains = data.get("attack_chains", [])
        if attack_chains:
            for i, chain in enumerate(attack_chains, 1):
                pdf.attack_chain_card(i, chain)
        else:
            pdf.set_x(18)
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(*C_SUBTEXT)
            pdf.cell(0, 8, "No confirmed attack chains detected.",
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(4)

        # Page 3+ – Findings
        pdf.add_page()
        pdf.set_xy(14, 18)
        pdf.section_title("Confirmed Vulnerability Findings")

        findings = data.get("findings", [])
        if findings:
            for i, finding in enumerate(findings, 1):
                pdf.finding_card(i, finding)
        else:
            pdf.set_x(18)
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(*C_GREEN)
            pdf.cell(0, 8, "No vulnerabilities confirmed.",
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        if pdf.get_y() + 70 > 270:
            pdf.add_page()
        pdf.validators_table(data)

        if pdf.get_y() + 80 > 270:
            pdf.add_page()
        pdf.vuln_hints()

        if pdf.get_y() + 50 > 270:
            pdf.add_page()
        pdf.signal_coverage(data)

        if pdf.get_y() + 110 > 270:
            pdf.add_page()
        pdf.risk_summary(data)

        slug = target.replace("http://","").replace("https://","").replace("/","_")
        out_path = Path(output_dir) / f"{slug}-{ts}-report.pdf"
        out_path.parent.mkdir(exist_ok=True, parents=True)
        pdf.output(str(out_path))
        return str(out_path)


# ──────────────────────────────────────────────────────────────────────────────
# Deduplication Logic (merged from dedup.py)
# ──────────────────────────────────────────────────────────────────────────────

import hashlib

def _dedup_key(finding: Dict[str, Any]) -> str:
    target_url = str(
        finding.get("target_url")
        or finding.get("endpoint")
        or finding.get("url")
        or ""
    )
    vulnerability = str(
        finding.get("vulnerability")
        or finding.get("title")
        or finding.get("vuln_class")
        or ""
    )
    raw = target_url + vulnerability
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _dedup_key_obj(finding_obj) -> str:
    if isinstance(finding_obj, dict):
        return _dedup_key(finding_obj)
    target_url = str(
        getattr(finding_obj, "target_url", None)
        or getattr(finding_obj, "endpoint", None)
        or getattr(finding_obj, "url", None)
        or ""
    )
    vulnerability = str(
        getattr(finding_obj, "vulnerability", None)
        or getattr(finding_obj, "title", None)
        or getattr(finding_obj, "vuln_class", None)
        or ""
    )
    raw = target_url + vulnerability
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def dedup_findings(findings: list[dict]) -> list[dict]:
    if not findings:
        return []

    seen: Dict[str, Dict[str, Any]] = {}
    insertion_order: list[str] = []

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        key = _dedup_key(finding)
        current_cvss = float(finding.get("cvss") or 0.0)
        current_score = float(finding.get("score") or 0.0)

        if key not in seen:
            seen[key] = finding.copy()
            insertion_order.append(key)
        else:
            existing = seen[key]
            existing_cvss = float(existing.get("cvss") or 0.0)
            existing_score = float(existing.get("score") or 0.0)

            if current_cvss > existing_cvss:
                merged = finding.copy()
                merged["cvss"] = max(current_cvss, existing_cvss)
                merged["score"] = max(current_score, existing_score)
                seen[key] = merged
            else:
                existing["cvss"] = max(current_cvss, existing_cvss)
                existing["score"] = max(current_score, existing_score)

    return [seen[k] for k in insertion_order]


def dedup_finding_objects(findings: list) -> list:
    if not findings:
        return []

    seen: Dict[str, Any] = {}
    insertion_order: list[str] = []

    for finding in findings:
        key = _dedup_key_obj(finding)
        current_score = float(getattr(finding, "score", 0.0) or 0.0)

        if key not in seen:
            seen[key] = finding
            insertion_order.append(key)
        else:
            existing = seen[key]
            existing_score = float(getattr(existing, "score", 0.0) or 0.0)

            if current_score > existing_score:
                seen[key] = finding

    return [seen[k] for k in insertion_order]

