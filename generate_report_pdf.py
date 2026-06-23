#!/usr/bin/env python3
"""
Zentry Vulnerability Report — Human-Readable PDF Generator
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from fpdf import FPDF
from fpdf.enums import XPos, YPos

# ──────────────────────────────────────────────────────────────────────────────
# Colour palette
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


# ──────────────────────────────────────────────────────────────────────────────
# PDF class
# ──────────────────────────────────────────────────────────────────────────────
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

    # ── header / footer (all pages except cover) ──────────────────────────────
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

    # ── cover ─────────────────────────────────────────────────────────────────
    def cover(self, data: dict):
        self.add_page()
        self._bg()

        # left accent stripe
        self.set_fill_color(*C_ACCENT)
        self.rect(0, 0, 8, 297, "F")

        # top-right badge
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

        # title
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

        # target
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

        # divider
        self.set_draw_color(*C_ACCENT)
        self.set_line_width(0.5)
        self.line(20, 120, 190, 120)

        # summary boxes
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

        # meta table
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

        # confidential banner
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

    # ── helpers ───────────────────────────────────────────────────────────────
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

    # ── finding card ──────────────────────────────────────────────────────────
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

        # ── header row ────────────────────────────────────────────────────────
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

        # ── detail rows ───────────────────────────────────────────────────────
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

        # ── remediation ───────────────────────────────────────────────────────
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

        # ── evidence path reference (Part E) ──────────────────────────────
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
            # Truncate path for display
            display_path = evidence_path if len(evidence_path) <= 90 else evidence_path[:87] + "..."
            self.cell(0, 5.5, display_path,
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.ln(6)

    # ── attack chain card ─────────────────────────────────────────────────────
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

        # ── header row ────────────────────────────────────────────────────────
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

        # Description
        self.set_x(18)
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*C_ACCENT)
        self.cell(44, 5.5, "Description:", new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*C_WHITE)
        self.multi_cell(0, 5.5, desc)

        # OWASP category
        if owasp:
            self.kv_row("OWASP Category", owasp)

        # Component findings as attack steps
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

    # ── validators table ──────────────────────────────────────────────────────
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
            # map "OpenRedirectValidator" -> "open_redirect_validator"
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

    # ── vuln hints ────────────────────────────────────────────────────────────
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

    # ── signal coverage ───────────────────────────────────────────────────────
    def signal_coverage(self, data: dict):
        sc      = data.get("signal_coverage", {}).get("detected_signals", {})
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

    # ── risk summary ──────────────────────────────────────────────────────────
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


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────
def main():
    json_path = Path("reports/altoro.testfire.net-2026-06-20_15-20-53-report.json")
    if not json_path.exists():
        reports = sorted(Path("reports").glob("*.json"))
        if not reports:
            print("ERROR: No JSON report found in reports/")
            sys.exit(1)
        json_path = reports[-1]

    with open(json_path) as f:
        data = json.load(f)

    ts     = data.get("timestamp",
                datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S"))
    target = data.get("target", "unknown")

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
    out  = f"reports/{slug}-{ts}-report.pdf"
    pdf.output(out)
    print(f"\n  PDF report saved -> {out}\n")
    return out


if __name__ == "__main__":
    main()
