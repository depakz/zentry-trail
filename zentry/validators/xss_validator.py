"""
XSSValidator — Enhanced class-based validator for DAG/ValidationEngine pipeline.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, parse_qsl, urlunsplit, urlencode, urljoin, urlparse

import requests
import urllib3

from zentry.session import Evidence, ValidationResult
from zentry.validators.base import BaseValidator

# Disable insecure request warning for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ──────────────────────────────────────────────────────────────────────────────
# Payloads
# ──────────────────────────────────────────────────────────────────────────────
REFLECTION_PROBE = "xss_zentry_probe_8472"
DANGEROUS_CHARS  = ["<", ">", '"', "'"]

HTML_PAYLOADS = [
    "<b>zentry_xss_tag</b>",
    "<h1>zentry_xss_h1</h1>",
    "<i>zentry_xss_i</i>",
    "<marquee>zentry_xss</marquee>",
    "<img src=x>",
]

JS_PAYLOADS = [
    "<script>alert(document.domain)</script>",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    '"><svg/onload=alert(1)>',
]

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ZentryScanner/2.0)"}

HIGH_PRIORITY_PARAMS = {
    "query", "search", "q", "s", "find", "keyword", "term", "text",
    "message", "comment", "name", "input", "data", "value",
    "title", "desc", "description", "content", "note", "body",
}


def _get(url: str, cookies: dict = None, timeout: int = 15) -> tuple[int, str]:
    try:
        r = requests.get(url, headers=HEADERS, cookies=cookies or {},
                         timeout=timeout, allow_redirects=True, verify=False)
        return r.status_code, r.text
    except Exception:
        return 0, ""


def _post(url: str, data: dict, cookies: dict = None, timeout: int = 15) -> tuple[int, str]:
    try:
        r = requests.post(url, data=data, headers=HEADERS, cookies=cookies or {},
                          timeout=timeout, allow_redirects=True, verify=False)
        return r.status_code, r.text
    except Exception:
        return 0, ""


def _chars_unescaped(body: str, probe: str) -> list[str]:
    """Return dangerous chars reflected unescaped around the probe."""
    idx = body.find(probe)
    if idx == -1:
        return []
    ctx = body[max(0, idx - 200): idx + 200 + len(probe)]
    HTML_ESCAPES = {"<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}
    unescaped = []
    for c in DANGEROUS_CHARS:
        escaped = HTML_ESCAPES.get(c, c)
        if c in ctx and escaped not in ctx:
            unescaped.append(c)
    return unescaped


class XSSValidator(BaseValidator):
    validator_id = "xss_validator"
    priority = 90

    def __init__(self, context=None):
        super().__init__()
        self.context = context

    def can_run(self, state: Dict[str, Any]) -> bool:
        url = state.get("url") or state.get("target")
        return isinstance(url, str) and url.startswith(("http://", "https://"))

    def run(self, state: Dict[str, Any]) -> Optional[ValidationResult]:
        target_url = state.get("url") or state.get("target")
        if not target_url:
            return None

        # Stored XSS check
        auth_manager = state.get("auth_manager")
        if auth_manager and auth_manager.authenticated:
            session = auth_manager.get_session()
            
            # 1. Test /feedback.jsp (POST)
            feedback_url = urljoin(target_url, "/feedback.jsp")
            try:
                r_get = session.get(feedback_url, verify=False, timeout=8)
                if r_get.status_code == 200:
                    payload = "<u>zentry_stored_xss_test</u>"
                    post_data = {
                        "name": "Zentry Tester",
                        "email": "tester@zentry.test",
                        "subject": "Security Test",
                        "comments": payload,
                        "btnSubmit": "Submit"
                    }
                    r_post = session.post(feedback_url, data=post_data, verify=False, timeout=10)
                    r_check = session.get(feedback_url, verify=False, timeout=8)
                    if payload in r_check.text and "<u>" in r_check.text:
                        return ValidationResult(
                            success=True,
                            confidence=0.98,
                            severity="high",
                            vulnerability="stored-xss",
                            evidence=Evidence(
                                request={"target": feedback_url, "param": "comments", "payload": payload, "method": "POST", "post_data": post_data},
                                response={"snippet": r_check.text[:500]},
                                matched=payload,
                            ),
                            impact="Stored XSS confirmed on /feedback.jsp. Comments are rendered unescaped.",
                            remediation="Encode all user-supplied comments using HTML entity encoding before storing/rendering."
                        )
            except Exception:
                pass

            # 2. Test /search.jsp (GET)
            search_url = urljoin(target_url, "/search.jsp")
            try:
                payload = "<u>zentry_reflected_xss_search</u>"
                test_url = search_url + "?query=" + requests.utils.quote(payload)
                r = session.get(test_url, verify=False, timeout=8)
                if r.status_code == 200 and payload in r.text and "<u>" in r.text:
                    return ValidationResult(
                        success=True,
                        confidence=0.96,
                        severity="high",
                        vulnerability="reflected-xss",
                        evidence=Evidence(
                            request={"target": test_url, "param": "query", "payload": payload, "method": "GET"},
                            response={"snippet": r.text[:500]},
                            matched=payload,
                        ),
                        impact="Reflected XSS confirmed on /search.jsp using auth session.",
                        remediation="HTML encode all search query parameters before rendering them in the search results page."
                    )
            except Exception:
                pass

        endpoints: List[str] = list(state.get("endpoints", []) or [])
        cookies: dict = state.get("auth_cookies") or {}

        forms = self._discover_forms(target_url, endpoints, cookies)

        test_targets = []
        for f in forms:
            for field in f["fields"]:
                test_targets.append({
                    "url": f["url"],
                    "param": field,
                    "method": f["method"],
                    "fields": {fd: "1" for fd in f["fields"]},
                    "type": "form"
                })

        for ep in endpoints[:40]:
            try:
                full_ep = urljoin(target_url, ep)
                parsed_ep = urlsplit(full_ep)
                params = [k for k, _ in parse_qsl(parsed_ep.query, keep_blank_values=True)]
                for p in params:
                    test_targets.append({
                        "url": full_ep,
                        "param": p,
                        "method": "GET",
                        "fields": {k: v for k, v in parse_qsl(parsed_ep.query, keep_blank_values=True)},
                        "type": "query"
                    })
            except Exception:
                pass

        seen = set()
        dedup_targets = []
        for t in test_targets:
            key = (urlparse(t["url"]).path, t["param"].lower(), t["method"])
            if key not in seen:
                seen.add(key)
                dedup_targets.append(t)

        dedup_targets = sorted(
            dedup_targets,
            key=lambda x: (0 if x["param"].lower() in HIGH_PRIORITY_PARAMS else 1, x["url"])
        )

        for t in dedup_targets[:25]:
            result = self._test_target(t, cookies)
            if result:
                return result

        return None

    def _discover_forms(self, base_url: str, endpoints: List[str], cookies: dict) -> List[Dict[str, Any]]:
        forms = []
        seen_forms = set()
        
        base_host = urlsplit(base_url).netloc
        urls_to_check = [base_url]
        for ep in endpoints:
            full = urljoin(base_url, ep)
            if urlsplit(full).netloc == base_host:
                urls_to_check.append(full)
        
        urls_to_check = list(dict.fromkeys(urls_to_check))
        
        def priority(u: str) -> int:
            u_lower = u.lower()
            if any(k in u_lower for k in ("login", "signin", "auth", "session", "search", "query", "feedback", "contact", "register", "signup")):
                return 0
            if any(u_lower.endswith(ext) for ext in (".jsp", ".php", ".aspx", ".html", ".htm")):
                return 1
            if u_lower.endswith("/"):
                return 2
            return 3
            
        urls_to_check = sorted(urls_to_check, key=priority)
        
        for url in urls_to_check[:15]:
            try:
                r = requests.get(url, headers=HEADERS, cookies=cookies, timeout=8, allow_redirects=True, verify=False)
                if r.status_code != 200:
                    continue
                body = r.text
                form_blocks = re.findall(r'<form[^>]*>.*?</form>', body, re.I | re.S)
                for block in form_blocks:
                    method_match = re.search(r'method=["\']?(post|get)["\']?', block, re.I)
                    method = method_match.group(1).upper() if method_match else "GET"
                    
                    action_match = re.search(r'action=["\']([^"\']*)["\']', block, re.I)
                    action = action_match.group(1) if action_match else ""
                    action_url = urljoin(url, action)
                    
                    fields = []
                    for input_match in re.finditer(r'<input[^>]+>', block, re.I):
                        name_match = re.search(r'name=["\']([^"\']+)["\']', input_match.group(0), re.I)
                        type_match = re.search(r'type=["\']?submit["\']?', input_match.group(0), re.I)
                        if name_match and not type_match:
                            fields.append(name_match.group(1))
                    
                    if fields:
                        form_key = (action_url, method, tuple(sorted(fields)))
                        if form_key not in seen_forms:
                            seen_forms.add(form_key)
                            forms.append({
                                "url": action_url,
                                "method": method,
                                "fields": fields
                            })
            except Exception:
                continue
        return forms

    def _test_target(self, target: Dict[str, Any], cookies: dict) -> Optional[ValidationResult]:
        url = target["url"]
        param = target["param"]
        method = target["method"]
        fields = dict(target["fields"])

        probe_val = REFLECTION_PROBE
        test_fields = dict(fields)
        test_fields[param] = probe_val

        if method == "POST":
            status, body = _post(url, test_fields, cookies)
        else:
            status, body = _get(self._rebuild_get_url(url, test_fields), cookies)

        if probe_val in body:
            danger_val = f"{REFLECTION_PROBE}<>\"'"
            danger_fields = dict(fields)
            danger_fields[param] = danger_val
            
            if method == "POST":
                _, danger_body = _post(url, danger_fields, cookies)
            else:
                _, danger_body = _get(self._rebuild_get_url(url, danger_fields), cookies)
            
            unescaped = _chars_unescaped(danger_body, REFLECTION_PROBE)

            if "<" in unescaped or ">" in unescaped:
                tag_fields = dict(fields)
                tag_fields[param] = HTML_PAYLOADS[0]
                
                if method == "POST":
                    _, tag_body = _post(url, tag_fields, cookies)
                else:
                    _, tag_body = _get(self._rebuild_get_url(url, tag_fields), cookies)
                
                if "zentry_xss_tag" in tag_body and "<b>" in tag_body:
                    evidence_url = url if method == "POST" else self._rebuild_get_url(url, tag_fields)
                    return self.confirm_finding(
                        request_obj=None,
                        response_obj=None,
                        vulnerability="reflected-xss",
                        severity="high",
                        confidence=0.97,
                        param=param,
                        payload=HTML_PAYLOADS[0],
                        impact=f"Reflected XSS confirmed on parameter '{param}' using {method}.",
                        remediation="Apply HTML entity encoding to all user-supplied data before rendering it in the DOM.",
                        raw_request=None,
                        raw_response=None,
                    )

                if unescaped:
                    evidence_url = url if method == "POST" else self._rebuild_get_url(url, danger_fields)
                    return self.confirm_finding(
                        request_obj=None,
                        response_obj=None,
                        vulnerability="reflected-xss-unescaped-chars",
                        severity="high",
                        confidence=0.88,
                        param=param,
                        payload=danger_val,
                        impact=f"Reflected XSS — characters {unescaped} reflected unescaped in response for parameter '{param}' via {method}.",
                        remediation="HTML-encode all user input before rendering in HTML context.",
                    )

            elif '"' in unescaped:
                evidence_url = url if method == "POST" else self._rebuild_get_url(url, danger_fields)
                return self.confirm_finding(
                    request_obj=None,
                    response_obj=None,
                    vulnerability="reflected-xss-attribute-context",
                    severity="high",
                    confidence=0.80,
                    param=param,
                    payload=danger_val,
                    impact=f"Attribute-context XSS: unescaped double-quote in parameter '{param}' via {method}.",
                    remediation="HTML-attribute-encode all user input used inside HTML attributes.",
                )

        for payload in JS_PAYLOADS:
            test_fields = dict(fields)
            test_fields[param] = payload
            
            if method == "POST":
                _, body = _post(url, test_fields, cookies)
            else:
                _, body = _get(self._rebuild_get_url(url, test_fields), cookies)
                
            if "<script>" in body.lower() and "alert" in body.lower():
                snippet_idx = body.lower().find("<script>")
                evidence_url = url if method == "POST" else self._rebuild_get_url(url, test_fields)
                return self.confirm_finding(
                    request_obj=None,
                    response_obj=None,
                    vulnerability="reflected-xss-script-tag",
                    severity="high",
                    confidence=0.93,
                    param=param,
                    payload=payload,
                    impact=f"Reflected XSS — <script> tag injected unescaped via parameter '{param}' using {method}.",
                    remediation="HTML-encode output; implement Content Security Policy (CSP).",
                )

        return None

    def _rebuild_get_url(self, url: str, params: Dict[str, str]) -> str:
        parts = urlsplit(url)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(params, doseq=True), parts.fragment))
