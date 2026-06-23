from urllib.parse import urlparse
from typing import List, Dict, Any

def extract_host(url: str) -> str:
    try:
        parsed = urlparse(url)
        return parsed.netloc or parsed.path.split("/")[0] or "unknown"
    except Exception:
        return str(url)

def normalize_vuln(name: str) -> str:
    name_lower = str(name).lower().strip()
    if name_lower in ("sqli", "sql-injection"):
        return "sql-injection"
    if name_lower in ("xss", "reflected-xss"):
        return "reflected-xss"
    if name_lower in ("csrf", "csrf-missing-protections"):
        return "csrf-missing-protections"
    return name_lower

class ChainEngine:
    def __init__(self, rules: List[Dict[str, Any]]):
        self.rules = rules

    def evaluate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        confirmed_chains = []
        
        # Build map of normalized vulnerability name -> list of matching findings
        vuln_to_findings: Dict[str, List[Dict[str, Any]]] = {}
        for f in findings:
            if not isinstance(f, dict):
                continue
            vuln = f.get("vulnerability")
            if not vuln:
                continue
            norm = normalize_vuln(vuln)
            vuln_to_findings.setdefault(norm, []).append(f)

        vuln_types = set(vuln_to_findings.keys())

        for rule in self.rules:
            required = [normalize_vuln(r) for r in rule["requires"]]
            if not set(required).issubset(vuln_types):
                continue

            # Apply any filters specified in the rule
            matched_findings_by_type = {}
            possible = True
            for req_vuln in required:
                candidates = vuln_to_findings[req_vuln]
                rule_filters = rule.get("filters", {}).get(req_vuln)
                if rule_filters:
                    filtered = []
                    for c in candidates:
                        match = True
                        for field, substring in rule_filters.items():
                            val = c.get(field)
                            if not val or substring.lower() not in str(val).lower():
                                match = False
                                break
                        if match:
                            filtered.append(c)
                    candidates = filtered
                if not candidates:
                    possible = False
                    break
                matched_findings_by_type[req_vuln] = candidates

            if not possible:
                continue

            # Check same_host requirement
            if rule.get("same_host"):
                # Group findings by host
                host_to_findings: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
                for req_vuln in required:
                    candidates = matched_findings_by_type[req_vuln]
                    for c in candidates:
                        host = extract_host(c.get("target_url") or c.get("url") or "")
                        host_to_findings.setdefault(host, {}).setdefault(req_vuln, []).append(c)

                # Find hosts that have all required vulnerabilities
                valid_hosts = []
                for host, vulns_map in host_to_findings.items():
                    if set(required).issubset(set(vulns_map.keys())):
                        comp_findings = []
                        for req_vuln in required:
                            comp_findings.extend(vulns_map[req_vuln])
                        valid_hosts.append((host, comp_findings))
                
                if not valid_hosts:
                    continue

                # Merge findings from all valid hosts
                component_findings = []
                seen_ids = set()
                for host, f_list in valid_hosts:
                    for f in f_list:
                        f_id = (f.get("target_url"), f.get("vulnerability"))
                        if f_id not in seen_ids:
                            seen_ids.add(f_id)
                            component_findings.append(f)
            else:
                component_findings = []
                for req_vuln in required:
                    component_findings.extend(matched_findings_by_type[req_vuln])

            if not component_findings:
                continue

            # Calculate and cap CVSS
            cvss_score = max(f.get("cvss") or f.get("score") or 0.0 for f in component_findings) + rule.get("cvss_boost", 0.0)
            cvss_score = min(10.0, max(0.0, cvss_score))

            chain = {
                "chain_id": rule["id"],
                "name": rule["name"],
                "description": rule["description"],
                "severity": rule["severity"],
                "owasp": rule["owasp"],
                "component_findings": component_findings,
                "cvss": round(cvss_score, 1)
            }
            confirmed_chains.append(chain)

        return confirmed_chains
