import requests
from typing import Dict, List
from .utils import logger
import re


class Validator:
    """Validate findings to eliminate false positives"""
    
    INVALID_TEMPLATES = {
        'robots-txt', 'sitemap', 'security-txt',
        'directory-listing', 'comments', 'cookie',
        'headers', 'redirect', 'http-banner'
    }
    
    @staticmethod
    def is_valid_template(template_name: str) -> bool:
        """Check if template is actionable"""
        template_lower = template_name.lower()
        return not any(inv in template_lower for inv in Validator.INVALID_TEMPLATES)
    
    @staticmethod
    def validate_xss(url: str, param: str = None, payload: str = None) -> bool:
        """
        Validate XSS by checking reflection
        """
        if not payload:
            payload = '<script>alert(1)</script>'
        
        try:
            if param:
                test_url = f"{url}?{param}={payload}"
            else:
                test_url = url
            
            resp = requests.get(test_url, timeout=10, allow_redirects=False)
            
            # Check reflection
            if payload in resp.text:
                logger.info(f"      ✅ XSS CONFIRMED: {url}")
                return True
            return False
        except:
            return False
    
    @staticmethod
    def validate_sqli(url: str, param: str = None) -> bool:
        """
        Basic SQLi validation via error patterns
        """
        try:
            payloads = ["'", "1' OR '1'='1"]
            error_patterns = [
                r"sql", r"mysql", r"postgresql", r"oracle",
                r"syntax error", r"unclosed quote",
                r"you have an error", r"exception"
            ]
            
            for payload in payloads:
                if param:
                    test_url = f"{url}?{param}={payload}"
                else:
                    test_url = url
                
                try:
                    resp = requests.get(test_url, timeout=10)
                    
                    if any(re.search(pattern, resp.text, re.I) 
                           for pattern in error_patterns):
                        logger.info(f"      ✅ SQLI CONFIRMED: {url}")
                        return True
                except:
                    pass
            
            return False
        except:
            return False
    
    @staticmethod
    def validate_finding(finding: Dict) -> bool:
        """
        Validate nuclei finding
        Returns: True if valid (not FP)
        """
        try:
            # Extract finding details
            template = finding.get('template', {})
            template_name = template.get('name', '').lower()
            host = finding.get('host', '')
            
            # Skip invalid templates
            if not Validator.is_valid_template(template_name):
                return False
            
            # High confidence keywords
            high_confidence = [
                'cve-', 'rce', 'sqli', 'xss', 'auth',
                'exposed', 'default', 'weak', 'bypass',
                'injection', 'access', 'disclosure'
            ]
            
            is_high_confidence = any(
                hc in template_name for hc in high_confidence
            )
            
            if not is_high_confidence:
                return False
            
            # Try to reach the URL
            try:
                resp = requests.head(host, timeout=5, allow_redirects=False)
                return resp.status_code < 500
            except:
                return False
                
        except:
            return False
    
    @staticmethod
    def validate_findings(findings: List[Dict]) -> List[Dict]:
        """
        Validate all findings, return only valid ones
        """
        validated = []
        
        logger.info(f"\n✔️ VALIDATING {len(findings)} FINDINGS:")
        
        for i, finding in enumerate(findings, 1):
            template_name = finding.get('template', {}).get('name', 'unknown')
            
            if Validator.validate_finding(finding):
                validated.append(finding)
                logger.info(f"   ├─ [{i:3}/{len(findings):3}] ✅ {template_name}")
            else:
                logger.info(f"   ├─ [{i:3}/{len(findings):3}] ❌ {template_name}")
        
        logger.info(f"   └─ Result: {len(validated)}/{len(findings)} valid findings\n")
        return validated
