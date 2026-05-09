import re
from typing import List, Dict, Set
from urllib.parse import urlparse, parse_qs
from .utils import logger


class ParameterExtractor:
    """Extract and analyze URLs with parameters"""
    
    INTERESTING_PARAMS = {
        # Reflection/XSS
        'id', 'search', 'q', 'query', 'keyword',
        'name', 'email', 'username', 'user', 'login',
        'text', 'message', 'content', 'data', 'body',
        'url', 'redirect', 'callback', 'return', 'goto',
        'next', 'referer', 'origin', 'source', 'from',
        
        # SQLI
        'product_id', 'category_id', 'post_id', 'page_id',
        'page', 'sort', 'filter', 'order', 'by', 'limit',
        'lang', 'version', 'format', 'type', 'mode',
        
        # SSRF/LFI
        'image', 'file', 'download', 'upload', 'load',
        'path', 'endpoint', 'target', 'proxy', 'server',
        'fetch', 'include', 'require', 'module', 'import',
        
        # Auth bypass
        'token', 'session', 'cookie', 'auth', 'jwt',
        'api_key', 'secret', 'password', 'pin', 'key',
        'otp', 'code', 'verify', 'confirm', 'token',
        
        # Information disclosure
        'version', 'debug', 'verbose', 'trace', 'log',
        'error', 'status', 'info', 'stats', 'metrics'
    }
    
    @staticmethod
    def extract_params_from_url(url: str) -> List[str]:
        """Extract parameter names from URL"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            return list(params.keys())
        except:
            return []
    
    @staticmethod
    def has_interesting_params(url: str) -> bool:
        """Check if URL has interesting parameters"""
        params = ParameterExtractor.extract_params_from_url(url)
        return any(p.lower() in ParameterExtractor.INTERESTING_PARAMS 
                  for p in params)
    
    @staticmethod
    def is_api_endpoint(url: str) -> bool:
        """Detect if URL is API endpoint"""
        api_patterns = [
            r'/api/',
            r'/v\d+/',
            r'/rest/',
            r'/graphql',
            r'/ajax/',
            r'\.json',
            r'\.xml',
            r'/ws/',
            r'/rpc'
        ]
        return any(re.search(pattern, url, re.I) for pattern in api_patterns)
    
    @staticmethod
    def is_auth_endpoint(url: str) -> bool:
        """Detect auth/login endpoints"""
        auth_patterns = [
            'login', 'auth', 'oauth', 'signin', 'signup',
            'register', 'verify', 'reset', 'password',
            'session', 'token', 'account', '2fa', 'mfa'
        ]
        return any(pattern in url.lower() for pattern in auth_patterns)
    
    @staticmethod
    def is_upload_endpoint(url: str) -> bool:
        """Detect upload/file endpoints"""
        upload_patterns = [
            'upload', 'file', 'media', 'attachment',
            'image', 'document', 'archive', 'export'
        ]
        return any(pattern in url.lower() for pattern in upload_patterns)
    
    @staticmethod
    def filter_high_value_endpoints(urls: Set[str]) -> Dict[str, List[str]]:
        """
        Filter and categorize URLs by attack surface
        Returns categorized endpoints
        """
        parameterized = []
        api_endpoints = []
        auth_endpoints = []
        upload_endpoints = []
        other = []
        
        for url in urls:
            categorized = False
            
            if ParameterExtractor.has_interesting_params(url):
                parameterized.append(url)
                categorized = True
            
            if ParameterExtractor.is_api_endpoint(url):
                if not categorized:
                    api_endpoints.append(url)
                categorized = True
            
            if ParameterExtractor.is_auth_endpoint(url):
                if not categorized:
                    auth_endpoints.append(url)
                categorized = True
            
            if ParameterExtractor.is_upload_endpoint(url):
                if not categorized:
                    upload_endpoints.append(url)
                categorized = True
            
            if not categorized:
                other.append(url)
        
        result = {
            'parameterized': list(set(parameterized)),
            'api': list(set(api_endpoints)),
            'auth': list(set(auth_endpoints)),
            'upload': list(set(upload_endpoints)),
            'other': list(set(other))[:50]  # Limit other
        }
        
        logger.info(f"\n🔍 ENDPOINT FILTERING:")
        logger.info(f"   ├─ Parameterized: {len(result['parameterized'])}")
        logger.info(f"   ├─ API endpoints: {len(result['api'])}")
        logger.info(f"   ├─ Auth endpoints: {len(result['auth'])}")
        logger.info(f"   ├─ Upload endpoints: {len(result['upload'])}")
        logger.info(f"   └─ Other: {len(result['other'])}")
        
        return result
    
    @staticmethod
    def create_scan_list(endpoints: Dict[str, List[str]]) -> List[str]:
        """
        Create prioritized scan list from endpoints
        """
        scan_list = []
        
        # Priority order
        for category in ['parameterized', 'api', 'auth', 'upload']:
            scan_list.extend(endpoints.get(category, []))
        
        # Add limited other
        scan_list.extend(endpoints.get('other', [])[:20])
        
        # Deduplicate while maintaining order
        seen = set()
        final = []
        for url in scan_list:
            if url not in seen:
                seen.add(url)
                final.append(url)
        
        return final
