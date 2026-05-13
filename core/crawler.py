import re
from typing import List, Set, Dict
from urllib.parse import urljoin, urlparse
from .utils import Utils, logger
import tempfile
import os


class Crawler:
    """Smart crawling with katana + gau fallback"""
    
    @staticmethod
    def crawl_katana(url: str, timeout: int = 30, depth: int = 2) -> Set[str]:
        """Crawl with katana (fast web crawler)"""
        try:
            cmd = (
                f'katana -u "{url}" -d {depth} -silent '
                f'-timeout {timeout} -rate-limit 150 -c 50 '
                f'-no-color 2>/dev/null'
            )
            stdout, code = Utils.run_command(cmd, timeout=timeout + 10)
            
            urls = set()
            for line in stdout.split('\n'):
                line = line.strip()
                if line and line.startswith(('http://', 'https://')):
                    urls.add(line)
            
            return urls
        except Exception as e:
            logger.warning(f"   ✗ katana error: {str(e)[:50]}")
            return set()
    
    @staticmethod
    def crawl_gau(domain: str, timeout: int = 20) -> Set[str]:
        """Crawl with gau (wayback URLs)"""
        try:
            cmd = f'gau --threads 3 --timeout {timeout} "{domain}" 2>/dev/null'
            stdout, code = Utils.run_command(cmd, timeout=timeout + 5)
            
            urls = set()
            for line in stdout.split('\n'):
                line = line.strip()
                if line and line.startswith(('http://', 'https://')):
                    urls.add(line)
            
            return urls
        except Exception as e:
            logger.warning(f"   ✗ gau error: {str(e)[:50]}")
            return set()
    
    @staticmethod
    def crawl_waybackurls(domain: str) -> Set[str]:
        """Fallback to waybackurls"""
        try:
            cmd = f'waybackurls "{domain}" 2>/dev/null'
            stdout, code = Utils.run_command(cmd, timeout=30)
            
            urls = set()
            for line in stdout.split('\n'):
                line = line.strip()
                if line and line.startswith(('http://', 'https://')):
                    urls.add(line)
            
            return urls
        except Exception as e:
            logger.warning(f"   ✗ waybackurls error: {str(e)[:50]}")
            return set()
    
    @staticmethod
    def discover_endpoints(hosts: List[str], tier: str = 'tier1') -> Dict[str, Set[str]]:
        """
        Discover endpoints from list of hosts
        tier: 'tier1' (deep) or 'tier2' (shallow)
        Returns: {'katana': set, 'gau': set, 'all': set}
        """
        katana_urls = set()
        gau_urls = set()
        
        if tier == 'tier1':
            depth = 2
            timeout = 20
            use_gau = True
        else:
            depth = 1
            timeout = 15
            use_gau = False
        
        logger.info(f"\n🕷️ ENDPOINT DISCOVERY ({tier}):")
        logger.info(f"   Starting crawl of {len(hosts)} hosts...")
        
        for i, host in enumerate(hosts, 1):
            host = Utils.normalize_url(host)
            
            # Katana crawl
            logger.info(f"   [{i:3}/{len(hosts):3}] 🔍 {host}")
            urls = Crawler.crawl_katana(host, timeout=timeout, depth=depth)
            if urls:
                logger.info(f"           └─ katana: {len(urls)} URLs")
                katana_urls.update(urls)
            
            # GAU only for tier1
            if use_gau:
                domain = Utils.extract_domain(host)
                gau = Crawler.crawl_gau(domain, timeout=10)
                if gau:
                    logger.info(f"           └─ gau: {len(gau)} URLs")
                    gau_urls.update(gau)
        
        # Filter static files
        all_urls = katana_urls | gau_urls
        filtered = {url for url in all_urls 
                   if not Utils.is_static_file(url)}
        
        logger.info(f"\n📊 CRAWLING SUMMARY:")
        logger.info(f"   ├─ Katana URLs: {len(katana_urls)}")
        logger.info(f"   ├─ GAU URLs: {len(gau_urls)}")
        logger.info(f"   ├─ Total raw: {len(all_urls)}")
        logger.info(f"   └─ After filtering: {len(filtered)}")
        
        return {
            'katana': katana_urls,
            'gau': gau_urls,
            'all': filtered
        }
