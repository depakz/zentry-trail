import re
from typing import List, Dict
from .utils import logger


class Prioritizer:
    """Score and prioritize domains by attack surface value"""
    
    HIGH_VALUE_KEYWORDS = {
        'api', 'admin', 'auth', 'dev', 'test', 'staging',
        'internal', 'backend', 'dashboard', 'console', 'management',
        'oauth', 'login', 'account', 'panel', 'control',
        'security', 'report', 'upload', 'download', 'export',
        'webhook', 'callback', 'integration', 'partner', 'graphql',
        'service', 'portal', 'system', 'app', 'web', 'server'
    }
    
    LOW_VALUE_KEYWORDS = {
        'cdn', 'assets', 'static', 'images', 'media',
        'fonts', 'cache', 'resources', 'public', 'js',
        'css', 'img', 'static', 'dist', 'build',
        'analytics', 'tracking', 'logs', 'metrics',
        'mail', 'smtp', 'pop', 'imap', 'files',
        'backup', 'archive', 'download', 'storage'
    }
    
    @staticmethod
    def score_domain(domain: str) -> int:
        """
        Score domain from 0-100
        Higher = more likely to have vulnerabilities
        """
        score = 50  # Base score
        
        domain_lower = domain.lower()
        
        # High-value keywords: +15 each
        for keyword in Prioritizer.HIGH_VALUE_KEYWORDS:
            if keyword in domain_lower:
                score += 15
        
        # Low-value keywords: -20 each
        for keyword in Prioritizer.LOW_VALUE_KEYWORDS:
            if keyword in domain_lower:
                score -= 20
        
        # Subdomain depth penalty
        dot_count = domain_lower.count('.')
        if dot_count > 3:
            score -= 5
        
        # Numeric in domain is often less valuable
        if re.search(r'\d+', domain_lower):
            score -= 2
        
        return max(0, min(100, score))
    
    @staticmethod
    def prioritize_hosts(hosts: List[str]) -> Dict[str, List[str]]:
        """
        Prioritize hosts into tiers
        Returns: {
            'tier1_deep': list,    # Top 100 - full scan
            'tier2_shallow': list, # Next 100 - limited scan
            'tier3_skip': list     # Rest - skip
        }
        """
        scored = [(host, Prioritizer.score_domain(host)) for host in hosts]
        scored.sort(key=lambda x: x[1], reverse=True)
        
        tier1 = [h[0] for h in scored[:100]]
        tier2 = [h[0] for h in scored[100:200]]
        tier3 = [h[0] for h in scored[200:]]
        
        logger.info(f"\n🎯 PRIORITIZATION RESULTS:")
        logger.info(f"   ├─ Tier-1 (DEEP scan): {len(tier1)} hosts")
        logger.info(f"   ├─ Tier-2 (SHALLOW): {len(tier2)} hosts")
        logger.info(f"   └─ Tier-3 (SKIP): {len(tier3)} hosts")
        
        # Show top 10
        logger.info(f"\n   🔥 TOP 10 TARGETS:")
        for i, (host, score) in enumerate(scored[:10], 1):
            logger.info(f"      {i:2}. {host:45} [score: {score:3}]")
        
        return {
            'tier1_deep': tier1,
            'tier2_shallow': tier2,
            'tier3_skip': tier3,
            'scored': scored
        }
