import os
import subprocess
import tempfile
from typing import List, Dict, Tuple
from .utils import Utils, logger
import json


class NucleiRunner:
    """Smart batched nuclei execution with timeouts"""
    
    BATCH_SIZE = 50  # URLs per batch
    BATCH_TIMEOUT = 300  # 5 minutes per batch
    
    TEMPLATES = [
        'cves/',
        'exposures/',
        'misconfigurations/',
        'vulnerabilities/',
    ]
    
    @staticmethod
    def run_batch(urls: List[str], batch_num: int, templates: List[str] = None) -> Dict:
        """
        Run nuclei on batch of URLs
        Returns: {'findings': [...], 'scanned': count}
        """
        if not urls:
            return {'findings': [], 'scanned': 0}
        
        if templates is None:
            templates = NucleiRunner.TEMPLATES
        
        # Create temp file with URLs
        batch_file = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                f.write('\n'.join(urls))
                batch_file = f.name
            
            # Build nuclei command - conservative settings
            template_flags = ' '.join([f'-t {t}' for t in templates])
            cmd = (
                f'nuclei -l "{batch_file}" {template_flags} '
                f'-json -silent -timeout 5 -rate-limit 50 '
                f'-retries 0 -severity critical,high,medium '
                f'-no-color 2>/dev/null'
            )
            
            logger.info(f"   ├─ [Batch {batch_num}] Running nuclei ({len(urls)} URLs)...")
            
            # Run with timeout
            stdout, code = Utils.run_command(cmd, timeout=NucleiRunner.BATCH_TIMEOUT)
            
            # Parse results
            findings = []
            for line in stdout.split('\n'):
                line = line.strip()
                if line:
                    try:
                        finding = json.loads(line)
                        findings.append(finding)
                    except:
                        pass
            
            logger.info(f"   └─ [Batch {batch_num}] ✓ {len(findings)} findings")
            return {'findings': findings, 'scanned': len(urls)}
            
        except subprocess.TimeoutExpired:
            logger.warning(f"   └─ [Batch {batch_num}] ⏱️ TIMEOUT")
            # Retry with half size
            if len(urls) > 10:
                logger.info(f"   └─ [Batch {batch_num}] Retrying with {len(urls)//2} URLs...")
                return NucleiRunner.run_batch(urls[:len(urls)//2], batch_num)
            return {'findings': [], 'scanned': 0}
        finally:
            if batch_file and os.path.exists(batch_file):
                os.unlink(batch_file)
    
    @staticmethod
    def scan_endpoints(endpoints: Dict[str, List[str]]) -> Dict:
        """
        Smart nuclei scanning with prioritization
        Only scans: parameterized, API, auth endpoints
        """
        all_findings = []
        total_scanned = 0
        
        # Build scan queue by priority
        scan_queue = []
        
        # Tier 1: Parameterized (highest priority)
        if endpoints.get('parameterized'):
            scan_queue.extend([
                ('parameterized', endpoints['parameterized'], 1)
            ])
        
        # Tier 2: API + Auth
        if endpoints.get('api'):
            scan_queue.extend([
                ('api', endpoints['api'], 2)
            ])
        if endpoints.get('auth'):
            scan_queue.extend([
                ('auth', endpoints['auth'], 2)
            ])
        
        # Tier 3: Upload
        if endpoints.get('upload'):
            scan_queue.extend([
                ('upload', endpoints['upload'], 3)
            ])
        
        batch_num = 1
        
        for endpoint_type, urls, priority in scan_queue:
            if not urls:
                continue
            
            logger.info(f"\n💥 SCANNING {endpoint_type.upper()} ({len(urls)} URLs):")
            
            # Split into batches
            for i in range(0, len(urls), NucleiRunner.BATCH_SIZE):
                batch = urls[i:i + NucleiRunner.BATCH_SIZE]
                result = NucleiRunner.run_batch(batch, batch_num)
                
                all_findings.extend(result['findings'])
                total_scanned += result['scanned']
                batch_num += 1
        
        logger.info(f"\n✅ NUCLEI SCANNING COMPLETE:")
        logger.info(f"   ├─ Total scanned: {total_scanned}")
        logger.info(f"   └─ Raw findings: {len(all_findings)}")
        
        return {
            'findings': all_findings,
            'scanned': total_scanned
        }
