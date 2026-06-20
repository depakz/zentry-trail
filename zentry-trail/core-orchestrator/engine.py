import asyncio
import logging
from .context import Context
from datetime import datetime, timedelta
from typing import Optional

# Import modules from other directories
from zentry_trail.passive_recon import subfinder, crtsh
from zentry_trail.active_probing import httpx, waf_detect
from zentry_trail.dynamic_crawling import katana, gospider
from zentry_trail.cve_scanner import nuclei, catalog_pruner
from zentry_trail.validation_engine import registry
from zentry_trail.reporting_aggregator import parser, sarif_builder

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("orchestrator")

class SecurityValidationEngine:
    def __init__(self, root_domain: str):
        self.root_domain = root_domain
        self.context = Context()
        self.start_time: Optional[datetime] = None
        self.timeout = 840  # 14 minutes in seconds
        
    async def run(self):
        self.start_time = datetime.now()
        logger.info(f"Starting security validation for {self.root_domain}")
        
        try:
            # Set global timeout
            await asyncio.wait_for(self._run_pipeline(), timeout=self.timeout)
        except asyncio.TimeoutError:
            logger.warning("Pipeline execution timed out after 14 minutes")
        finally:
            await self._shutdown()
            
    async def _run_pipeline(self):
        # Phase 1: Passive Recon
        passive_tasks = [
            subfinder.run(self.root_domain, self.context),
            crtsh.run(self.root_domain, self.context)
        ]
        await asyncio.gather(*passive_tasks)
        
        # Phase 2: Active Probing
        active_tasks = [
            httpx.run(self.context),
            waf_detect.run(self.context)
        ]
        await asyncio.gather(*active_tasks)
        
        # Phase 3: Dynamic Crawling
        crawler_tasks = []
        while not self.context.asset_queue.empty():
            asset = await self.context.dequeue_asset()
            crawler_tasks.append(katana.run(asset, self.context))
            crawler_tasks.append(gospider.run(asset, self.context))
        
        await asyncio.gather(*crawler_tasks)
        
        # Phase 4: CVE Scanning
        tech_tags = [tech for sublist in self.context.tech_stacks.values() for tech in sublist]
        pruned_templates = catalog_pruner.prune_templates(tech_tags)
        await nuclei.run(self.context, pruned_templates)
        
        # Phase 5: Validation
        while not self.context.asset_queue.empty():
            finding = await self.context.dequeue_asset()
            await registry.route_finding(finding, self.context)
            
    async def _shutdown(self):
        logger.info("Initiating graceful shutdown")
        await self.context.graceful_shutdown()
        
        # Generate final report
        normalized_findings = parser.normalize_findings(self.context.results)
        sarif_report = sarif_builder.build_report(normalized_findings)
        
        # Save report to file
        report_path = f"security_report_{self.root_domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sarif"
        with open(report_path, 'w') as f:
            f.write(sarif_report)
            
        logger.info(f"Validation completed. Report saved to {report_path}")
        
async def main(root_domain: str):
    engine = SecurityValidationEngine(root_domain)
    await engine.run()

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python engine.py <root_domain>")
        sys.exit(1)
        
    asyncio.run(main(sys.argv[1]))