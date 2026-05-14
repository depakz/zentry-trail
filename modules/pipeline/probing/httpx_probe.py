"""Compatibility shim — orchestrator imports `probe` from here."""
from modules.recon.probing.probe import probe as _probe

async def probe(subdomains, max_tiers: int = 3):
    """Async entry used by core/orchestrator.py"""
    return await _probe(subdomains, max_tiers=max_tiers)
