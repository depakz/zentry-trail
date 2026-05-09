"""Compatibility shim — orchestrator imports `probe` from here."""
from modules.recon.probing.probe import probe as _probe

async def probe(subdomains):
    """Async entry used by core/orchestrator.py"""
    return await _probe(subdomains)
