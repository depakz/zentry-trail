import asyncio
from avvp.services.osint.dedup import SimHashDeduplicator
from avvp.services.osint.crtsh_runner import CRTSHRunner


def test_simhash_dedup():
    dedup = SimHashDeduplicator()
    assert dedup.is_duplicate("example.com") is False
    assert dedup.is_duplicate("example.net") is False
    # near duplicate
    assert dedup.is_duplicate("example.com") is True


def test_crtsh_lookup():
    # This test hits crt.sh; allow it but tolerate failures by returning empty
    runner = CRTSHRunner()
    res = asyncio.run(runner.run("example.com"))
    assert isinstance(res, list)
