"""
Standalone test for the probing module.
Usage:
  python3 test_probe.py example.com www.example.com api.example.com
  python3 test_probe.py --file subs.txt
"""
import sys
import json
import asyncio
from modules.recon.probing.probe import probe

async def main():
    if "--file" in sys.argv:
        path = sys.argv[sys.argv.index("--file") + 1]
        with open(path) as f:
            domains = [l.strip() for l in f if l.strip()]
    else:
        domains = sys.argv[1:]
        if not domains:
            domains = ["example.com", "www.example.com", "*.example.com",
                       "https://google.com/search", "nonexistent-xyz-123.com"]

    print(f"\n🎯 Testing probe with {len(domains)} domains:\n")
    for d in domains:
        print(f"  • {d}")
    print()

    results = await probe(domains, enable_waf_detect=True)

    print(f"\n{'='*70}")
    print(f"📊 RESULTS: {len(results)} alive hosts")
    print(f"{'='*70}\n")
    for r in results:
        print(json.dumps(r, indent=2))
        print("-" * 50)

if __name__ == "__main__":
    asyncio.run(main())
