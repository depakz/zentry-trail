import asyncio
from modules.pipeline.scanning import nuclei_runner
async def main():
    res = await nuclei_runner.scan(["http://localhost:3000"], tags=["generic", "misconfig", "exposure"])
    print("RES:", res)
asyncio.run(main())
