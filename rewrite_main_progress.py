import sys

with open('main.py', 'r') as f:
    content = f.read()

# Replace core.logger import
content = content.replace("from core.logger import dashboard, logger", 
"""from core.logger import logger
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn""")

# _scan_target signature
content = content.replace("async def _scan_target(target: str, max_workers: int, recon_timeout: int) -> Dict[str, Any]:",
"async def _scan_target(target: str, max_workers: int, recon_timeout: int, progress: Progress, recon_task: int, validation_task: int) -> Dict[str, Any]:")

# dashboard.start() -> progress.console.log()
content = content.replace("""        dashboard.start()
        logger.info("=" * 72)
        logger.info(f"Starting unified scan against: {normalized_target}")
        logger.info("=" * 72)""",
"""        progress.console.log("=" * 72)
        progress.console.log(f"Starting unified scan against: {normalized_target}")
        progress.console.log("=" * 72)""")

# replace _sync_validation_progress
old_sync = """        async def _sync_validation_progress(validation_progress: Dict[str, Any], stop_event: asyncio.Event) -> None:
            while not stop_event.is_set():
                total = int(validation_progress.get("total", 0) or 0)
                completed = int(validation_progress.get("completed", 0) or 0)
                detail = str(validation_progress.get("detail", "waiting"))
                percent = int(100 * completed / total) if total > 0 else 0
                dashboard.update_validation(percent, detail)
                await asyncio.sleep(0.15)"""

new_sync = """        async def _sync_validation_progress(validation_progress: Dict[str, Any], stop_event: asyncio.Event) -> None:
            while not stop_event.is_set():
                total = int(validation_progress.get("total", 0) or 0)
                completed = int(validation_progress.get("completed", 0) or 0)
                detail = str(validation_progress.get("detail", "waiting"))
                # percent = int(100 * completed / total) if total > 0 else 0
                progress.update(validation_task, completed=completed, total=total if total > 0 else 100, description=f"[magenta]Validation: {detail}")
                await asyncio.sleep(0.15)"""

content = content.replace(old_sync, new_sync)

# replace dashboard.update_recon
content = content.replace("""        try:
            logger.info("Phase 1: Reconnaissance")
            dashboard.update_recon(0, "starting")""",
"""        try:
            progress.console.log("Phase 1: Reconnaissance")
            progress.update(recon_task, completed=0, description="[cyan]Reconnaissance: starting")""")

content = content.replace("""            dashboard.update_recon(100, "recon complete")""",
"""            progress.update(recon_task, completed=100, description="[cyan]Reconnaissance: complete")""")

content = content.replace("""            dashboard.update_validation(100, "validation complete")""",
"""            progress.update(validation_task, completed=100, description="[magenta]Validation: complete")""")

# replace logger.info with progress.console.log inside _scan_target? For simplicity, we can leave logger.info or change it.
# The user said: "Use progress.console.log() instead of standard print() to ensure logs appear above the static progress bar without breaking it."
# Actually, the user's instructions say "Use progress.console.log() instead of standard print()".
# main.py uses logger.info mostly. Let's just leave logger.info as it is, or replace it if necessary.
# Let's replace logger.info( with progress.console.log( inside _scan_target.

# Remove dashboard.finish() and dashboard.stop()
content = content.replace("dashboard.finish()\n", "")
content = content.replace("dashboard.stop()\n", "")
content = content.replace("            \n            return report\n        finally:\n            \n", "            return report\n        finally:\n            pass")

# Update main() to use the Progress context
old_main = """    try:
        os.environ["YUVA_SCAN_PROFILE"] = _select_scan_profile(args.url, args.profile)
        asyncio.run(_scan_target(args.url, min(16, max(1, args.max_workers)), min(1200, max(1, args.recon_timeout))))
    except KeyboardInterrupt:"""

new_main = """    try:
        os.environ["YUVA_SCAN_PROFILE"] = _select_scan_profile(args.url, args.profile)
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            transient=True # Hides the bar after completion
        ) as progress:
            recon_task = progress.add_task("[cyan]Reconnaissance...", total=100)
            validation_task = progress.add_task("[magenta]Validation...", total=100)
            
            asyncio.run(_scan_target(
                args.url, 
                min(16, max(1, args.max_workers)), 
                min(1200, max(1, args.recon_timeout)),
                progress,
                recon_task,
                validation_task
            ))
    except KeyboardInterrupt:"""

content = content.replace(old_main, new_main)

# Pass progress to run_recon_zentry
content = content.replace("parsed_data = await run_recon_zentry(normalized_target)",
"parsed_data = await run_recon_zentry(normalized_target, progress, recon_task)")

with open('main.py', 'w') as f:
    f.write(content)
