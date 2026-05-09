import json
import os
from datetime import datetime
from pathlib import Path
import subprocess
import sys
from typing import List, Set, Optional, Tuple
import logging
from urllib.parse import urlparse

from rich.console import Console
from rich.logging import RichHandler

# Setup rich console
console = Console()

# Setup rich logging
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
    datefmt='[%X]',
    handlers=[RichHandler(rich_tracebacks=True, console=console, show_path=False)]
)
logger = logging.getLogger("yuva")


class Utils:
    """Utility functions for the framework"""
    
    @staticmethod
    def ensure_dir(path: str) -> str:
        """Ensure directory exists"""
        Path(path).mkdir(parents=True, exist_ok=True)
        return path
    
    @staticmethod
    def save_json(data, filepath: str):
        """Save JSON with pretty printing"""
        Utils.ensure_dir(os.path.dirname(filepath))
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        logger.info(f"📁 Saved: {filepath}")
    
    @staticmethod
    def load_json(filepath: str) -> dict:
        """Load JSON safely"""
        if not os.path.exists(filepath):
            return {}
        with open(filepath, 'r') as f:
            return json.load(f)
    
    @staticmethod
    def read_lines(filepath: str) -> Set[str]:
        """Read file lines as set (deduplicated)"""
        if not os.path.exists(filepath):
            return set()
        with open(filepath, 'r') as f:
            return set(line.strip() for line in f if line.strip())
    
    @staticmethod
    def write_lines(lines: Set, filepath: str):
        """Write set to file"""
        Utils.ensure_dir(os.path.dirname(filepath))
        with open(filepath, 'w') as f:
            f.write('\n'.join(sorted(lines)))
        logger.info(f"💾 Wrote {len(lines)} items to {filepath}")
    
    @staticmethod
    def run_command(cmd: str, timeout: int = 30, shell: bool = True) -> Tuple[str, int]:
        """Run command with timeout"""
        try:
            result = subprocess.run(
                cmd,
                shell=shell,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout, result.returncode
        except subprocess.TimeoutExpired:
            logger.warning(f"⏱️ TIMEOUT: {cmd[:50]}...")
            return "", 1
        except Exception as e:
            logger.error(f"❌ Command failed: {e}")
            return "", 1
    
    @staticmethod
    def tool_exists(tool: str) -> bool:
        """Check if tool is installed"""
        stdout, code = Utils.run_command(f"which {tool}")
        return code == 0
    
    @staticmethod
    def get_timestamp() -> str:
        """Get formatted timestamp"""
        return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    @staticmethod
    def dedup_urls(urls: List[str]) -> List[str]:
        """Deduplicate URLs maintaining order"""
        seen = set()
        result = []
        for url in urls:
            url = url.strip()
            if url and url not in seen:
                seen.add(url)
                result.append(url)
        return result
    
    @staticmethod
    def is_static_file(url: str) -> bool:
        """Check if URL is static asset"""
        static_exts = {
            '.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp',
            '.css', '.js', '.json', '.woff', '.woff2', '.ttf',
            '.ico', '.mp4', '.mp3', '.pdf', '.zip', '.tar',
            '.gz', '.tar.gz', '.exe', '.dmg', '.apk'
        }
        return any(url.lower().endswith(ext) for ext in static_exts)
    
    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize URL"""
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')
    
    @staticmethod
    def extract_domain(url: str) -> str:
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc
        except:
            return url
    
    @staticmethod
    def get_base_url(url: str) -> str:
        """Get base URL"""
        try:
            parsed = urlparse(url)
            return f"{parsed.scheme}://{parsed.netloc}"
        except:
            return url
