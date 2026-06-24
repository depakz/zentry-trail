import asyncio
import json
import os
import shutil
import subprocess
import tempfile
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger("zentry.recon.tool_wrappers")

ROOT_DIR = Path(__file__).resolve().parents[2]
ROOT_BIN_DIR = ROOT_DIR / "bin"

def resolve_binary(name: str) -> Optional[str]:
    """Resolve a tool binary from ./bin first, then PATH."""
    candidates = [ROOT_BIN_DIR / name]
    for candidate in candidates:
        try:
            if candidate.exists() and candidate.is_file():
                return str(candidate)
        except Exception:
            continue
    discovered = shutil.which(name)
    if discovered:
        return discovered
    return None

class ToolWrappers:
    def __init__(self):
        pass

    async def run_subfinder(self, domain: str) -> List[str]:
        binary = resolve_binary("subfinder")
        if not binary:
            logger.warning("subfinder binary not found")
            return []
        try:
            cmd = [binary, "-d", domain, "-silent"]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            output = stdout.decode(errors="ignore") if stdout else ""
            return [line.strip() for line in output.splitlines() if line.strip()]
        except Exception as e:
            logger.error(f"Error running subfinder: {e}")
            return []

    async def run_amass(self, domain: str) -> List[str]:
        binary = resolve_binary("amass")
        if not binary:
            logger.warning("amass binary not found")
            return []
        try:
            cmd = [binary, "enum", "-passive", "-d", domain, "-timeout", "2", "-silent"]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            output = stdout.decode(errors="ignore") if stdout else ""
            return [line.strip() for line in output.splitlines() if line.strip() and domain in line]
        except Exception as e:
            logger.error(f"Error running amass: {e}")
            return []

    async def run_httpx(self, domains: List[str]) -> List[Dict[str, Any]]:
        binary = resolve_binary("httpx")
        if not binary:
            logger.warning("httpx binary not found")
            # Fallback
            return [{"url": f"http://{d}", "host": d, "scheme": "http"} for d in domains]
        if not domains:
            return []
        try:
            with tempfile.NamedTemporaryFile(mode="w+", delete=False) as f:
                f.write("\n".join(domains))
                f_path = f.name
            
            cmd = [
                binary,
                "-l", f_path,
                "-json",
                "-silent",
                "-status-code",
                "-title",
                "-tech-detect",
                "-ip",
                "-follow-redirects",
                "-timeout", "10",
                "-threads", "50",
                "-retries", "1",
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            
            try:
                os.unlink(f_path)
            except Exception:
                pass

            output = stdout.decode(errors="ignore") if stdout else ""
            results = []
            for line in output.splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    url = data.get("url")
                    if url:
                        results.append({
                            "url": url,
                            "input": data.get("input", ""),
                            "status": data.get("status_code", 200),
                            "title": data.get("title", ""),
                            "tech": data.get("tech-detect", []) or data.get("tech", []),
                            "ip": data.get("ip", ""),
                            "host": data.get("host", ""),
                            "scheme": data.get("scheme", "http"),
                            "webserver": data.get("webserver", ""),
                            "content_type": data.get("content-type", data.get("content_type", "")),
                            "content_length": data.get("content-length", 0),
                            "cdn": data.get("cdn", False),
                            "cdn_name": data.get("cdn-name", ""),
                        })
                except json.JSONDecodeError:
                    continue
            return results
        except Exception as e:
            logger.error(f"Error running httpx: {e}")
            return [{"url": f"http://{d}", "host": d, "scheme": "http"} for d in domains]

    async def run_wafw00f(self, url: str) -> str:
        binary = resolve_binary("wafw00f")
        if not binary:
            logger.warning("wafw00f not found")
            return "none"
        try:
            proc = await asyncio.create_subprocess_exec(
                binary, url, "-a",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            output = stdout.decode(errors="ignore") if stdout else ""
            for line in output.splitlines():
                if "is behind" in line.lower():
                    return line.strip()
            return "none"
        except Exception as e:
            logger.error(f"Error running wafw00f: {e}")
            return "none"

    async def run_katana(self, url: str, depth: int = 2) -> List[str]:
        binary = resolve_binary("katana")
        if not binary:
            logger.warning("katana binary not found")
            return []
        try:
            cmd = [binary, "-u", url, "-d", str(depth), "-silent", "-jc", "-kf", "all", "-aff", "-c", "50", "-rl", "150"]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            output = stdout.decode(errors="ignore") if stdout else ""
            return [line.strip() for line in output.splitlines() if line.strip()]
        except Exception as e:
            logger.error(f"Error running katana: {e}")
            return []

    async def run_gau(self, domain: str) -> List[str]:
        binary = resolve_binary("gau")
        if not binary:
            logger.warning("gau binary not found")
            return []
        try:
            cmd = [binary, "--threads", "5", "--subs", domain]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            output = stdout.decode(errors="ignore") if stdout else ""
            return [line.strip() for line in output.splitlines() if line.strip()]
        except Exception as e:
            logger.error(f"Error running gau: {e}")
            return []

    def run_naabu(self, target: str) -> Dict[str, Any]:
        binary = resolve_binary("naabu")
        if not binary:
            logger.warning("naabu binary not found")
            return {"target": target, "open_ports": []}
        try:
            cmd = [
                binary,
                "-host", target,
                "-json",
                "-silent",
                "-top-ports", "1000"
            ]
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = proc.communicate(timeout=60)
            if proc.returncode != 0:
                logger.warning(f"Naabu returned non-zero code: {stderr}")
            
            open_ports = []
            seen = set()
            for line in stdout.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    port = entry.get("port")
                    host = entry.get("host")
                    if port and (host, port) not in seen:
                        seen.add((host, port))
                        open_ports.append({
                            "port": int(port),
                            "service": "",
                            "product": "",
                            "version": ""
                        })
                except json.JSONDecodeError:
                    continue
            return {
                "target": target,
                "open_ports": open_ports
            }
        except Exception as e:
            logger.error(f"Error running naabu: {e}")
            return {"target": target, "open_ports": []}

    async def run_nuclei(self, targets: List[str], tags: List[str] = None) -> List[Dict[str, Any]]:
        binary = resolve_binary("nuclei")
        if not binary:
            logger.warning("nuclei binary not found")
            return []
        if not targets:
            return []
        
        if tags is None:
            tags = []
        base_tags = {"generic", "misconfig", "exposure"}
        tags = list(set(tags).union(base_tags))

        try:
            with tempfile.NamedTemporaryFile(mode="w+", delete=False) as f:
                f.write("\n".join(targets))
                f_path = f.name
            
            tags_flag = f"{','.join(tags)}"
            cmd = [
                binary,
                "-l", f_path,
                "-silent",
                "-tags", tags_flag,
                "-severity", "critical,high,medium",
                "-jsonl",
                "-rl", "150",
                "-c", "50",
                "-bs", "25"
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()

            try:
                os.unlink(f_path)
            except Exception:
                pass

            output = stdout.decode(errors="ignore") if stdout else ""
            findings = []
            for line in output.splitlines():
                if not line.strip():
                    continue
                try:
                    findings.append(json.loads(line))
                except Exception:
                    continue
            return findings
        except Exception as e:
            logger.error(f"Error running nuclei: {e}")
            return []
