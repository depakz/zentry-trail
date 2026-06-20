import asyncio
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any, Tuple
import logging
from enum import Enum

# Configure structured logging
logger = logging.getLogger("pipeline_context")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

class VulnerabilitySeverity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

@dataclass
class FindingModel:
    """Unverified telemetry from initial scanners"""
    target_url: str
    vulnerability_type: str
    severity: VulnerabilitySeverity
    scanner_source: str
    description: str
    remediation: str
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    raw_request: Optional[str] = None
    raw_response: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

@dataclass
class ValidatedExposureModel:
    """Confirmed vulnerability with dynamic verification proof"""
    finding: FindingModel
    verification_proof: str
    validation_timestamp: float = field(default_factory=time.time)
    false_positive: bool = False

class PipelineContext:
    """Thread-safe asynchronous pipeline state machine"""
    def __init__(self, root_target_domain: str, time_budget_seconds: int = 900):
        self.root_target_domain = root_target_domain
        self.start_time = time.monotonic()
        self.time_budget = time_budget_seconds
        
        # Inter-stage communication queues
        self.recon_to_probing_queue = asyncio.Queue()
        self.probing_to_scan_queue = asyncio.Queue()
        self.scan_to_validation_queue = asyncio.Queue()
        
        # Thread-safe data stores with locks
        self._lock = threading.Lock()
        self.subdomains: Set[str] = set()
        self.tech_stack: Dict[str, List[str]] = {}  # target_url -> technologies
        self.findings: List[FindingModel] = []
        self.validated_exposures: List[ValidatedExposureModel] = []
        self.failed_tasks: List[Tuple[str, Exception]] = []
        
        # Pipeline status tracking
        self.recon_completed = asyncio.Event()
        self.probing_completed = asyncio.Event()
        self.scanning_completed = asyncio.Event()
        self.validation_completed = asyncio.Event()

    def get_remaining_seconds(self) -> float:
        """Calculate remaining execution budget"""
        elapsed = time.monotonic() - self.start_time
        return max(0.0, self.time_budget - elapsed)

    def add_subdomain(self, subdomain: str) -> None:
        """Thread-safe subdomain addition"""
        with self._lock:
            self.subdomains.add(subdomain)

    def add_tech_stack(self, target_url: str, technologies: List[str]) -> None:
        """Thread-safe technology stack update"""
        with self._lock:
            self.tech_stack[target_url] = technologies

    def add_finding(self, finding: FindingModel) -> None:
        """Thread-safe finding addition"""
        with self._lock:
            self.findings.append(finding)

