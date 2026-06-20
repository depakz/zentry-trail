"""Differential Response Analyzer for tracking anomaly indicators."""

import requests
from dataclasses import dataclass
from typing import List


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
        body_delta = abs(probe_len - baseline_len)

        probe_text = (probe_response.text or "").lower()
        reflection = any(marker in probe_text for marker in ["error", "exception", "syntax", "payload"])

        error_class = "none"
        if "error" in probe_text:
            error_class = "error"
        elif any(s in probe_text for s in ["timeout", "timed out", "deadlock"]):
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