"""Autonomous chain synthesis via artifact types and semantic reasoning."""

import re
from dataclasses import dataclass
from typing import Dict, List, Optional


# Define all output types
ALL_OUTPUT_TYPES = {
    "CREDENTIAL:AWS_KEY", "CREDENTIAL:GCP_SA_TOKEN", "CREDENTIAL:API_KEY",
    "CREDENTIAL:SESSION_TOKEN", "CREDENTIAL:JWT_SIGNED", "CREDENTIAL:DB_CONNECTION_STRING",
    "ENDPOINT:INTERNAL_URL", "ENDPOINT:INTERNAL_IP", "ENDPOINT:KUBERNETES_API",
    "ENDPOINT:CLOUD_METADATA_URL", "ENDPOINT:DATABASE_HOST", "ENDPOINT:SERVICE_NAME",
    "IDENTITY:USER_ID", "IDENTITY:ORG_ID", "IDENTITY:ROLE_NAME",
}

# Define what attacks need what inputs
ATTACK_REQUIRES: Dict[str, List[str]] = {
    "ssrf_internal": ["ENDPOINT:INTERNAL_URL", "ENDPOINT:INTERNAL_IP"],
    "cloud_credential_abuse": ["CREDENTIAL:AWS_KEY", "CREDENTIAL:GCP_SA_TOKEN"],
    "file_read": ["ENDPOINT:INTERNAL_URL"],
    "horizontal_idor": ["IDENTITY:USER_ID", "IDENTITY:ORG_ID"],
    "privilege_escalation": ["IDENTITY:ROLE_NAME"],
    "k8s_api_attack": ["ENDPOINT:KUBERNETES_API"],
    "db_direct_access": ["CREDENTIAL:DB_CONNECTION_STRING", "ENDPOINT:DATABASE_HOST"],
}


@dataclass
class ChainCandidate:
    """Candidate for chain exploitation."""
    source_finding_id: str
    attack_type: str
    artifact: Dict
    confidence: float
    source: str


def extract_artifacts_from_response(response_text: str) -> List[Dict]:
    """Extract typed artifacts from response text."""
    artifacts = []

    # AWS key pattern
    if re.search(r'AKIA[0-9A-Z]{16}', response_text):
        artifacts.append({"type": "CREDENTIAL:AWS_KEY", "value": "aws_key_found"})

    # Internal IPs
    if re.search(r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}', response_text):
        artifacts.append({"type": "ENDPOINT:INTERNAL_IP", "value": "internal_ip_found"})
    if re.search(r'172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}', response_text):
        artifacts.append({"type": "ENDPOINT:INTERNAL_IP", "value": "internal_ip_found"})

    # JWT - match full JWT (3 parts) or partial (just header eyJ...)
    if re.search(r'eyJ[A-Za-z0-9_-]{3,}', response_text):
        artifacts.append({"type": "CREDENTIAL:JWT_SIGNED", "value": "jwt_found"})

    # DB connection string
    if re.search(r'(mongodb|mysql|postgres)://', response_text):
        artifacts.append({"type": "CREDENTIAL:DB_CONNECTION_STRING", "value": "db_conn_found"})

    # User ID patterns
    if re.search(r'(user_id|uid|userid).*?(\d+)', response_text, re.IGNORECASE):
        artifacts.append({"type": "IDENTITY:USER_ID", "value": "user_id_found"})

    return artifacts


class TypeCompatibilityResolver:
    """Resolve which attacks can use discovered artifacts."""

    def resolve(self, artifacts: List[Dict]) -> List[ChainCandidate]:
        """Find attacks compatible with artifacts."""
        candidates = []

        for artifact in artifacts:
            artifact_type = artifact.get("type", "")
            for attack_type, required_types in ATTACK_REQUIRES.items():
                if artifact_type in required_types or any(artifact_type.split(":")[0] in rt for rt in required_types):
                    candidates.append(ChainCandidate(
                        source_finding_id="source",
                        attack_type=attack_type,
                        artifact=artifact,
                        confidence=0.9,
                        source="type_resolver",
                    ))

        return candidates


class EmbeddingReasoner:
    """Semantic reasoning for chain discovery when types don't match."""

    def find_candidates(self, artifact: Dict, threshold: float = 0.60) -> List[ChainCandidate]:
        """Find attacks semantically related to artifact."""
        artifact_type = artifact.get("type", "")

        # Simple string-based matching
        candidates = []
        for attack_type in ATTACK_REQUIRES.keys():
            if artifact_type.lower() in attack_type.lower() or attack_type.lower() in artifact_type.lower():
                candidates.append(ChainCandidate(
                    source_finding_id="source",
                    attack_type=attack_type,
                    artifact=artifact,
                    confidence=0.65,
                    source="embedding_reasoner",
                ))

        return candidates


class ExploitStatePropagator:
    """Propagate exploitable state via chain candidates."""

    def __init__(self):
        self.type_resolver = TypeCompatibilityResolver()
        self.embedding_reasoner = EmbeddingReasoner()

    def on_finding_confirmed(self, finding_id: str, response_text: str) -> List[ChainCandidate]:
        """Generate chain candidates from confirmed finding."""
        artifacts = extract_artifacts_from_response(response_text)
        candidates = []

        for artifact in artifacts:
            candidates.extend(self.type_resolver.resolve([artifact]))
            candidates.extend(self.embedding_reasoner.find_candidates(artifact))

        return candidates
