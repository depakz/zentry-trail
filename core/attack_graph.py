"""Attack Graph Featurization."""

import numpy as np
from typing import Dict, List, Optional

class AttackGraphNode:
    """Node in attack graph with 32-dimensional featurization."""
    def __init__(
        self,
        node_id: str,
        url: str,
        priority_score: float = 0.0,
        confirmed_findings: Optional[List[str]] = None,
        method: str = "GET",
        param_types: Optional[Dict[str, float]] = None,
        tech_stack: Optional[List[str]] = None,
        auth_state: str = "unauthenticated",
        status_code: int = 200,
        latency_ms: float = 0.0,
        tags: Optional[List[str]] = None,
        chain_depth: int = 0
    ):
        self.node_id = node_id
        self.url = url
        self.priority_score = priority_score
        self.confirmed_findings = confirmed_findings or []
        self.method = method.upper()
        self.param_types = param_types or {"int": 0.0, "string": 0.0, "uuid": 0.0, "url": 0.0}
        self.tech_stack = tech_stack or []
        self.auth_state = auth_state.lower()
        self.status_code = status_code
        self.latency_ms = latency_ms
        self.tags = tags or []
        self.chain_depth = chain_depth

    def featurize(self) -> np.ndarray:
        """Output a 32-dimensional float vector capturing node state."""
        features = np.zeros(32, dtype=np.float32)
        
        # [0:4] HTTP method
        if self.method == "GET": features[0] = 1.0
        elif self.method == "POST": features[1] = 1.0
        elif self.method == "PUT": features[2] = 1.0
        elif self.method == "DELETE": features[3] = 1.0
        
        # [4:8] Parameter data type distributions
        features[4] = float(self.param_types.get("int", 0.0))
        features[5] = float(self.param_types.get("string", 0.0))
        features[6] = float(self.param_types.get("uuid", 0.0))
        features[7] = float(self.param_types.get("url", 0.0))
        
        # [8:12] Technology stack classification
        tech_str = " ".join(self.tech_stack).lower()
        if "php" in tech_str or "wordpress" in tech_str: features[8] = 1.0
        if "node" in tech_str or "react" in tech_str: features[9] = 1.0
        if "python" in tech_str or "django" in tech_str: features[10] = 1.0
        if "java" in tech_str or "spring" in tech_str: features[11] = 1.0
        
        # [12:16] Authentication state one-hot
        if self.auth_state == "unauthenticated": features[12] = 1.0
        elif self.auth_state == "authenticated": features[13] = 1.0
        elif self.auth_state == "admin": features[14] = 1.0
        else: features[15] = 1.0
        
        # [16:20] Response status code bucket
        if 200 <= self.status_code < 300: features[16] = 1.0
        elif 300 <= self.status_code < 400: features[17] = 1.0
        elif 400 <= self.status_code < 500: features[18] = 1.0
        elif self.status_code >= 500: features[19] = 1.0
        
        # [20:24] Latency quantile metrics
        if self.latency_ms < 100: features[20] = 1.0
        elif self.latency_ms < 500: features[21] = 1.0
        elif self.latency_ms < 2000: features[22] = 1.0
        else: features[23] = 1.0
        
        # [24:28] Priority target flag checks
        tags_str = " ".join(self.tags).lower()
        url_lower = self.url.lower()
        if "admin_path" in tags_str or "admin" in url_lower: features[24] = 1.0
        if "file_upload" in tags_str or "upload" in url_lower: features[25] = 1.0
        if "auth_bypass" in tags_str or "login" in url_lower: features[26] = 1.0
        if "api" in tags_str or "api" in url_lower: features[27] = 1.0
        
        # [28:32] Internal discovery indicators
        features[28] = float(self.priority_score)
        features[29] = float(len(self.confirmed_findings))
        features[30] = float(self.chain_depth)
        
        return features


class AttackGraph:
    def __init__(self):
        self.nodes: Dict[str, AttackGraphNode] = {}
        self.adjacency: Dict[str, List[str]] = {}
        
    def add_node(self, node: AttackGraphNode) -> None:
        self.nodes[node.node_id] = node
        if node.node_id not in self.adjacency:
            self.adjacency[node.node_id] = []
            
    def add_edge(self, source_id: str, target_id: str) -> None:
        if source_id in self.nodes and target_id in self.nodes:
            self.adjacency[source_id].append(target_id)
            
    def export_adjacency_matrix(self) -> np.ndarray:
        """Export cross-node adjacency matrix."""
        node_ids = list(self.nodes.keys())
        n = len(node_ids)
        matrix = np.zeros((n, n), dtype=np.float32)
        id_to_idx = {nid: i for i, nid in enumerate(node_ids)}
        for source_id, targets in self.adjacency.items():
            if source_id in id_to_idx:
                src_idx = id_to_idx[source_id]
                for target_id in targets:
                    if target_id in id_to_idx:
                        tgt_idx = id_to_idx[target_id]
                        matrix[src_idx, tgt_idx] = 1.0
        return matrix