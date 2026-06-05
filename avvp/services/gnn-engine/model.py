try:
    import torch
    import torch.nn as nn
    from torch.nn import Linear
    HAS_TORCH = True
    try:
        from torch_geometric.nn import GATConv, global_mean_pool
        HAS_PYG = True
    except Exception:
        HAS_PYG = False
except Exception:
    HAS_TORCH = False
    HAS_PYG = False
    # Provide lightweight fallbacks
    class nn: pass

from typing import Tuple


if HAS_TORCH and HAS_PYG:
    class VulnGNN(nn.Module):
        def __init__(self, node_features=64, hidden=128, output=32, num_vuln_classes=10):
            super().__init__()
            self.conv1 = GATConv(node_features, hidden, heads=4)
            self.conv2 = GATConv(hidden * 4, hidden, heads=4)
            self.conv3 = GATConv(hidden * 4, output, heads=1)
            self.policy_head = Linear(output, num_vuln_classes)
            self.value_head = Linear(output, 1)

        def forward(self, x, edge_index, batch=None) -> Tuple[object, object]:
            h = self.conv1(x, edge_index)
            h = torch.relu(h)
            h = self.conv2(h, edge_index)
            h = torch.relu(h)
            h = self.conv3(h, edge_index)
            # global pool
            g = global_mean_pool(h, batch) if batch is not None else h.mean(dim=0, keepdim=True)
            policy = self.policy_head(g)
            value = self.value_head(g)
            return policy, value
else:
    # Fallback simple MLP
    class VulnGNN:
        def __init__(self, node_features=64, hidden=128, output=32, num_vuln_classes=10):
            self.node_features = node_features
            self.hidden = hidden
            self.output = output
            self.num_vuln_classes = num_vuln_classes

        def infer(self, x=None, edge_index=None, batch=None):
            # return uniform policy and zero value
            policy = [1.0 / self.num_vuln_classes] * self.num_vuln_classes
            value = 0.0
            return policy, value
