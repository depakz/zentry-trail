import math
import random
import asyncio
from typing import Any, List

class MCTSNode:
    def __init__(self, state: Any, parent=None):
        self.state = state
        self.parent = parent
        self.children = []
        self.visits = 0
        self.value = 0.0
        self.untried_actions = list(range(3))  # placeholder actions

class MCTSPlanner:
    def __init__(self, gnn_client=None, c_puct: float = 1.5, simulations: int = 50):
        self.gnn = gnn_client
        self.c_puct = c_puct
        self.simulations = simulations

    async def plan(self, graph) -> List[Any]:
        root = MCTSNode(state=graph)
        # get policy,value from gnn
        if self.gnn:
            policy, value = await self.gnn.infer(graph)
        else:
            policy, value = [1/3,1/3,1/3], 0.0

        for _ in range(self.simulations):
            node = self._select(root)
            if node.untried_actions:
                node = self._expand(node)
            reward = await self._simulate(node)
            self._backpropagate(node, reward)

        # return top actions from root
        actions = sorted([(child.value / (child.visits or 1), idx) for idx, child in enumerate(root.children)], reverse=True)
        return [a for _, a in actions]

    def _select(self, node: MCTSNode) -> MCTSNode:
        while node.children:
            best = max(node.children, key=lambda n: n.value / (n.visits + 1e-6) + self.c_puct * math.sqrt(math.log(max(1, node.visits + 1)) / (n.visits + 1e-6)))
            node = best
        return node

    def _expand(self, node: MCTSNode) -> MCTSNode:
        action = node.untried_actions.pop()
        child = MCTSNode(state=(node.state, action), parent=node)
        node.children.append(child)
        return child

    async def _simulate(self, node: MCTSNode) -> float:
        # Random rollout
        await asyncio.sleep(0)  # yield
        return random.random()

    def _backpropagate(self, node: MCTSNode, reward: float):
        while node:
            node.visits += 1
            node.value += reward
            node = node.parent
