import asyncio
from avvp.services.mcts_planner.mcts import MCTSPlanner

class MockGNNClient:
    async def infer(self, graph):
        return [0.5, 0.3, 0.2], 0.1

def test_mcts_runs():
    planner = MCTSPlanner(gnn_client=MockGNNClient(), simulations=5)
    actions = asyncio.run(planner.plan({'nodes':10}))
    assert isinstance(actions, list)


if __name__ == '__main__':
    asyncio.run(planner.plan({'nodes':10}))
