import asyncio
import json
import logging
from modules.pipeline.brain.dag_engine_enhanced import DAGBrain
from modules.pipeline.brain.graph_builder import DAGNode
from modules.recon.tools.wrappers import (
    NmapWrapper,
    NiktoWrapper,
    GobusterWrapper,
    SqlmapWrapper,
    HydraWrapper,
    WhoisWrapper
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("I-Intern-CyberTool")

async def main():
    logger.info("Initializing I-Intern-CyberTool")
    
    # Initialize the DAG-driven state machine
    brain = DAGBrain()
    state = {
        "target": "example.com",
        "findings": [],
        "context": {}
    }
    
    logger.info("Building DAG graph from state...")
    graph = brain.build_graph(state)
    
    # Register tools from modules/recon/tools as runnable nodes
    wrappers = [
        NmapWrapper(),
        NiktoWrapper(),
        GobusterWrapper(),
        SqlmapWrapper(),
        HydraWrapper(),
        WhoisWrapper()
    ]
    
    logger.info("Registering security tools as runnable DAG nodes...")
    for wrapper in wrappers:
        tool_name = wrapper.__class__.__name__
        
        # Create a DAG node representing the tool
        node = DAGNode(
            id=f"tool_{tool_name.lower()}",
            kind="tool",
            label=tool_name,
            data={
                "tool": wrapper,
                "is_runnable": True,
                "state": "ready"
            }
        )
        
        graph.add_node(node)
        logger.info(f"Registered tool node: {tool_name}")
        
    logger.info("I-Intern-CyberTool initialization complete. Graph contains %d nodes.", len(graph.nodes))

if __name__ == "__main__":
    asyncio.run(main())
