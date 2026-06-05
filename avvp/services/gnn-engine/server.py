from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import asyncio
from .model import VulnGNN, HAS_TORCH

app = FastAPI()

class GraphPayload(BaseModel):
    nodes: list
    edges: list

# instantiate a model (in real service, load checkpoint)
model = VulnGNN()

@app.post('/infer')
async def infer(payload: GraphPayload):
    # For now, call model.infer if available, otherwise return mock
    try:
        if HAS_TORCH:
            # complex path omitted in this scaffold; return placeholder
            return {"policy": [], "value": 0.0}
        else:
            policy, value = model.infer()
            return {"policy": policy, "value": value}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
