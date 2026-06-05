from fastapi import FastAPI
import redis.asyncio as redis
from typing import Dict
import uvicorn

app = FastAPI()
_r = redis.from_url("redis://127.0.0.1:6379/0")

@app.get('/hit/{token}')
async def hit(token: str):
    key = f"oob:{token}"
    await _r.lpush(key, "http_hit")
    await _r.expire(key, 7*24*3600)
    return {"token": token, "hit": True}

# DNS server placeholder: in production use dnslib to listen and record queries

def start_dns_server():
    # Left as a placeholder for local DNS service that records queries into Redis
    return None

if __name__ == '__main__':
    uvicorn.run(app, host='0.0.0.0', port=8080)
