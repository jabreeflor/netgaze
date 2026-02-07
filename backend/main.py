from __future__ import annotations

import asyncio
import time

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from capture import CaptureEngine

app = FastAPI(title="NetGaze", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = CaptureEngine()


@app.get("/api/health")
def health():
    return {"status": "ok", "timestamp": time.time()}


@app.get("/api/interfaces")
def list_interfaces():
    return {"interfaces": engine.get_interfaces()}


@app.get("/api/stats")
def get_stats():
    return engine.get_stats().model_dump()


@app.post("/api/capture/start")
def start_capture(interface: str = "en0"):
    engine.start(interface)
    return {"status": "started", "interface": interface}


@app.post("/api/capture/stop")
def stop_capture():
    engine.stop()
    return {"status": "stopped"}


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    last_stats_time = 0.0
    try:
        while True:
            batch = []
            for _ in range(50):
                packet = await engine.get_packet()
                if packet is None:
                    break
                batch.append(packet.model_dump())

            now = time.time()
            send_stats = now - last_stats_time >= 1.0

            if batch or send_stats:
                message = {}
                if batch:
                    message["packets"] = batch
                if send_stats:
                    message["stats"] = engine.get_stats().model_dump()
                    last_stats_time = now
                await ws.send_json(message)
            else:
                await asyncio.sleep(0.05)
    except WebSocketDisconnect:
        pass
    except Exception:
        try:
            await ws.close()
        except Exception:
            pass


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
