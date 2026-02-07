from __future__ import annotations

import asyncio
import csv
import io
import time

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

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


@app.on_event("startup")
async def on_startup():
    engine.set_loop(asyncio.get_event_loop())


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


@app.get("/api/top-talkers")
def get_top_talkers():
    stats = engine.get_stats()
    return {
        "top_talkers": stats.top_talkers,
        "top_destinations": stats.top_destinations,
        "top_domains": stats.top_domains,
        "connection_count": stats.connection_count,
    }


@app.get("/api/export")
def export_packets(format: str = "json"):
    packets = engine.get_captured_packets()

    if format == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "Timestamp", "Source IP", "Destination IP", "Protocol",
            "Source Port", "Destination Port", "Size", "Domain",
            "Summary", "Headers", "Payload",
        ])
        for pkt in packets:
            headers_str = "; ".join(f"{h.key}: {h.value}" for h in pkt.headers)
            writer.writerow([
                pkt.timestamp,
                pkt.src_ip,
                pkt.dst_ip,
                pkt.protocol,
                pkt.src_port or "",
                pkt.dst_port or "",
                pkt.size,
                pkt.domain or "",
                pkt.summary,
                headers_str,
                pkt.payload_text[:500] if pkt.payload_text else "",
            ])
        buf.seek(0)
        return StreamingResponse(
            buf,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=netgaze_capture.csv"},
        )

    # Default: JSON
    data = [pkt.model_dump() for pkt in packets]
    return StreamingResponse(
        io.BytesIO(
            __import__("json").dumps(data, indent=2).encode()
        ),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=netgaze_capture.json"},
    )


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
