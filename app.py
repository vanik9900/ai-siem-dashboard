import asyncio
import os
import yaml
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

from core.database import init_db, save_alert
from core.rules_engine import check_heuristics
from services.ai_engine import analyze_with_ollama
from services.soar_engine import block_ip

with open("config/settings.yaml", "r") as f:
    config = yaml.safe_load(f)

app = FastAPI(title="Local AI SIEM System")
active_websockets: list[WebSocket] = []

@app.on_event("startup")
async def startup():
    init_db()
    asyncio.create_task(stream_logs())

async def stream_logs():
    log_file = config["log_sources"]["apache_access_log"]
    if not os.path.exists(log_file):
        open(log_file, 'a').close()

    with open(log_file, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                await asyncio.sleep(0.3)
                continue
            
            # 1. Rules pre-filter
            analysis = check_heuristics(line.strip())
            
            # 2. Local Ollama fallback if no rule hit
            if not analysis:
                analysis = analyze_with_ollama(
                    line.strip(), 
                    config["ollama"]["url"], 
                    config["ollama"]["model"]
                )

            # 3. SOAR Action
            action = "MONITORED"
            if analysis.get("is_threat") and analysis.get("confidence", 0) >= config["soar"]["auto_block_threshold"]:
                action = block_ip(analysis["ip"])

            analysis["action"] = action
            
            if analysis.get("is_threat"):
                save_alert(analysis["ip"], analysis["threat_type"], analysis["confidence"], analysis["explanation"], action, line.strip())
                for ws in active_websockets:
                    try:
                        await ws.send_json(analysis)
                    except Exception:
                        pass

@app.websocket("/ws/alerts")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    active_websockets.append(ws)
    try:
        while True:
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        active_websockets.remove(ws)

@app.get("/")
async def get_dashboard():
    with open("templates/index.html", "r") as f:
        return HTMLResponse(f.read())

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host=config["server"]["host"], port=config["server"]["port"], reload=True)