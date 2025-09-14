import asyncio
import logging
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from typing import Optional
from .parser import parse_fast_log
from .analysis import run_analysis
from .models import AnalysisResult
import json

LOG_PATH = Path('logs/fast.log')
REFRESH_SECONDS = 10
MAX_PARSE_LINES = 20000  # tail lines to parse for performance; adjust as needed

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI(title="EMR Security Network Analyzer (Static Mode)")
app.mount('/static', StaticFiles(directory=Path(__file__).parent / 'static'), name='static')

latest_payload: str = json.dumps({"status":"not analyzed"})

def perform_analysis() -> None:
    global latest_payload
    if not LOG_PATH.exists():
        latest_payload = json.dumps({"error":"Log file not found","path": str(LOG_PATH)})
        return
    logger.info("Parsing log file once: %s", LOG_PATH)
    events = list(parse_fast_log(str(LOG_PATH), max_lines=None))  # parse entire file
    logger.info("Parsed %d events", len(events))
    result: AnalysisResult = run_analysis(events)
    latest_payload = result.model_dump_json()

@app.on_event('startup')
async def startup_event():
    perform_analysis()

@app.get('/', response_class=HTMLResponse)
async def index():
    with open(Path(__file__).parent / 'templates' / 'index.html', 'r', encoding='utf-8') as f:
        return f.read()

@app.get('/api/analysis')
async def get_analysis():
    return json.loads(latest_payload)

@app.post('/api/reload')
async def reload_analysis():
    try:
        perform_analysis()
        return {"status":"reloaded"}
    except Exception as e:
        logger.exception("Reload failed")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == '__main__':
    import uvicorn
    uvicorn.run('app.main:app', host='0.0.0.0', port=8000, reload=True)
