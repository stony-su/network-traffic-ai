# EMR Security Network Analyzer (Static Mode)

A lightweight demo web application that ingests a completed Suricata `fast.log` security alert file (e.g., from an Electronic Medical Record network segment) and renders a network + alert graph with simple anomaly scoring. This version performs a **single parse at startup** (no continuous tailing) and offers a manual reload endpoint/button.

## Features

- Parses full Suricata `fast.log` once at startup
- Builds force-directed network graph (hosts + alert signature nodes)
- Manual reload button (POST /api/reload) to re-run analysis if you replace the log
- Simple z-score based anomaly detection on per-source alert volume
- Recent events panel with priority and signature
- Pure FastAPI + D3.js frontend (no build step)
- No virtual environment requirement (install system-wide if desired)

## Install Dependencies (No venv)
Ensure you have Python 3.10+.

```powershell
pip install -r requirements.txt
```

If you have both `pip` and `pip3`, pick the one matching your target Python.

## Run
```powershell
python -m uvicorn app.main:app --reload --port 8000
```
Then open: http://localhost:8000

## How It Works
1. On startup the entire `logs/fast.log` is parsed (no line limit).
2. Events from the last 24h build the graph and anomaly list.
3. Frontend fetches `/api/analysis` once and renders the graph.
4. If you want to analyze a different static log, overwrite the file and click Reload (or POST to `/api/reload`).

## Data Model
- Host nodes: unique IPs
- Alert nodes: signature strings aggregated
- Edges: host->alert and host->host (communication + alert context)
- Anomalies: High per-source alert count (z-score > 2.5 and > mean+5)

## Customization Ideas
- Add role/asset enrichment (map IP -> device type / EMR component)
- Add authentication & RBAC
- Persist parsed events in a database (e.g. SQLite or PostgreSQL)
- Implement incremental tail parsing for huge logs
- Add ML model (e.g., IsolationForest) for multi-feature anomaly detection
- Integrate PCAP enrichment / GeoIP (mind PHI governance)

## Security & PHI Note
This demo does not handle PHI and should not be used directly in production clinical environments without rigorous security, auditing, and compliance hardening.

## Limitations
- Regex is simplified; multi-line wrapped alerts may be skipped.
- Full file parsed every reload (optimize by tail limiting for huge logs if desired).
- Basic anomaly heuristic only.

## License
MIT (add a LICENSE file if distributing publicly).
