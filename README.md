# Security Network Analyzer 

A lightweight demo web application that ingests a completed Suricata `fast.log` security alert file and renders a network + alert graph with simple anomaly scoring. 

## Features

- Parses  Suricata `fast.log` at start
- Builds force-directed network graph 
- Z-score based anomaly detection on alert volume
- Recent events panel with priorities
- D3.js frontend
- Flask Backend 

## Run
```powershell
python -m uvicorn app.main:app --reload --port 8000
```

## Graph
- Host nodes: unique IPs
- Alert nodes: signature strings aggregated
- Edges: host->alert and host->host (communication + alert context)

## Security notice
Dormant virus in Suricata logs, do not download or run 

## License
MIT (add a LICENSE file if distributing publicly).
