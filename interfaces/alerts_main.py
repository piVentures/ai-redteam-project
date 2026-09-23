"""Read-only alerts API."""
import json
from pathlib import Path
from fastapi import FastAPI

app = FastAPI(title="Detector Alerts", version="1.0")
ALERT_PATH = Path("results/alerts.jsonl")


@app.get("/alerts")
def alerts():
    if not ALERT_PATH.exists():
        return []
    with ALERT_PATH.open() as f:
        lines = f.readlines()[-50:]
    return [json.loads(l) for l in lines if l.strip()]
