"""Background detector. Tails the prediction log."""
import json
import os
import time
from pathlib import Path
from adapters.detector import RULES

LOG_PATH = Path(os.getenv("PREDICTIONS_LOG", "logs/predictions.jsonl"))
ALERT_PATH = Path(os.getenv("ALERTS_LOG", "results/alerts.jsonl"))


def tail_jsonl(path: Path):
    while not path.exists():
        print(f"[detector] waiting for {path} ...", flush=True)
        time.sleep(2)
    with path.open("r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def emit(alert: dict) -> None:
    alert["ts"] = time.time()
    print(f"[ALERT] {alert}", flush=True)
    ALERT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with ALERT_PATH.open("a") as f:
        f.write(json.dumps(alert) + "\n")


def main() -> None:
    print(f"[detector] watching {LOG_PATH} ...", flush=True)
    for event in tail_jsonl(LOG_PATH):
        for rule in RULES:
            try:
                alert = rule(event)
            except Exception as e:
                print(f"[detector] rule {rule.__name__} failed: {e}", flush=True)
                continue
            if alert:
                emit(alert)


if __name__ == "__main__":
    main()
