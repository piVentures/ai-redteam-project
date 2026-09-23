"""JSON event logging. The only place that writes prediction logs."""
import json
import os
from domain.entities import PredictionEvent


def log_event(log_dir: str, event: PredictionEvent) -> None:
    path = os.path.join(log_dir, "predictions.jsonl")
    try:
        with open(path, "a") as f:
            f.write(json.dumps(event.to_dict()) + "\n")
    except FileNotFoundError:
        pass
