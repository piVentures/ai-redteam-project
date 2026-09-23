"""Detector rules. No HTTP, no model. Consumes PredictionEvent dicts."""
from collections import defaultdict, deque


WINDOW_SECONDS = 60
_state = {
    "requests_by_ip": defaultdict(deque),
    "confidences_by_ip": defaultdict(deque),
}


def check_extraction_volume(event: dict):
    ip = event["client_ip"]
    now = event["ts"]
    dq = _state["requests_by_ip"][ip]
    dq.append(now)
    while dq and now - dq[0] > WINDOW_SECONDS:
        dq.popleft()
    if len(dq) > 40:
        return {"rule": "extraction_volume", "atlas": "AML.T0024",
                "ip": ip, "count_last_60s": len(dq)}
    return None


def check_mia_confidence_sweep(event: dict):
    ip = event["client_ip"]
    dq = _state["confidences_by_ip"][ip]
    dq.append(event["confidence"])
    if len(dq) > 20:
        dq.popleft()
    if len(dq) >= 20 and sum(1 for c in dq if c > 0.95) / len(dq) > 0.8:
        return {"rule": "mia_confidence_sweep", "atlas": "AML.T0025", "ip": ip}
    return None


def check_adversarial_noise(event: dict):
    score = event.get("noise_score")
    if score is not None and score > 45:
        return {"rule": "adversarial_noise_input", "atlas": "AML.T0043",
                "ip": event["client_ip"], "noise_score": score}
    return None


RULES = [check_extraction_volume, check_mia_confidence_sweep, check_adversarial_noise]
