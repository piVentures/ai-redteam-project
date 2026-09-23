"""
Detector rules. No HTTP, no model. Consumes PredictionEvent dicts.

Each rule maps to one MITRE ATLAS technique. Cooldown prevents alert
flooding when a rule stays triggered (e.g., during a sustained extraction
attack).
"""
import time
from collections import defaultdict, deque

DETECTOR_VERSION = "v2-cooldown-2026-09-23"

WINDOW_SECONDS = 60
COOLDOWN_SECONDS = 60

_state = {
    "requests_by_ip": defaultdict(deque),
    "confidences_by_ip": defaultdict(deque),
    "last_fired": defaultdict(float),
}


def _should_fire(rule_name: str, ip: str, now: float) -> bool:
    """Return True if the cooldown has elapsed for this rule+IP."""
    key = f"{rule_name}:{ip}"
    if now - _state["last_fired"][key] < COOLDOWN_SECONDS:
        return False
    _state["last_fired"][key] = now
    return True


def check_extraction_volume(event: dict):
    """ATLAS: AML.T0024 — high query volume from one client in a short window."""
    ip = event["client_ip"]
    now = event["ts"]
    dq = _state["requests_by_ip"][ip]
    dq.append(now)
    while dq and now - dq[0] > WINDOW_SECONDS:
        dq.popleft()
    if len(dq) > 40:
        if not _should_fire("extraction_volume", ip, now):
            return None
        return {
            "rule": "extraction_volume",
            "atlas": "AML.T0024",
            "ip": ip,
            "count_last_60s": len(dq),
        }
    return None


def check_mia_confidence_sweep(event: dict):
    """ATLAS: AML.T0025 — repeated very-high-confidence queries from one client."""
    ip = event["client_ip"]
    now = event["ts"]
    dq = _state["confidences_by_ip"][ip]
    dq.append(event["confidence"])
    if len(dq) > 20:
        dq.popleft()
    if len(dq) >= 20 and sum(1 for c in dq if c > 0.95) / len(dq) > 0.8:
        if not _should_fire("mia_confidence_sweep", ip, now):
            return None
        return {"rule": "mia_confidence_sweep", "atlas": "AML.T0025", "ip": ip}
    return None


def check_adversarial_noise(event: dict):
    """ATLAS: AML.T0043 — adversarial input with unusually high pixel noise."""
    score = event.get("noise_score")
    if score is not None and score > 45:
        now = event["ts"]
        ip = event["client_ip"]
        if not _should_fire("adversarial_noise", ip, now):
            return None
        return {
            "rule": "adversarial_noise_input",
            "atlas": "AML.T0043",
            "ip": ip,
            "noise_score": score,
        }
    return None


RULES = [
    check_extraction_volume,
    check_mia_confidence_sweep,
    check_adversarial_noise,
]