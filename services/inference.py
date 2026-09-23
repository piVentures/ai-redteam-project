"""Inference service. Domain-only dependencies."""
import time
import math
import torch

from domain.constants import CLASSES
from domain.entities import Prediction, PredictionEvent


def predict(model, tensor: torch.Tensor) -> Prediction:
    with torch.no_grad():
        logits = model(tensor)
        probs = torch.softmax(logits, dim=1).squeeze(0)
    return Prediction(
        class_name=CLASSES[int(probs.argmax())],
        confidence=float(probs.max()),
        probabilities={c: float(p) for c, p in zip(CLASSES, probs)},
    )


def build_event(client_ip: str, prediction: Prediction, noise_score: float) -> PredictionEvent:
    probs = prediction.probabilities or {}
    entropy = -sum(p * math.log(p + 1e-12) for p in probs.values()) if probs else 0.0
    return PredictionEvent(
        ts=time.time(),
        client_ip=client_ip,
        top_class=prediction.class_name,
        confidence=prediction.confidence,
        entropy=entropy,
        noise_score=noise_score,
    )
