"""Orchestrates preprocessing, inference, and event logging."""
import torch
from domain.entities import Prediction
from services.preprocessing import preprocess, noise_score_from_bytes
from services.inference import predict, build_event


def serve_prediction(model, image_bytes: bytes, client_ip: str, log_event_fn) -> Prediction:
    """Preprocess -> predict -> emit event. Returns the Prediction."""
    noise = noise_score_from_bytes(image_bytes)
    tensor = preprocess(image_bytes)
    prediction = predict(model, tensor)
    event = build_event(client_ip, prediction, noise)
    log_event_fn(event)
    return prediction
