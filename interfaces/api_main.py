"""Entry point for uvicorn. Composes adapters, use cases, services, domain."""
import os
from adapters.model_loader import load_model
from adapters.http import create_app

SECURITY_MODE = os.getenv("SECURITY_MODE", "vulnerable")
MODEL_PATH = os.getenv("MODEL_PATH", "model/artifacts/baseline.pt")
LOG_DIR = os.getenv("LOG_DIR", "logs")

model = load_model(MODEL_PATH, SECURITY_MODE)
app = create_app(model, SECURITY_MODE, LOG_DIR, MODEL_PATH)
