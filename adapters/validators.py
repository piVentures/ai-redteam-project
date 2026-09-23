"""Input validation (hardened mode only)."""
import io
import numpy as np
from PIL import Image
from fastapi import HTTPException

MAX_IMAGE_BYTES = 2 * 1024 * 1024
MAX_IMAGE_DIMENSION = 512
NOISE_SCORE_THRESHOLD = 45
ALLOWED_FORMATS = {"PNG", "JPEG"}


def validate_image(raw: bytes) -> None:
    if len(raw) > MAX_IMAGE_BYTES:
        raise HTTPException(status_code=413, detail="Image too large")
    try:
        img = Image.open(io.BytesIO(raw))
        img.verify()
        img = Image.open(io.BytesIO(raw))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid image")
    if img.format not in ALLOWED_FORMATS:
        raise HTTPException(status_code=415, detail="Unsupported format")
    if img.size[0] > MAX_IMAGE_DIMENSION or img.size[1] > MAX_IMAGE_DIMENSION:
        raise HTTPException(status_code=400, detail="Image dimensions too large")
    arr = np.array(img.convert("L"), dtype=np.float32)
    noise = float(np.mean(np.abs(np.diff(arr, axis=0))))
    if noise > NOISE_SCORE_THRESHOLD:
        raise HTTPException(status_code=422, detail="Input flagged by anomaly heuristic")
