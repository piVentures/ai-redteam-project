"""In-memory token-bucket rate limiter (hardened mode only)."""
import time
from collections import defaultdict
from fastapi import Request, HTTPException

WINDOW_SECONDS = 60
MAX_REQUESTS = 20
_buckets: dict[str, list[float]] = defaultdict(list)


def check_rate_limit(request: Request) -> None:
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    _buckets[ip] = [t for t in _buckets[ip] if now - t < WINDOW_SECONDS]
    if len(_buckets[ip]) >= MAX_REQUESTS:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    _buckets[ip].append(now)
