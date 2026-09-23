"""API key verification (hardened mode only)."""
import os
from fastapi import Request, HTTPException


def verify_api_key(request: Request) -> None:
    expected = os.environ.get("API_KEY")
    if not expected:
        raise HTTPException(status_code=500, detail="Server misconfigured")
    provided = request.headers.get("x-api-key")
    if provided != expected:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
