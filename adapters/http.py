"""
FastAPI app factory. The only place that knows about HTTP.
"""
import traceback
import torch
from fastapi import FastAPI, File, UploadFile, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from domain.constants import CLASSES
from usecases.serve_prediction import serve_prediction


def create_app(model, security_mode, log_dir, model_path):
    # Hardened mode: disable interactive docs and OpenAPI schema
    if security_mode == "hardened":
        docs_url = None
        redoc_url = None
        openapi_url = None
    else:
        docs_url = "/docs"
        redoc_url = "/redoc"
        openapi_url = "/openapi.json"

    app = FastAPI(
        title="Image Classifier API",
        version="1.0",
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
    )

    # CORS: restrictive in hardened mode, permissive in vulnerable mode
    if security_mode == "hardened":
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["http://localhost:3000"],
            allow_methods=["POST", "GET"],
            allow_headers=["x-api-key", "content-type"],
            allow_credentials=False,
        )
    else:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_methods=["*"],
            allow_headers=["*"],
            allow_credentials=False,
        )

    def _log(event):
        from adapters.logging import log_event
        log_event(log_dir, event)

    @app.get("/health")
    def health():
        return {"status": "ok", "mode": security_mode}

    @app.get("/model-info")
    def model_info():
        # [VULN-03] Reconnaissance endpoint. ATLAS: AML.T0007
        if security_mode == "vulnerable":
            return {
                "architecture": str(model),
                "classes": CLASSES,
                "torch_version": torch.__version__,
                "num_params": sum(p.numel() for p in model.parameters()),
                "model_path": model_path,
            }
        raise HTTPException(status_code=404, detail="Not found")

    @app.post("/predict")
    async def predict_endpoint(request: Request, file: UploadFile = File(...)):
        if security_mode == "hardened":
            from adapters.auth import verify_api_key
            from adapters.rate_limit import check_rate_limit
            verify_api_key(request)
            check_rate_limit(request)

        try:
            raw = await file.read()

            if security_mode == "hardened":
                from adapters.validators import validate_image
                validate_image(raw)

            client_ip = request.client.host if request.client else "unknown"
            prediction = serve_prediction(model, raw, client_ip, _log)

            if security_mode == "vulnerable":
                # [VULN-04] Full softmax exposure. ATLAS: AML.T0024
                return JSONResponse(content=prediction.to_dict_vulnerable())
            else:
                return JSONResponse(content=prediction.to_dict_hardened())

        except HTTPException:
            raise
        except Exception as e:
            if security_mode == "vulnerable":
                # [VULN-05] Verbose error. ATLAS: AML.T0007
                return JSONResponse(
                    status_code=500,
                    content={"error": str(e), "trace": traceback.format_exc()},
                )
            raise HTTPException(status_code=400, detail="Invalid input")

    return app
