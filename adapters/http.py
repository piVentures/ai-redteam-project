"""
FastAPI app factory. The only place that knows about HTTP.
"""
import traceback
import torch
from fastapi import FastAPI, File, UploadFile, Request, HTTPException
from fastapi.responses import JSONResponse

from domain.constants import CLASSES
from usecases.serve_prediction import serve_prediction


def create_app(model, security_mode: str, log_dir: str, model_path: str) -> FastAPI:
    app = FastAPI(title="Image Classifier API", version="1.0")

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
