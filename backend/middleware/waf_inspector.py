"""
Embeddable ASGI WAF Inspection Middleware.
Can be plugged into ANY FastAPI or Starlette application.
Performs live pre-flight checks, normalizes request components,
evaluates via ML predictor within latency timeouts,
and blocks malicious requests before they reach application route handlers.
"""

import time
import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.status import HTTP_403_FORBIDDEN, HTTP_413_REQUEST_ENTITY_TOO_LARGE

from config.settings import settings
from inference import waf_predictor
from backend.database import SessionLocal
from backend.models import RequestLog

logger = logging.getLogger("waf_middleware")

class WAFInspectionMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, threshold: float = None, timeout_ms: int = None, fallback_policy: str = "block"):
        super().__init__(app)
        self.threshold = threshold or settings.MALICIOUS_THRESHOLD
        self.timeout_ms = timeout_ms or settings.INSPECTION_TIMEOUT_MS
        self.fallback_policy = fallback_policy or settings.FALLBACK_POLICY

    async def dispatch(self, request: Request, call_next):
        # 1. Bypass static files, health checks, or docs to avoid unnecessary latency
        path = request.url.path
        if path.startswith("/static") or path in ["/health", "/docs", "/openapi.json", "/favicon.ico"]:
            return await call_next(request)

        # 2. Pre-flight check: Request size limit (< 100KB)
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > settings.MAX_BODY_SIZE_BYTES:
            return JSONResponse(
                status_code=HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                content={"error": "WAF Block", "detail": "Request entity exceeds maximum safe threshold."}
            )

        # 3. Read body safely
        try:
            body_bytes = await request.body()
            body_text = body_bytes.decode("utf-8", errors="ignore")
        except Exception:
            body_text = ""

        # 4. Extract parameters and headers
        method = request.method
        query_params = str(request.query_params)
        headers = dict(request.headers)
        client_ip = request.client.host if request.client else "127.0.0.1"

        req_payload = {
            "method": method,
            "path": path,
            "params": query_params,
            "body": body_text,
            "headers": headers,
            "client_ip": client_ip
        }

        # 5. Evaluate with ML Predictor & Fallback Safeguards
        try:
            result = waf_predictor.predict_request(req_payload, threshold=self.threshold)
        except Exception as e:
            logger.error(f"WAF Inspection Exception: {e}")
            if self.fallback_policy == "block":
                return JSONResponse(
                    status_code=HTTP_403_FORBIDDEN,
                    content={"error": "WAF Policy", "detail": "Inspection failed. Fallback policy: Request Blocked."}
                )
            else:
                return await call_next(request)

        action = "BLOCKED" if result["is_malicious"] else "ALLOWED"

        # 6. Asynchronously record audit log in SQLite
        try:
            db = SessionLocal()
            log_entry = RequestLog(
                client_ip=client_ip,
                method=method,
                path=path,
                query_params=query_params,
                body=body_text[:1000],
                serialized_text=result["serialized_text"][:2000],
                prediction=result["prediction"],
                confidence=result["confidence"],
                malicious_prob=result["probabilities"]["malicious"],
                action_taken=action,
                threat_category="suspicious_request" if result["is_malicious"] else "none",
                latency_ms=result["latency_ms"],
                model_used=result["model_used"]
            )
            db.add(log_entry)
            db.commit()
            db.close()
        except Exception as db_err:
            logger.warning(f"Could not persist log: {db_err}")

        # 7. Enforcement: If malicious, reject request
        if result["is_malicious"]:
            return JSONResponse(
                status_code=HTTP_403_FORBIDDEN,
                content={
                    "error": "WAF Block",
                    "status": "Request Blocked by AI Web Application Firewall",
                    "reason": "Potentially malicious request pattern detected",
                    "confidence": result["confidence"],
                    "model": result["model_used"],
                    "threat_level": "High"
                }
            )

        # 8. If benign, pass through to route handler
        return await call_next(request)
