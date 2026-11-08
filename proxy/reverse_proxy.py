"""
Standalone AI WAF Reverse Proxy Gateway.
Intercepts live network traffic, inspects via DistilBERT WAF engine,
and proxies benign requests to the upstream server.
Blocks malicious requests with 403 Forbidden.
"""

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.status import HTTP_403_FORBIDDEN, HTTP_413_REQUEST_ENTITY_TOO_LARGE, HTTP_502_BAD_GATEWAY

from config.settings import settings
from inference import waf_predictor
from backend.database import SessionLocal, Base, engine
from backend.models import RequestLog

Base.metadata.create_all(bind=engine)

proxy_app = FastAPI(title="WAF Reverse Proxy Gateway")

UPSTREAM_URL = f"http://{settings.UPSTREAM_HOST}:{settings.UPSTREAM_PORT}"

@proxy_app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def inspect_and_proxy(request: Request, full_path: str):
    # 1. Size guardrail (< 100KB)
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > settings.MAX_BODY_SIZE_BYTES:
        return JSONResponse(
            status_code=HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={"error": "WAF Block", "message": "Request payload exceeds size limit."}
        )

    # 2. Extract components
    body_bytes = await request.body()
    body_text = body_bytes.decode("utf-8", errors="ignore")
    query_params = str(request.query_params)
    client_ip = request.client.host if request.client else "127.0.0.1"

    req_dict = {
        "method": request.method,
        "path": "/" + full_path,
        "params": query_params,
        "body": body_text,
        "headers": dict(request.headers),
        "client_ip": client_ip
    }

    # 3. Inspect with WAF ML engine
    result = waf_predictor.predict_request(req_dict)
    action = "BLOCKED" if result["is_malicious"] else "ALLOWED"

    # 4. Asynchronous logging
    try:
        db = SessionLocal()
        log_entry = RequestLog(
            client_ip=client_ip,
            method=request.method,
            path="/" + full_path,
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
    except Exception as e:
        print(f"[WAF Proxy] Log error: {e}")

    # 5. Block malicious request
    if result["is_malicious"]:
        return JSONResponse(
            status_code=HTTP_403_FORBIDDEN,
            content={
                "error": "Forbidden by AI WAF",
                "status": "BLOCKED",
                "classification": "MALICIOUS",
                "confidence": result["confidence"],
                "model": result["model_used"],
                "detail": "Request was classified as potentially malicious by Transformer WAF."
            }
        )

    # 6. Proxy benign request to upstream
    target_url = f"{UPSTREAM_URL}/{full_path}"
    if query_params:
        target_url += f"?{query_params}"

    headers = dict(request.headers)
    headers.pop("host", None)

    async with httpx.AsyncClient() as client:
        try:
            upstream_resp = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body_bytes,
                timeout=10.0
            )
            return Response(
                content=upstream_resp.content,
                status_code=upstream_resp.status_code,
                headers=dict(upstream_resp.headers)
            )
        except httpx.RequestError as exc:
            return JSONResponse(
                status_code=HTTP_502_BAD_GATEWAY,
                content={"error": "Bad Gateway", "detail": f"Could not connect to upstream target: {exc}"}
            )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(proxy_app, host="127.0.0.1", port=8000)
