"""
FastAPI Application Entry Point for Transformer-Based WAF.
Includes CORS, static file mounting, database initialization,
and inspection middleware with safeguard fallbacks.
"""

import os
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

from config.settings import settings, BASE_DIR
from backend.database import engine, Base
from backend.routes import predict, logs, feedback

# Initialize database tables immediately
Base.metadata.create_all(bind=engine)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure database tables exist
    Base.metadata.create_all(bind=engine)
    yield

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Transformer-Based AI Web Application Firewall (WAF) API Engine",
    lifespan=lifespan
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Guardrail Middleware: Enforces Request-Size Limits & Safeguards
@app.middleware("http")
async def security_guardrail_middleware(request: Request, call_next):
    # Enforce request body size limit (< 100KB) to prevent DoS attacks on NLP tokenizer
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > settings.MAX_BODY_SIZE_BYTES:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={
                "error": "Payload Too Large",
                "message": f"Request size exceeds WAF safeguard limit ({settings.MAX_BODY_SIZE_BYTES} bytes)."
            }
        )
    return await call_next(request)

# Register API Endpoints
app.include_router(predict.router, prefix=settings.API_V1_STR)
app.include_router(logs.router, prefix=settings.API_V1_STR)
app.include_router(feedback.router, prefix=settings.API_V1_STR)

# Also expose at root /predict, /analyze, /logs, /stats, /feedback for direct usability
app.include_router(predict.router)
app.include_router(logs.router)
app.include_router(feedback.router)

# Serve Frontend static assets & index.html
frontend_dir = BASE_DIR / "frontend"
if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

    @app.get("/", include_in_schema=False)
    async def serve_dashboard():
        index_file = frontend_dir / "index.html"
        if index_file.exists():
            return FileResponse(index_file)
        return {"message": "Transformer WAF API is running. Dashboard index.html not found."}

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "malicious_threshold": settings.MALICIOUS_THRESHOLD
    }
