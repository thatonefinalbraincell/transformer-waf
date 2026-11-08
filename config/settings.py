import os
from pathlib import Path
from pydantic_settings import BaseSettings

# Base directories
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
MODELS_DIR = BASE_DIR / "models"
BASELINE_MODEL_DIR = MODELS_DIR / "baseline"
TRANSFORMER_MODEL_DIR = MODELS_DIR / "distilbert_waf"

class Settings(BaseSettings):
    PROJECT_NAME: str = "Transformer-Based WAF"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Host & Port
    BACKEND_HOST: str = "127.0.0.1"
    BACKEND_PORT: int = 8000
    
    # Upstream Target (for Reverse Proxy mode)
    UPSTREAM_HOST: str = "127.0.0.1"
    UPSTREAM_PORT: int = 8080
    
    # WAF Inspection Thresholds
    # Predictions with probability >= MALICIOUS_THRESHOLD will be blocked
    MALICIOUS_THRESHOLD: float = 0.75
    
    # Inspection Safeguards
    MAX_BODY_SIZE_BYTES: int = 100 * 1024  # 100 KB
    INSPECTION_TIMEOUT_MS: int = 200        # Max allowed inference latency before fallback
    FALLBACK_POLICY: str = "block"          # "block" or "allow" when timeout/error occurs
    
    # Model Configuration
    MODEL_NAME: str = "distilbert-base-uncased"
    MAX_TOKEN_LENGTH: int = 256             # Balanced for WAF payload inspection latency
    BATCH_SIZE: int = 32
    
    # Database
    DATABASE_URL: str = f"sqlite:///{BASE_DIR / 'backend' / 'waf.db'}"

    class Config:
        case_sensitive = True
        env_file = ".env"

settings = Settings()
