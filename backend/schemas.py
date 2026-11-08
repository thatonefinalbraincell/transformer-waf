"""
Pydantic Schemas for Request & Response Validation.
"""

from datetime import datetime
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field

# Input schema for POST /predict and POST /analyze
class HTTPRequestInput(BaseModel):
    method: str = Field(default="GET", description="HTTP Method (GET, POST, etc.)", examples=["POST"])
    path: str = Field(default="/", description="URL path", examples=["/api/v1/login"])
    query_params: Optional[str] = Field(default="", description="Query string", examples=["id=10"])
    body: Optional[str] = Field(default="", description="Request payload or JSON string", examples=["username=admin' OR 1=1--"])
    headers: Optional[Dict[str, str]] = Field(default_factory=dict, description="Selected HTTP headers")
    client_ip: Optional[str] = Field(default="127.0.0.1", description="Client IP address")
    threshold: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Override decision threshold tau")

# Output schema for POST /predict
class PredictionResponse(BaseModel):
    log_id: int
    prediction: str
    is_malicious: bool
    action_taken: str
    confidence: float
    probabilities: Dict[str, float]
    threshold_applied: float
    latency_ms: float
    model_used: str

# Finding item for POST /analyze
class ThreatFinding(BaseModel):
    category: str
    matched_snippet: str
    severity: str
    explanation: str

# Output schema for POST /analyze
class AnalyzeResponse(BaseModel):
    prediction_result: PredictionResponse
    is_suspicious: bool
    overall_threat_level: str
    findings_count: int
    findings: List[ThreatFinding]
    recommendation: str

# Log record schema for GET /logs
class RequestLogItem(BaseModel):
    id: int
    timestamp: datetime
    client_ip: str
    method: str
    path: str
    query_params: Optional[str]
    body: Optional[str]
    prediction: str
    confidence: float
    action_taken: str
    threat_category: str
    latency_ms: float
    model_used: str
    reviewed_by_admin: bool
    is_false_negative: bool
    is_false_positive: bool

    class Config:
        from_attributes = True

# Output schema for GET /stats
class StatsResponse(BaseModel):
    total_requests: int
    benign_count: int
    malicious_count: int
    blocked_count: int
    allowed_count: int
    detection_rate: float
    avg_latency_ms: float
    false_negatives_count: int
    false_positives_count: int
    threat_distribution: Dict[str, int]

# Input schema for POST /feedback
class FeedbackInput(BaseModel):
    log_id: int = Field(description="ID of the logged request to correct")
    corrected_label: str = Field(description="'BENIGN' or 'MALICIOUS'")
    notes: Optional[str] = Field(default="", description="Admin justification or context")

# Output schema for POST /feedback
class FeedbackResponse(BaseModel):
    status: str
    message: str
    feedback_id: int
    updated_log: RequestLogItem
