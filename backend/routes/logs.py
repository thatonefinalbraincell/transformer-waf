"""
Traffic Logs & Statistics API endpoints.
GET /logs
GET /stats
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from backend.database import get_db
from backend.models import RequestLog
from backend.schemas import RequestLogItem, StatsResponse

router = APIRouter(tags=["Logs & Analytics"])

@router.get("/logs", response_model=List[RequestLogItem])
def get_request_logs(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    prediction: Optional[str] = Query(default=None, description="Filter by BENIGN or MALICIOUS"),
    action: Optional[str] = Query(default=None, description="Filter by ALLOWED or BLOCKED"),
    is_false_negative: Optional[bool] = Query(default=None, description="Filter false negatives"),
    db: Session = Depends(get_db)
):
    """
    Returns historical request logs with optional filtering by status,
    prediction, action, or false negative review flag.
    """
    query = db.query(RequestLog)
    if prediction:
        query = query.filter(RequestLog.prediction == prediction.upper())
    if action:
        query = query.filter(RequestLog.action_taken == action.upper())
    if is_false_negative is not None:
        query = query.filter(RequestLog.is_false_negative == is_false_negative)

    logs = query.order_by(desc(RequestLog.timestamp)).offset(offset).limit(limit).all()
    return logs

@router.get("/stats", response_model=StatsResponse)
def get_waf_statistics(db: Session = Depends(get_db)):
    """
    Returns real-time aggregated WAF metrics:
    - Total requests analyzed
    - Benign requests count
    - Malicious requests count
    - Blocked and allowed requests
    - Detection rate (%)
    - Average latency (ms)
    - False Negative and False Positive counts
    - Threat category distribution
    """
    total = db.query(func.count(RequestLog.id)).scalar() or 0
    benign = db.query(func.count(RequestLog.id)).filter(RequestLog.prediction == "BENIGN").scalar() or 0
    malicious = db.query(func.count(RequestLog.id)).filter(RequestLog.prediction == "MALICIOUS").scalar() or 0
    blocked = db.query(func.count(RequestLog.id)).filter(RequestLog.action_taken == "BLOCKED").scalar() or 0
    allowed = db.query(func.count(RequestLog.id)).filter(RequestLog.action_taken == "ALLOWED").scalar() or 0

    avg_lat = db.query(func.avg(RequestLog.latency_ms)).scalar() or 0.0
    fn_count = db.query(func.count(RequestLog.id)).filter(RequestLog.is_false_negative == True).scalar() or 0
    fp_count = db.query(func.count(RequestLog.id)).filter(RequestLog.is_false_positive == True).scalar() or 0

    # Detection rate = Malicious / Total
    det_rate = (malicious / total) if total > 0 else 0.0

    # Threat breakdown
    category_counts = db.query(
        RequestLog.threat_category,
        func.count(RequestLog.id)
    ).group_by(RequestLog.threat_category).all()

    threat_dist = {cat or "none": count for cat, count in category_counts}

    return StatsResponse(
        total_requests=total,
        benign_count=benign,
        malicious_count=malicious,
        blocked_count=blocked,
        allowed_count=allowed,
        detection_rate=round(det_rate, 4),
        avg_latency_ms=round(float(avg_lat), 2),
        false_negatives_count=fn_count,
        false_positives_count=fp_count,
        threat_distribution=threat_dist
    )

@router.get("/metrics/benchmark")
def get_benchmark_metrics():
    """
    Returns comparative evaluation report and test-set confusion matrix.
    """
    import json
    from config.settings import MODELS_DIR, BASELINE_MODEL_DIR

    comparison_path = MODELS_DIR / "comparison_report.json"
    baseline_path = BASELINE_MODEL_DIR / "baseline_metrics.json"

    data = {}
    if comparison_path.exists():
        with open(comparison_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    elif baseline_path.exists():
        with open(baseline_path, "r", encoding="utf-8") as f:
            base_m = json.load(f)
            data = {"baseline": {"metrics": base_m, "model_name": base_m.get("model")}}

    return data
