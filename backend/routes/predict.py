"""
Prediction and Deep Analysis API endpoints.
POST /predict
POST /analyze
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import RequestLog
from backend.schemas import HTTPRequestInput, PredictionResponse, AnalyzeResponse, ThreatFinding
from inference import waf_predictor, analyze_patterns

router = APIRouter(tags=["Inspection & Prediction"])

@router.post("/predict", response_model=PredictionResponse, status_code=status.HTTP_200_OK)
def predict_request_endpoint(req: HTTPRequestInput, db: Session = Depends(get_db)):
    """
    Evaluates an incoming HTTP request and returns:
    - Prediction (BENIGN or MALICIOUS)
    - Confidence score
    - Classification result & action (ALLOWED or BLOCKED)
    """
    req_dict = req.model_dump()
    result = waf_predictor.predict_request(req_dict, threshold=req.threshold)

    action = "BLOCKED" if result["is_malicious"] else "ALLOWED"

    # Analyze patterns to tag threat category
    heuristic_res = analyze_patterns(result["serialized_text"])
    threat_cat = "none"
    if heuristic_res["findings"]:
        threat_cat = heuristic_res["findings"][0]["category"].lower().replace(" ", "_")
    elif result["is_malicious"]:
        threat_cat = "suspicious_request"

    # Persist log in DB
    log_entry = RequestLog(
        client_ip=req.client_ip or "127.0.0.1",
        method=(req.method or "GET").upper(),
        path=req.path or "/",
        query_params=req.query_params or "",
        body=req.body or "",
        serialized_text=result["serialized_text"],
        prediction=result["prediction"],
        confidence=result["confidence"],
        malicious_prob=result["probabilities"]["malicious"],
        action_taken=action,
        threat_category=threat_cat,
        latency_ms=result["latency_ms"],
        model_used=result["model_used"]
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)

    return PredictionResponse(
        log_id=log_entry.id,
        prediction=result["prediction"],
        is_malicious=result["is_malicious"],
        action_taken=action,
        confidence=result["confidence"],
        probabilities=result["probabilities"],
        threshold_applied=result["threshold_applied"],
        latency_ms=result["latency_ms"],
        model_used=result["model_used"]
    )

@router.post("/analyze", response_model=AnalyzeResponse, status_code=status.HTTP_200_OK)
def analyze_request_endpoint(req: HTTPRequestInput, db: Session = Depends(get_db)):
    """
    Deep inspection endpoint that returns ML classification along with
    explainable pattern analysis, matched tokens, and security recommendations.
    """
    # 1. Obtain standard prediction
    req_dict = req.model_dump()
    result = waf_predictor.predict_request(req_dict, threshold=req.threshold)
    action = "BLOCKED" if result["is_malicious"] else "ALLOWED"

    # 2. Heuristic Deep Inspection
    pattern_report = analyze_patterns(result["serialized_text"])
    findings = [
        ThreatFinding(
            category=f["category"],
            matched_snippet=f["matched_snippet"],
            severity=f["severity"],
            explanation=f["explanation"]
        ) for f in pattern_report["findings"]
    ]

    threat_cat = findings[0].category.lower().replace(" ", "_") if findings else ("none" if not result["is_malicious"] else "anomalous_payload")

    # 3. Save log record
    log_entry = RequestLog(
        client_ip=req.client_ip or "127.0.0.1",
        method=(req.method or "GET").upper(),
        path=req.path or "/",
        query_params=req.query_params or "",
        body=req.body or "",
        serialized_text=result["serialized_text"],
        prediction=result["prediction"],
        confidence=result["confidence"],
        malicious_prob=result["probabilities"]["malicious"],
        action_taken=action,
        threat_category=threat_cat,
        latency_ms=result["latency_ms"],
        model_used=result["model_used"]
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)

    # 4. Formulate Recommendation
    if result["is_malicious"] or pattern_report["is_suspicious"]:
        rec = f"BLOCK request immediately. Found {len(findings)} threat signatures. Risk level: {pattern_report['overall_threat_level']}."
    else:
        rec = "ALLOW request. No malicious tokens or statistical anomalies detected."

    pred_resp = PredictionResponse(
        log_id=log_entry.id,
        prediction=result["prediction"],
        is_malicious=result["is_malicious"],
        action_taken=action,
        confidence=result["confidence"],
        probabilities=result["probabilities"],
        threshold_applied=result["threshold_applied"],
        latency_ms=result["latency_ms"],
        model_used=result["model_used"]
    )

    return AnalyzeResponse(
        prediction_result=pred_resp,
        is_suspicious=pattern_report["is_suspicious"],
        overall_threat_level=pattern_report["overall_threat_level"],
        findings_count=len(findings),
        findings=findings,
        recommendation=rec
    )
