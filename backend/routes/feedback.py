"""
Feedback API Endpoint for Admin Label Corrections.
POST /feedback
GET /feedback
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.database import get_db
from backend.models import RequestLog, AdminFeedback
from backend.schemas import FeedbackInput, FeedbackResponse, RequestLogItem

router = APIRouter(tags=["Admin Feedback & Review"])

@router.post("/feedback", response_model=FeedbackResponse, status_code=status.HTTP_201_CREATED)
def submit_admin_feedback(feedback_in: FeedbackInput, db: Session = Depends(get_db)):
    """
    Submits administrator correction for a prediction.
    If original was BENIGN and corrected to MALICIOUS => False Negative flagged.
    If original was MALICIOUS and corrected to BENIGN => False Positive flagged.
    Stores the corrected sample for future model fine-tuning.
    """
    log_entry = db.query(RequestLog).filter(RequestLog.id == feedback_in.log_id).first()
    if not log_entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Request log with ID {feedback_in.log_id} not found."
        )

    corrected_label = feedback_in.corrected_label.upper()
    if corrected_label not in ["BENIGN", "MALICIOUS"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="corrected_label must be either 'BENIGN' or 'MALICIOUS'."
        )

    # Flag False Negative or False Positive
    original = log_entry.prediction.upper()
    is_fn = (original == "BENIGN" and corrected_label == "MALICIOUS")
    is_fp = (original == "MALICIOUS" and corrected_label == "BENIGN")

    log_entry.reviewed_by_admin = True
    log_entry.is_false_negative = is_fn
    log_entry.is_false_positive = is_fp
    log_entry.admin_notes = feedback_in.notes or ""

    feedback_record = AdminFeedback(
        log_id=log_entry.id,
        original_prediction=original,
        corrected_label=corrected_label,
        notes=feedback_in.notes or "",
        flagged_for_retraining=True
    )

    db.add(feedback_record)
    db.commit()
    db.refresh(log_entry)
    db.refresh(feedback_record)

    msg = f"Feedback logged successfully."
    if is_fn:
        msg += " Flagged as CRITICAL FALSE NEGATIVE for dataset retraining."
    elif is_fp:
        msg += " Flagged as False Positive to adjust threshold or tokenizer rules."

    return FeedbackResponse(
        status="success",
        message=msg,
        feedback_id=feedback_record.id,
        updated_log=log_entry
    )

@router.get("/feedback/queue", response_model=List[RequestLogItem])
def get_review_queue(limit: int = 50, db: Session = Depends(get_db)):
    """
    Returns requests flagged for review, especially false negatives or borderline predictions.
    """
    items = db.query(RequestLog).filter(
        RequestLog.is_false_negative == True
    ).order_by(desc(RequestLog.timestamp)).limit(limit).all()
    return items
