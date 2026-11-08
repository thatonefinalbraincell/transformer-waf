"""
SQLAlchemy ORM Models for WAF traffic logs and feedback.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, Text, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from .database import Base

class RequestLog(Base):
    __tablename__ = "request_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    client_ip = Column(String(50), default="127.0.0.1")
    method = Column(String(10), index=True)
    path = Column(String(500), index=True)
    query_params = Column(Text, default="")
    body = Column(Text, default="")
    serialized_text = Column(Text)
    
    # ML & WAF Decision
    prediction = Column(String(20), index=True)      # "BENIGN" or "MALICIOUS"
    confidence = Column(Float)                       # 0.0 - 1.0
    malicious_prob = Column(Float)
    action_taken = Column(String(20), index=True)    # "ALLOWED" or "BLOCKED"
    threat_category = Column(String(50), default="none")
    latency_ms = Column(Float)
    model_used = Column(String(100))

    # Administrative Review & Retraining
    reviewed_by_admin = Column(Boolean, default=False)
    is_false_negative = Column(Boolean, default=False)  # Classified as Benign, but actually Malicious
    is_false_positive = Column(Boolean, default=False)  # Classified as Malicious, but actually Benign
    admin_notes = Column(Text, default="")

    feedback = relationship("AdminFeedback", back_populates="request_log", cascade="all, delete-orphan")

class AdminFeedback(Base):
    __tablename__ = "admin_feedback"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    log_id = Column(Integer, ForeignKey("request_logs.id"))
    submitted_at = Column(DateTime, default=datetime.utcnow)
    original_prediction = Column(String(20))
    corrected_label = Column(String(20))             # "BENIGN" or "MALICIOUS"
    notes = Column(Text, default="")
    flagged_for_retraining = Column(Boolean, default=True)

    request_log = relationship("RequestLog", back_populates="feedback")
