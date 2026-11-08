"""
Unified Inference Engine for the WAF.
Loads Transformer (DistilBERT) or Fallback Baseline (TF-IDF + LogReg),
evaluates classification confidence against configurable threshold tau,
and measures inference latency.
"""

import os
import time
import logging
from pathlib import Path
from typing import Dict, Any, Optional

import joblib
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

from config.settings import (
    TRANSFORMER_MODEL_DIR,
    BASELINE_MODEL_DIR,
    settings
)
from .serializer import serializer
from .heuristics import analyze_patterns

logger = logging.getLogger("waf_predictor")

class WAFPredictor:
    def __init__(self):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.transformer_model = None
        self.transformer_tokenizer = None
        self.baseline_pipeline = None
        self.model_type = "none"

        self._load_models()

    def _load_models(self):
        """
        Attempts to load DistilBERT first; falls back to Baseline if unavailable.
        """
        # 1. Try DistilBERT
        if (TRANSFORMER_MODEL_DIR / "config.json").exists():
            try:
                logger.info(f"Loading fine-tuned DistilBERT from {TRANSFORMER_MODEL_DIR}...")
                self.transformer_tokenizer = AutoTokenizer.from_pretrained(str(TRANSFORMER_MODEL_DIR))
                self.transformer_model = AutoModelForSequenceClassification.from_pretrained(str(TRANSFORMER_MODEL_DIR))
                self.transformer_model.to(self.device)
                self.transformer_model.eval()
                self.model_type = "DistilBERT (Fine-Tuned)"
                logger.info("DistilBERT loaded successfully.")
                return
            except Exception as e:
                logger.error(f"Failed to load DistilBERT: {e}")

        # 2. Try Baseline
        baseline_file = BASELINE_MODEL_DIR / "tfidf_logreg.joblib"
        if baseline_file.exists():
            try:
                logger.info(f"Loading Baseline TF-IDF + LogReg from {baseline_file}...")
                self.baseline_pipeline = joblib.load(baseline_file)
                self.model_type = "TF-IDF + Logistic Regression (Baseline)"
                logger.info("Baseline model loaded successfully.")
                return
            except Exception as e:
                logger.error(f"Failed to load baseline: {e}")

        logger.warning("No pre-trained model found on disk. Initializing zero-shot tokenizer fallback.")
        self.model_type = "heuristic_only"

    def predict(
        self,
        serialized_text: str,
        threshold: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        Predicts whether the serialized request is BENIGN or MALICIOUS.
        """
        tau = threshold if threshold is not None else settings.MALICIOUS_THRESHOLD
        start_time = time.perf_counter()

        malicious_prob = 0.0
        benign_prob = 1.0

        if self.transformer_model is not None:
            # Transformer Inference
            inputs = self.transformer_tokenizer(
                serialized_text,
                truncation=True,
                max_length=settings.MAX_TOKEN_LENGTH,
                return_tensors="pt"
            ).to(self.device)

            with torch.no_grad():
                logits = self.transformer_model(**inputs).logits
                probs = torch.softmax(logits, dim=-1)[0]
                benign_prob = float(probs[0].item())
                malicious_prob = float(probs[1].item())

        elif self.baseline_pipeline is not None:
            # Baseline Inference
            probs = self.baseline_pipeline.predict_proba([serialized_text])[0]
            benign_prob = float(probs[0])
            malicious_prob = float(probs[1])
        else:
            # Fallback to pattern inspection if no model file loaded
            analysis = analyze_patterns(serialized_text)
            if analysis["is_suspicious"]:
                malicious_prob = 0.95
                benign_prob = 0.05
            else:
                malicious_prob = 0.05
                benign_prob = 0.95

        latency_ms = (time.perf_counter() - start_time) * 1000.0

        is_malicious = malicious_prob >= tau
        classification = "MALICIOUS" if is_malicious else "BENIGN"
        confidence = malicious_prob if is_malicious else benign_prob

        return {
            "prediction": classification,
            "is_malicious": is_malicious,
            "confidence": round(confidence, 4),
            "probabilities": {
                "benign": round(benign_prob, 4),
                "malicious": round(malicious_prob, 4)
            },
            "threshold_applied": tau,
            "latency_ms": round(latency_ms, 2),
            "model_used": self.model_type
        }

    def predict_request(self, request_data: Dict[str, Any], threshold: Optional[float] = None) -> Dict[str, Any]:
        serialized = serializer.serialize_dict(request_data)
        result = self.predict(serialized, threshold=threshold)
        result["serialized_text"] = serialized
        return result

# Singleton instance
waf_predictor = WAFPredictor()
