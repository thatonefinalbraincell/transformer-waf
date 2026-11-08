"""
Baseline Model Trainer: TF-IDF + Logistic Regression.
Serves as the traditional ML benchmark for comparing against DistilBERT.
Computes Accuracy, Precision, Recall, F1, FPR, FNR, and Confusion Matrix.
"""

import json
import logging
from pathlib import Path
import joblib
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

from config.settings import PROCESSED_DATA_DIR, BASELINE_MODEL_DIR

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("baseline_trainer")

def train_and_evaluate_baseline():
    BASELINE_MODEL_DIR.mkdir(parents=True, exist_ok=True)

    train_path = PROCESSED_DATA_DIR / "train.csv"
    test_path = PROCESSED_DATA_DIR / "test.csv"

    if not train_path.exists() or not test_path.exists():
        raise FileNotFoundError(f"Missing processed data. Run build_dataset.py first.")

    logger.info("Loading training and testing datasets...")
    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)

    X_train = train_df["normalized_text"].astype(str)
    y_train = train_df["label"].astype(int)

    X_test = test_df["normalized_text"].astype(str)
    y_test = test_df["label"].astype(int)

    logger.info(f"Train samples: {len(X_train)}, Test samples: {len(X_test)}")

    # Dual TF-IDF: Word-level (semantics) + Char-level n-grams (syntax, quotes, brackets, encodings)
    logger.info("Configuring FeatureUnion (Word TF-IDF + Character n-grams)...")
    word_vectorizer = TfidfVectorizer(
        analyzer="word",
        ngram_range=(1, 2),
        max_features=5000,
        token_pattern=r'\S+'
    )
    char_vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        max_features=10000
    )

    feature_union = FeatureUnion([
        ("word_tfidf", word_vectorizer),
        ("char_tfidf", char_vectorizer)
    ])

    pipeline = Pipeline([
        ("features", feature_union),
        ("classifier", LogisticRegression(class_weight="balanced", max_iter=1000, C=1.0, random_state=42))
    ])

    logger.info("Training Logistic Regression classifier on TF-IDF features...")
    pipeline.fit(X_train, y_train)

    # Predictions & Probabilities
    logger.info("Evaluating baseline model on unseen test set...")
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    # Metrics Computation
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    
    # Confusion Matrix: [[TN, FP], [FN, TP]]
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    metrics = {
        "model": "TF-IDF + Logistic Regression (Char & Word n-grams)",
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1_score": round(float(f1), 4),
        "false_positive_rate": round(float(fpr), 4),
        "false_negative_rate": round(float(fnr), 4),
        "confusion_matrix": {
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp)
        },
        "test_samples": int(len(y_test))
    }

    # Save Pipeline and Metrics
    model_output_path = BASELINE_MODEL_DIR / "tfidf_logreg.joblib"
    metrics_output_path = BASELINE_MODEL_DIR / "baseline_metrics.json"

    joblib.dump(pipeline, model_output_path)
    with open(metrics_output_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    logger.info(f"Baseline model saved to: {model_output_path}")
    logger.info(f"Baseline metrics saved to: {metrics_output_path}")

    print("\n" + "="*60)
    print("BASELINE EVALUATION REPORT (TF-IDF + LOGISTIC REGRESSION)")
    print("="*60)
    print(f"Accuracy:              {acc:.4f} ({acc*100:.2f}%)")
    print(f"Precision:             {prec:.4f} ({prec*100:.2f}%)")
    print(f"Recall:                {rec:.4f} ({rec*100:.2f}%)")
    print(f"F1-Score:              {f1:.4f}")
    print(f"False Positive Rate:   {fpr:.4f} ({fpr*100:.2f}%)  [Legitimate traffic blocked]")
    print(f"False Negative Rate:   {fnr:.4f} ({fnr*100:.2f}%)  [Attacks missed / Security risk]")
    print("-" * 60)
    print("Confusion Matrix:")
    print(f"  [TN: {tn:<4} | FP: {fp:<4}]")
    print(f"  [FN: {fn:<4} | TP: {tp:<4}]")
    print("="*60 + "\n")

    return pipeline, metrics

if __name__ == "__main__":
    train_and_evaluate_baseline()
