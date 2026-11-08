"""
Comprehensive Evaluation & Comparative Benchmark Suite.
Compares the TF-IDF Baseline against the DistilBERT Transformer WAF
across Accuracy, Precision, Recall, F1, FPR, FNR, Attack-Type Breakdown,
and Inference Latency percentiles (P50, P95, P99).
"""

import json
import time
import logging
from pathlib import Path
import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

from config.settings import PROCESSED_DATA_DIR, BASELINE_MODEL_DIR, TRANSFORMER_MODEL_DIR, MODELS_DIR

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("evaluator")

def benchmark_model(name: str, predict_fn, test_df: pd.DataFrame):
    """
    Evaluates a prediction function on accuracy, security metrics, latency, and attack breakdown.
    """
    latencies_ms = []
    y_true = test_df["label"].astype(int).tolist()
    y_pred = []
    y_probs = []

    for text in test_df["normalized_text"]:
        t0 = time.perf_counter()
        pred, prob = predict_fn(str(text))
        t1 = time.perf_counter()
        latencies_ms.append((t1 - t0) * 1000.0)
        y_pred.append(int(pred))
        y_probs.append(float(prob))

    # Metric computations
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    # Attack category breakdown
    test_df_copy = test_df.copy()
    test_df_copy["pred"] = y_pred
    attack_breakdown = {}
    for atype, group in test_df_copy.groupby("attack_type"):
        group_acc = (group["label"] == group["pred"]).mean()
        attack_breakdown[atype] = {
            "total_samples": len(group),
            "detection_accuracy": round(float(group_acc), 4)
        }

    return {
        "model_name": name,
        "metrics": {
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
            }
        },
        "latency_ms": {
            "mean": round(float(np.mean(latencies_ms)), 2),
            "p50": round(float(np.percentile(latencies_ms, 50)), 2),
            "p95": round(float(np.percentile(latencies_ms, 95)), 2),
            "p99": round(float(np.percentile(latencies_ms, 99)), 2)
        },
        "attack_breakdown": attack_breakdown
    }

def run_evaluation_suite():
    test_path = PROCESSED_DATA_DIR / "test.csv"
    if not test_path.exists():
        raise FileNotFoundError(f"Test dataset not found at {test_path}")

    test_df = pd.read_csv(test_path)
    logger.info(f"Loaded test dataset with {len(test_df)} samples.")

    results = {}

    # 1. Evaluate Baseline Model
    baseline_path = BASELINE_MODEL_DIR / "tfidf_logreg.joblib"
    if baseline_path.exists():
        logger.info("Evaluating Baseline (TF-IDF + Logistic Regression)...")
        pipeline = joblib.load(baseline_path)

        def baseline_predict(text: str):
            prob = pipeline.predict_proba([text])[0, 1]
            pred = 1 if prob >= 0.5 else 0
            return pred, prob

        results["baseline"] = benchmark_model("TF-IDF + Logistic Regression", baseline_predict, test_df)
    else:
        logger.warning(f"Baseline model not found at {baseline_path}")

    # 2. Evaluate DistilBERT if checkpoints exist
    distilbert_path = TRANSFORMER_MODEL_DIR
    if (distilbert_path / "model.safetensors").exists() or (distilbert_path / "pytorch_model.bin").exists() or (distilbert_path / "config.json").exists():
        logger.info("Evaluating DistilBERT Model...")
        try:
            import torch
            from transformers import AutoTokenizer, AutoModelForSequenceClassification
            device = "cuda" if torch.cuda.is_available() else "cpu"
            tokenizer = AutoTokenizer.from_pretrained(str(distilbert_path))
            model = AutoModelForSequenceClassification.from_pretrained(str(distilbert_path)).to(device)
            model.eval()

            def distilbert_predict(text: str):
                inputs = tokenizer(text, truncation=True, max_length=256, return_tensors="pt").to(device)
                with torch.no_grad():
                    logits = model(**inputs).logits
                    probs = torch.softmax(logits, dim=-1)[0]
                    malicious_prob = probs[1].item()
                    pred = 1 if malicious_prob >= 0.75 else 0
                return pred, malicious_prob

            results["distilbert"] = benchmark_model("DistilBERT (Transformer)", distilbert_predict, test_df)
        except Exception as e:
            logger.error(f"Error loading DistilBERT model: {e}")

    report_path = MODELS_DIR / "comparison_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    logger.info(f"Comparative report saved to: {report_path}")
    print("\n" + "="*70)
    print("COMPARATIVE EVALUATION SUMMARY")
    print("="*70)
    for model_key, res in results.items():
        m = res["metrics"]
        lat = res["latency_ms"]
        print(f"Model: {res['model_name']}")
        print(f"  Accuracy:  {m['accuracy']:.4f} | F1: {m['f1_score']:.4f}")
        print(f"  Recall:    {m['recall']:.4f}   | Precision: {m['precision']:.4f}")
        print(f"  FNR:       {m['false_negative_rate']:.4f} (Missed attacks)")
        print(f"  FPR:       {m['false_positive_rate']:.4f} (False alarms)")
        print(f"  Latency:   Mean={lat['mean']}ms, P95={lat['p95']}ms, P99={lat['p99']}ms")
        print("-" * 70)

    return results

if __name__ == "__main__":
    run_evaluation_suite()
