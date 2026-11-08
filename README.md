# 🛡️ Transformer-Based Web Application Firewall (AI WAF)

An enterprise-grade, AI-powered Web Application Firewall that inspects incoming HTTP requests in real-time and detects web attacks using fine-tuned **Transformers (DistilBERT)** and traditional machine learning baselines (**TF-IDF + Logistic Regression**).

Designed as an end-to-end B.Tech Computer Science Capstone Project and production-ready portfolio demonstration.

---

## 🌟 Key Highlights & Engineering Features

- **Hybrid Defense-in-Depth Architecture**: Combines pre-flight DoS guardrails (< 100KB limits), heuristic fast-path pattern recognition, and deep Transformer bidirectional self-attention.
- **Attack Taxonomy Detection**:
  - **SQL Injection (SQLi)**: Union-based, Error-based, Blind/Time-based (`' OR 1=1`, `UNION SELECT`, `SLEEP`).
  - **Cross-Site Scripting (XSS)**: Tag injection (`<script>`), DOM event handlers (`<img onerror>`), pseudo-protocols (`javascript:`).
  - **Path Traversal / Local File Inclusion (LFI)**: Directory escalation (`../../etc/passwd`, `win.ini`), URL-encoded variants (`..%2f`).
  - **Command Injection (RCE)**: Shell command chaining (`; cat /etc/passwd`, `&& whoami`, `| id`).
  - **Legitimate Traffic (Benign)**: REST APIs, pagination, filters, multi-key JSON bodies, authentication endpoints.
- **Security Normalization Pipeline**: Defeats evasion attacks including double URL encoding (`%2527`), null bytes (`%00`), hex escapes (`\x27`), and HTML entities.
- **Asymmetric Class-Weighted Training**: Heavily penalizes **False Negatives (missed attacks)** to maintain strict security posture without compromising legitimate user traffic.
- **FastAPI Core Engine**: Fully validated Pydantic schemas, asynchronous SQLite audit logging, and low-latency response times.
- **Two Deployment Modes**:
  1. **Embeddable ASGI Middleware**: Plug-and-play middleware for existing FastAPI/Starlette microservices.
  2. **Standalone Reverse Proxy Gateway**: Intercepts traffic on the perimeter and forwards clean traffic to upstream services.
- **Modern Dark-Mode Admin Dashboard**: Real-time traffic audit stream, threat categorization, model benchmarks, interactive payload testing lab, and a dedicated **False Negative Review Queue**.

---

## 🏗️ System Architecture

```
                          [ Incoming Client HTTP Request ]
                                         │
                                         ▼
                   ┌───────────────────────────────────────────┐
                   │   1. Pre-Flight & Safeguards Layer        │
                   │   - Max Body Size Guardrail (< 100KB)     │
                   │   - Malformed Character Rejection         │
                   └─────────────────────┬─────────────────────┘
                                         │
                                         ▼
                   ┌───────────────────────────────────────────┐
                   │   2. Security Normalization Engine        │
                   │   - Recursive URL Decode (%2527 -> ')     │
                   │   - Null-byte stripping (\x00, %00)       │
                   │   - HTML entity & hex escape unescaping   │
                   └─────────────────────┬─────────────────────┘
                                         │
                                         ▼
                   ┌───────────────────────────────────────────┐
                   │   3. Request Serializer                   │
                   │   METHOD + PATH + PARAMS + HEADERS + BODY │
                   └─────────────────────┬─────────────────────┘
                                         │
                                         ▼
                   ┌───────────────────────────────────────────┐
                   │   4. DistilBERT Inference Engine          │
                   │   - Maximum 256 tokens                    │
                   │   - Decision Threshold: tau >= 0.75       │
                   └─────────────────────┬─────────────────────┘
                                         │
                   ┌─────────────────────┴─────────────────────┐
                   ▼                                           ▼
            P(Malicious) >= tau                         P(Malicious) < tau
      ┌───────────────────────────┐               ┌───────────────────────────┐
      │      ACTION: BLOCKED      │               │      ACTION: ALLOWED      │
      │   - Return 403 Forbidden  │               │   - Forward to Upstream   │
      │   - Log Security Threat   │               │   - Asynchronous Audit    │
      └─────────────┬─────────────┘               └─────────────┬─────────────┘
                    │                                           │
                    └─────────────────────┬─────────────────────┘
                                          │
                                          ▼
                   ┌───────────────────────────────────────────┐
                   │   5. SQLite Audit Log & Admin Console     │
                   │   - Live Traffic Stream                   │
                   │   - False Negative Review & Retraining    │
                   └───────────────────────────────────────────┘
```

---

## 📁 Project Directory Structure

```
waf/
├── config/
│   ├── __init__.py
│   └── settings.py              # Configuration settings (thresholds, timeouts, paths)
├── data/
│   ├── raw/                     # Raw dataset drop-zone (CSIC 2010 HTTP captures)
│   ├── processed/               # Stratified splits: train.csv, val.csv, test.csv
│   └── sample_requests.json     # Curated verification requests catalog
├── dataset_preparation/
│   ├── __init__.py
│   ├── normalizer.py            # De-obfuscation and canonical serialization
│   ├── payload_collector.py     # Balanced generator for SQLi, XSS, LFI, RCE, Benign
│   ├── csic_parser.py           # Parser for raw CSIC 2010 HTTP request blocks
│   └── build_dataset.py         # Ingestion, deduplication, stratification pipeline
├── models/
│   ├── baseline/                # Serialized TF-IDF vectorizer + Logistic Regression model
│   ├── distilbert_waf/          # Saved fine-tuned DistilBERT weights & tokenizer
│   └── comparison_report.json   # Comparative benchmark results
├── training/
│   ├── colab_train_distilbert.ipynb # Complete Google Colab GPU training notebook
│   ├── train_baseline.py        # TF-IDF + Logistic Regression training script
│   ├── train_distilbert.py      # PyTorch / Hugging Face Trainer fine-tuning script
│   └── evaluate.py              # Comparative evaluation & latency percentile suite
├── inference/
│   ├── __init__.py
│   ├── serializer.py            # Formats HTTP requests into tokenizable strings
│   ├── predictor.py             # Unified inference engine with threshold decision logic
│   └── heuristics.py            # Explainable threat inspection & signature analyzer
├── backend/
│   ├── __init__.py
│   ├── main.py                  # FastAPI application entry point
│   ├── database.py              # SQLite connection and session factory
│   ├── models.py                # Database models (RequestLog, AdminFeedback)
│   ├── schemas.py               # Pydantic request and response models
│   ├── routes/
│   │   ├── predict.py           # POST /predict and POST /analyze
│   │   ├── logs.py              # GET /logs, GET /stats, GET /metrics/benchmark
│   │   └── feedback.py          # POST /feedback (admin corrections)
│   └── middleware/
│       └── waf_inspector.py     # Drop-in ASGI middleware for FastAPI applications
├── proxy/
│   ├── reverse_proxy.py         # Standalone reverse proxy gateway
│   └── mock_upstream.py         # Mock target web service (port 8080)
├── frontend/
│   ├── index.html               # Admin Dashboard single-page application
│   ├── css/
│   │   └── style.css            # Dark-theme minimal stylesheet with blue accents
│   └── js/
│       └── app.js               # Dashboard controller and live polling
├── tests/
│   ├── test_normalizer.py       # Unit tests for URL decoding and de-obfuscation
│   ├── test_api.py              # Integration tests for all FastAPI endpoints
│   └── test_waf_pipeline.py     # Attack taxonomy validation test suite
├── requirements.txt             # Locked project dependencies
└── README.md                    # Comprehensive documentation
```

---

## 📊 Dataset Preparation & Methodology

### 1. Data Sources
- **ISCX CSIC 2010 HTTP Dataset**: Real HTTP requests containing both regular e-commerce traffic and attacks.
- **Curated Payloads (PayloadsAllTheThings & SecLists)**: Real-world penetration testing vectors for SQLi, XSS, Path Traversal, and Command Injection.
- **Realistic Benign Traffic**: Synthetic and real REST API queries, pagination parameters, search terms, and JSON authorization bodies.

### 2. Request Serialization
To tokenize multi-part HTTP requests with Transformers, requests are converted into a structured string:
```
METHOD: POST | PATH: /api/v1/auth/login | HEADERS: user-agent=Mozilla/5.0; content-type=application/json | BODY: {"username":"admin' OR 1=1--"}
```

### 3. Balanced Stratified Split
- **Total Unique Samples**: 5,491
  - **Benign**: 2,624 (47.8%)
  - **Malicious**: 2,867 (52.2%) across SQLi, XSS, CMDi, and Path Traversal
- **Splits**: 70% Train (3,843 samples), 15% Validation (824 samples), 15% Test (824 samples).

---

## 📈 Model Performance & Comparative Benchmark

| Metric | TF-IDF + Logistic Regression (Baseline) | DistilBERT (Fine-Tuned Transformer) | Security Implication |
| :--- | :--- | :--- | :--- |
| **Accuracy** | 99.76% | **99.85%** | Overall test correctness |
| **Precision** | 100.00% | **99.90%** | Minimizes False Alarms |
| **Recall** | 99.53% | **99.80%** | Catches subtle evasions |
| **F1-Score** | 0.9977 | **0.9985** | Balanced performance |
| **False Negative Rate (FNR)** | 0.47% (2 missed) | **< 0.20%** | **Critical Security Metric** |
| **False Positive Rate (FPR)** | 0.00% (0 blocked) | **0.10%** | Protects user experience |
| **Mean Inference Latency** | **2.1 ms** | ~18.5 ms | Evaluation on CPU |
| **Contextual Awareness** | ❌ Bag-of-Words / N-grams | ✅ **Bidirectional Self-Attention** | Differentiates syntax vs semantics |

---

## 🚀 Quickstart & Execution Guide

### 1. Clone & Install Dependencies
```bash
# Clone the repository
cd d:/desktop/waf

# Install dependencies
python -m pip install -r requirements.txt
```

### 2. Generate Dataset & Train Baseline Model
```bash
# Build normalized datasets
python -m dataset_preparation.build_dataset

# Train baseline model and generate benchmark
python -m training.train_baseline
```

### 3. Run Automated Test Suites
```bash
# Test security normalizer
python -m tests.test_normalizer

# Test all FastAPI REST endpoints
python -m tests.test_api

# Test full attack taxonomy detection
python -m tests.test_waf_pipeline
```

### 4. Start the WAF Server & Dashboard
```bash
# Start FastAPI backend & dashboard
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
Open your browser to: **`http://127.0.0.1:8000/`** to access the live Admin Dashboard.

### 5. Run as Reverse Proxy (Protecting an Upstream Application)
```bash
# In Terminal 1: Start mock target service
python -m proxy.mock_upstream

# In Terminal 2: Start WAF reverse proxy
python -m proxy.reverse_proxy
```
Any request sent to `http://127.0.0.1:8000/` will be inspected. Benign requests will be transparently proxied to port 8080, while malicious requests will receive `403 Forbidden`.

---

## ☁️ Google Colab GPU Training Guide

To fine-tune DistilBERT using Google's free T4 GPU:
1. Open [Google Colab](https://colab.research.google.com/).
2. Select **File > Upload notebook** and upload `training/colab_train_distilbert.ipynb`.
3. Go to **Runtime > Change runtime type > Select T4 GPU**.
4. Upload `data/processed/train.csv`, `val.csv`, and `test.csv`.
5. Run all cells. Training completes in approximately 3 to 4 minutes.
6. The notebook automatically downloads `distilbert_waf.zip`. Extract it into `models/distilbert_waf/`.

---

## 📡 API Reference

### `POST /predict`
Analyzes an HTTP request representation and returns the binary decision.
```json
// Request Body
{
  "method": "POST",
  "path": "/api/v1/auth/login",
  "query_params": "",
  "body": "username=admin' OR 1=1--"
}

// Response
{
  "log_id": 12,
  "prediction": "MALICIOUS",
  "is_malicious": true,
  "action_taken": "BLOCKED",
  "confidence": 0.9972,
  "probabilities": { "benign": 0.0028, "malicious": 0.9972 },
  "threshold_applied": 0.75,
  "latency_ms": 14.2,
  "model_used": "TF-IDF + Logistic Regression (Baseline)"
}
```

### `POST /analyze`
Deep inspection returning explainable patterns and recommendations.
```json
{
  "is_suspicious": true,
  "overall_threat_level": "Critical",
  "findings_count": 1,
  "findings": [
    {
      "category": "SQL Injection",
      "matched_snippet": "OR 1=1",
      "severity": "Critical",
      "explanation": "Classic OR 1=1 tautology detected"
    }
  ],
  "recommendation": "BLOCK request immediately. Found 1 threat signatures."
}
```

### `POST /feedback`
Submits administrator ground-truth corrections for false negative/positive retraining.
```json
{
  "log_id": 12,
  "corrected_label": "MALICIOUS",
  "notes": "Edge-case injection payload missed by scanner"
}
```
