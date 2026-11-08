"""
Integration tests for FastAPI WAF endpoints using TestClient.
"""

from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"

def test_predict_benign_request():
    payload = {
        "method": "GET",
        "path": "/api/v1/products",
        "query_params": "category=electronics&page=1&limit=20",
        "body": ""
    }
    response = client.post("/predict", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["prediction"] == "BENIGN"
    assert data["is_malicious"] is False
    assert data["action_taken"] == "ALLOWED"

def test_predict_sqli_attack():
    payload = {
        "method": "POST",
        "path": "/api/v1/login",
        "body": "username=admin' OR '1'='1&password=123"
    }
    response = client.post("/predict", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["prediction"] == "MALICIOUS"
    assert data["is_malicious"] is True
    assert data["action_taken"] == "BLOCKED"
    assert data["confidence"] > 0.75

def test_analyze_xss_attack():
    payload = {
        "method": "POST",
        "path": "/api/v1/comments",
        "body": "<script>alert(document.cookie)</script>"
    }
    response = client.post("/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_suspicious"] is True
    assert data["overall_threat_level"] in ["High", "Critical"]
    assert len(data["findings"]) > 0

def test_stats_and_logs():
    # Test /stats
    response = client.get("/stats")
    assert response.status_code == 200
    stats = response.json()
    assert "total_requests" in stats
    assert "detection_rate" in stats

    # Test /logs
    response = client.get("/logs?limit=5")
    assert response.status_code == 200
    logs = response.json()
    assert isinstance(logs, list)
    assert len(logs) > 0

def test_admin_feedback_submission():
    # 1. Test False Negative: Start with a request predicted as BENIGN
    post_res = client.post("/predict", json={
        "method": "GET",
        "path": "/api/v1/products",
        "query_params": "search=laptop"
    })
    benign_log = post_res.json()
    assert benign_log["prediction"] == "BENIGN"
    log_id_fn = benign_log["log_id"]

    # Submit feedback asserting it is actually MALICIOUS (False Negative correction)
    feedback_payload_fn = {
        "log_id": log_id_fn,
        "corrected_label": "MALICIOUS",
        "notes": "Admin discovered subtle evasion in query string"
    }
    fb_res_fn = client.post("/feedback", json=feedback_payload_fn)
    assert fb_res_fn.status_code == 201
    fb_data_fn = fb_res_fn.json()
    assert fb_data_fn["status"] == "success"
    assert fb_data_fn["updated_log"]["is_false_negative"] is True

    # 2. Test False Positive: Start with an attack request
    post_res_mal = client.post("/predict", json={
        "method": "POST",
        "path": "/api/v1/auth/login",
        "body": "username=admin' OR '1'='1"
    })
    mal_log = post_res_mal.json()
    assert mal_log["prediction"] == "MALICIOUS"
    log_id_fp = mal_log["log_id"]

    # Submit feedback asserting it was actually BENIGN (False Positive correction)
    feedback_payload_fp = {
        "log_id": log_id_fp,
        "corrected_label": "BENIGN",
        "notes": "Admin approved vulnerability testing scanner IP"
    }
    fb_res_fp = client.post("/feedback", json=feedback_payload_fp)
    assert fb_res_fp.status_code == 201
    fb_data_fp = fb_res_fp.json()
    assert fb_data_fp["status"] == "success"
    assert fb_data_fp["updated_log"]["is_false_positive"] is True

if __name__ == "__main__":
    test_health_endpoint()
    test_predict_benign_request()
    test_predict_sqli_attack()
    test_analyze_xss_attack()
    test_stats_and_logs()
    test_admin_feedback_submission()
    print("All FastAPI integration tests passed successfully!")
