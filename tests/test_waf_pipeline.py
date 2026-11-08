"""
End-to-End WAF Pipeline Tests.
Validates detection rates across SQLi, XSS, Path Traversal, and Command Injection.
"""

from inference import waf_predictor

ATTACK_VECTORS = [
    # SQLi
    ("POST", "/api/v1/auth/login", "", "admin' OR 1=1--", "MALICIOUS"),
    ("GET", "/api/v1/products", "id=1 UNION SELECT 1,username,password FROM users--", "", "MALICIOUS"),
    ("GET", "/api/v1/users", "id=1' AND SLEEP(5)--", "", "MALICIOUS"),
    
    # XSS
    ("POST", "/api/v1/comments", "", "<script>alert('XSS')</script>", "MALICIOUS"),
    ("GET", "/api/v1/search", "q=<img src=x onerror=alert(1)>", "", "MALICIOUS"),
    ("GET", "/view", "redirect=javascript:alert(document.cookie)", "", "MALICIOUS"),

    # Path Traversal
    ("GET", "/download", "file=../../../../etc/passwd", "", "MALICIOUS"),
    ("GET", "/download", "file=..%2f..%2f..%2fetc%2fshadow", "", "MALICIOUS"),
    ("GET", "/view", "doc=../../windows/system32/drivers/etc/hosts", "", "MALICIOUS"),

    # Command Injection
    ("POST", "/api/v1/tools", "", "target=127.0.0.1; cat /etc/passwd", "MALICIOUS"),
    ("GET", "/order/lookup", "ref=123 && whoami", "", "MALICIOUS"),
    ("POST", "/api/v1/query", "", "name=test | id", "MALICIOUS"),

    # Benign Requests
    ("GET", "/api/v1/products", "category=electronics&page=2&limit=20", "", "BENIGN"),
    ("GET", "/api/v1/search", "q=wireless+headphones", "", "BENIGN"),
    ("POST", "/api/v1/auth/login", "", '{"email": "user@example.com", "password": "SecurePass!123"}', "BENIGN"),
]

def test_waf_pipeline_taxonomy():
    passed = 0
    total = len(ATTACK_VECTORS)

    print("\n" + "="*70)
    print("RUNNING END-TO-END WAF ATTACK TAXONOMY TEST")
    print("="*70)

    for method, path, params, body, expected in ATTACK_VECTORS:
        req = {
            "method": method,
            "path": path,
            "params": params,
            "body": body
        }
        res = waf_predictor.predict_request(req)
        actual = res["prediction"]
        is_ok = (actual == expected)

        if is_ok:
            passed += 1
            status_str = "[PASS]"
        else:
            status_str = "[FAIL]"

        snippet = (body or params)[:40]
        print(f"{status_str} Expected: {expected:<9} | Got: {actual:<9} | Conf: {res['confidence']*100:.1f}% | Payload: {snippet}")

    accuracy = passed / total
    print("-" * 70)
    print(f"Taxonomy Test Passed: {passed}/{total} ({accuracy*100:.1f}%)")
    print("="*70 + "\n")

    assert accuracy >= 0.85, f"Taxonomy accuracy below 85%: {accuracy}"

if __name__ == "__main__":
    test_waf_pipeline_taxonomy()
