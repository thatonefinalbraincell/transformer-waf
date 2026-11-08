"""
Unit tests for HTTP Request Normalizer and Obfuscation Defenses.
"""

from dataset_preparation.normalizer import normalizer

def test_recursive_url_decode():
    # Single URL decode
    assert normalizer.recursive_url_decode("%27") == "'"
    # Double URL decode
    assert normalizer.recursive_url_decode("%2527") == "'"
    # Path traversal encoded
    assert normalizer.recursive_url_decode("..%2f..%2f") == "../../"

def test_null_byte_stripping():
    # Attackers use %00 or \x00 to truncate strings
    dirty = "legit.jpg\x00.php"
    cleaned = normalizer.clean_text(dirty)
    assert "\x00" not in cleaned
    assert "%00" not in cleaned

def test_html_entity_unescaping():
    dirty = "&lt;script&gt;alert(1)&lt;/script&gt;"
    cleaned = normalizer.clean_text(dirty)
    assert "<script>alert(1)</script>" in cleaned

def test_serialization_format():
    serialized = normalizer.serialize_request(
        method="POST",
        path="/api/login",
        query_params="ref=1",
        body="user=admin",
        headers={"user-agent": "test-agent"}
    )
    assert "METHOD: POST" in serialized
    assert "PATH: /api/login" in serialized
    assert "PARAMS: ref=1" in serialized
    assert "HEADERS: user-agent=test-agent" in serialized
    assert "BODY: user=admin" in serialized

if __name__ == "__main__":
    test_recursive_url_decode()
    test_null_byte_stripping()
    test_html_entity_unescaping()
    test_serialization_format()
    print("All normalizer tests passed!")
