"""
Security Heuristic & Signature Inspection Module.
Performs pattern-based deep inspection to extract explainable threat signals
for POST /analyze and fast-path pre-checks.
"""

import re
from typing import List, Dict, Any

PATTERNS = {
    "SQL Injection": [
        (r"(?i)(\bunion\b.*\bselect\b)", "High", "UNION SELECT query detected"),
        (r"(?i)(\bor\b\s+['\"]?1['\"]?\s*=\s*['\"]?1)", "Critical", "Classic OR 1=1 tautology detected"),
        (r"(?i)(\bdrop\b\s+\btable\b)", "Critical", "DROP TABLE command detected"),
        (r"(?i)(--|#|/\*).*", "Medium", "SQL comment delimiter detected"),
        (r"(?i)(\bselect\b.*\bfrom\b.*information_schema)", "Critical", "Schema enumeration attempt detected"),
        (r"(?i)(\bwaitfor\b\s+\bdelay\b|\bsleep\(\d+\))", "High", "Time-based blind SQLi vector detected"),
    ],
    "Cross-Site Scripting (XSS)": [
        (r"(?i)(<script\b[^>]*>.*?</script>)", "Critical", "Embedded script tag detected"),
        (r"(?i)(<[^>]+(onerror|onload|onfocus|onmouseover)\s*=\s*['\"][^'\"]*['\"][^>]*>)", "High", "Malicious event handler injection detected"),
        (r"(?i)(javascript\s*:\s*[^\s]+)", "High", "javascript: pseudo-protocol URL detected"),
        (r"(?i)(<iframe\b[^>]*>)", "Medium", "Suspicious iframe injection detected"),
        (r"(?i)(document\.cookie|document\.domain)", "High", "Cookie/domain exfiltration access detected"),
    ],
    "Path Traversal": [
        (r"(\.\./|\.\.\\)", "High", "Directory traversal sequence (../) detected"),
        (r"(?i)(/etc/passwd|/etc/shadow|/boot\.ini|win\.ini)", "Critical", "Sensitive system file target detected"),
        (r"(%2e%2e%2f|%2e%2e/|\.\.%2f)", "High", "URL-encoded path traversal sequence detected"),
    ],
    "Command Injection": [
        (r"(\||;|&&)\s*(cat|whoami|id|net\s+user|powershell|uname|ping)\b", "Critical", "Chained operating system command execution detected"),
        (r"(`|\$\()(cat|id|whoami)", "High", "Command substitution backtick/dollar-parenthesis detected"),
    ]
}

def analyze_patterns(text: str) -> Dict[str, Any]:
    """
    Inspects text for suspicious patterns across attack categories.
    """
    findings = []
    max_severity = "Clean"
    severity_order = {"Clean": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}

    for category, pattern_list in PATTERNS.items():
        for regex, severity, explanation in pattern_list:
            match = re.search(regex, text)
            if match:
                findings.append({
                    "category": category,
                    "matched_snippet": match.group(0)[:80],
                    "severity": severity,
                    "explanation": explanation
                })
                if severity_order.get(severity, 0) > severity_order.get(max_severity, 0):
                    max_severity = severity

    return {
        "is_suspicious": len(findings) > 0,
        "overall_threat_level": max_severity,
        "detected_patterns_count": len(findings),
        "findings": findings
    }
