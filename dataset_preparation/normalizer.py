import html
import re
import urllib.parse
from typing import Dict, Any, Optional

class HTTPRequestNormalizer:
    """
    Security normalizer for HTTP requests.
    Mitigates evasion techniques like double URL encoding, hex encoding,
    mixed casing, HTML entity injection, and null byte truncation.
    """

    def __init__(self, max_decode_rounds: int = 3):
        self.max_decode_rounds = max_decode_rounds

    def recursive_url_decode(self, text: str) -> str:
        """
        Recursively URL-decodes text up to max_decode_rounds
        to defeat nested obfuscation (e.g., %2527 -> %27 -> ').
        """
        if not text:
            return ""
        
        current = text
        for _ in range(self.max_decode_rounds):
            try:
                decoded = urllib.parse.unquote(current)
                if decoded == current:
                    break
                current = decoded
            except Exception:
                break
        return current

    def clean_text(self, text: str) -> str:
        """
        Applies security normalization pipeline:
        1. Strips null bytes (\x00, %00) which attackers use to bypass checks
        2. Recursive URL decoding
        3. HTML entity unescaping
        4. Hex sequence decoding (\\xHH)
        5. Whitespace consolidation
        """
        if not text:
            return ""

        # Remove null bytes
        cleaned = text.replace("\x00", "").replace("%00", "")

        # Recursive URL decode
        cleaned = self.recursive_url_decode(cleaned)

        # HTML entity unescape (&quot; -> ", &lt; -> <, etc.)
        cleaned = html.unescape(cleaned)

        # Decode standard \xHH hex escapes if present
        def replace_hex(match):
            try:
                return chr(int(match.group(1), 16))
            except Exception:
                return match.group(0)

        cleaned = re.sub(r'\\x([0-9a-fA-F]{2})', replace_hex, cleaned)

        # Normalize multiple spaces / tabs / newlines to single space
        cleaned = re.sub(r'[\r\n\t]+', ' ', cleaned)
        cleaned = re.sub(r'\s{2,}', ' ', cleaned)

        return cleaned.strip()

    def serialize_request(
        self,
        method: str,
        path: str,
        query_params: Optional[str] = "",
        body: Optional[str] = "",
        headers: Optional[Dict[str, str]] = None
    ) -> str:
        """
        Serializes multi-part HTTP components into a structured text representation
        specifically formatted for Transformer tokenization.
        """
        clean_method = (method or "GET").upper().strip()
        clean_path = self.clean_text(path or "/")
        clean_params = self.clean_text(query_params or "")
        clean_body = self.clean_text(body or "")

        # Select high-signal headers only (User-Agent, Content-Type, Referer, Cookie, Authorization)
        header_str = ""
        if headers:
            relevance = ["user-agent", "content-type", "referer", "cookie", "x-forwarded-for"]
            selected_headers = []
            for k, v in headers.items():
                if k.lower() in relevance:
                    clean_hval = self.clean_text(str(v))
                    selected_headers.append(f"{k.lower()}={clean_hval}")
            if selected_headers:
                header_str = "; ".join(selected_headers)

        parts = [f"METHOD: {clean_method}", f"PATH: {clean_path}"]
        if clean_params:
            parts.append(f"PARAMS: {clean_params}")
        if header_str:
            parts.append(f"HEADERS: {header_str}")
        if clean_body:
            parts.append(f"BODY: {clean_body}")

        return " | ".join(parts)

# Singleton helper instance
normalizer = HTTPRequestNormalizer()
