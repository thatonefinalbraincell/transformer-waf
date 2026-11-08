"""
Parser for the CSIC 2010 HTTP Dataset.
Extracts HTTP Method, Path, Query Parameters, Headers, and Body from raw HTTP captures.
"""

import re
from pathlib import Path
from typing import List, Dict, Any
from .normalizer import normalizer

class CSICParser:
    def __init__(self):
        self.request_separator = re.compile(r'\n\s*\n(?=[A-Z]{3,7}\s+)')

    def parse_raw_request(self, raw_block: str, default_label: int = 0, attack_type: str = "benign") -> Dict[str, Any]:
        """
        Parses a single raw HTTP request block.
        """
        lines = [line.strip('\r') for line in raw_block.strip().split('\n')]
        if not lines or not lines[0]:
            return {}

        # 1. Request Line: e.g. "POST /path/file.jsp?param=1 HTTP/1.1"
        request_line = lines[0].strip()
        parts = request_line.split()
        if len(parts) < 2:
            return {}

        method = parts[0].upper()
        full_path = parts[1]

        # Split path and query parameters
        if '?' in full_path:
            path, params = full_path.split('?', 1)
        else:
            path, params = full_path, ""

        # 2. Extract Headers and Body
        headers = {}
        body = ""
        is_body = False
        body_lines = []

        for line in lines[1:]:
            if is_body:
                body_lines.append(line)
            elif line.strip() == "":
                is_body = True
            elif ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        if body_lines:
            body = "\n".join(body_lines).strip()

        # 3. Classify attack subtype if label is malicious and not specified
        if default_label == 1 and attack_type == "malicious":
            combined_search = f"{params} {body}".lower()
            if any(k in combined_search for k in ["select", "union", "insert", "--", "' or", "drop table"]):
                attack_type = "sqli"
            elif any(k in combined_search for k in ["<script", "alert(", "<img", "javascript:"]):
                attack_type = "xss"
            elif any(k in combined_search for k in ["../", "..\\", "etc/passwd"]):
                attack_type = "path_traversal"
            elif any(k in combined_search for k in [";", "|", "&&", "cat ", "whoami"]):
                attack_type = "cmdi"
            else:
                attack_type = "parameter_tampering"

        serialized = normalizer.serialize_request(
            method=method,
            path=path,
            query_params=params,
            body=body,
            headers=headers
        )

        return {
            "method": method,
            "path": path,
            "params": params,
            "body": body,
            "normalized_text": serialized,
            "label": default_label,
            "attack_type": attack_type,
            "source": "csic_2010"
        }

    def parse_file(self, file_path: Path, label: int, attack_type: str = "benign") -> List[Dict[str, Any]]:
        """
        Parses a CSIC 2010 text file containing multiple requests.
        """
        if not file_path.exists():
            return []

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        blocks = self.request_separator.split(content)
        parsed_records = []
        for block in blocks:
            rec = self.parse_raw_request(block, default_label=label, attack_type=attack_type)
            if rec:
                parsed_records.append(rec)

        return parsed_records

csic_parser = CSICParser()
