"""
HTTP Request Serializer for Inference.
Formats incoming requests into tokenizable text representation.
"""

from typing import Dict, Any, Optional
from dataset_preparation.normalizer import normalizer

class RequestSerializer:
    @staticmethod
    def serialize_dict(data: Dict[str, Any]) -> str:
        method = data.get("method", "GET")
        path = data.get("path", "/")
        query_params = data.get("params") or data.get("query_params") or ""
        body = data.get("body") or ""
        headers = dict(data.get("headers") or {})
        if "user-agent" not in {k.lower(): v for k, v in headers.items()}:
            headers["user-agent"] = "Mozilla/5.0"

        # If body is dict/json, convert to string
        if isinstance(body, dict):
            import json
            body = json.dumps(body)

        return normalizer.serialize_request(
            method=method,
            path=path,
            query_params=query_params,
            body=body,
            headers=headers
        )

serializer = RequestSerializer()
