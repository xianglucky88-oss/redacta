import hashlib
import json
import math
import re


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


class Policy:
    """Closed schema: every input field must have an explicit release decision."""
    OPERATIONS = {"keep", "drop", "token", "mask", "bucket", "date_shift", "scrub"}

    def __init__(self, document, operations=()):
        self._document = json.loads(canonical(document))
        if not isinstance(document.get("version"), str) or not document["version"]:
            raise ValueError("policy version is required")
        if not isinstance(document.get("tables"), dict) or not document["tables"]:
            raise ValueError("policy tables are required")
        for table, spec in document["tables"].items():
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", table):
                raise ValueError("unsafe table name")
            if not isinstance(spec.get("fields"), dict) or not spec["fields"]:
                raise ValueError("each table needs field rules")
            k = spec.get("k", 1)
            if type(k) is not int or k < 1:
                raise ValueError("k must be a positive integer")
            quasi = spec.get("quasi", [])
            if not isinstance(quasi, list) or len(set(quasi)) != len(quasi):
                raise ValueError("quasi identifiers must be a unique field list")
            if k > 1 and not quasi:
                raise ValueError("k suppression requires quasi identifiers")
            for field, rule in spec["fields"].items():
                if not isinstance(field, str) or not isinstance(rule, dict) or rule.get("op") not in self.OPERATIONS | set(operations):
                    raise ValueError("invalid field rule")
                if rule["op"] == "token" and not rule.get("namespace"):
                    raise ValueError("token rule requires a shared namespace")
                if rule["op"] == "bucket":
                    width = rule.get("width")
                    if isinstance(width, bool) or not isinstance(width, (int, float)) or not math.isfinite(width) or width <= 0:
                        raise ValueError("bucket width must be finite and positive")
                if rule["op"] == "date_shift":
                    if spec.get("subject") not in spec["fields"]:
                        raise ValueError("date shifting requires a declared subject field")
                    if type(rule.get("days", 30)) is not int or rule.get("days", 30) < 1:
                        raise ValueError("date shift days must be positive")
            for field in quasi:
                if field not in spec["fields"] or spec["fields"][field]["op"] == "drop":
                    raise ValueError("quasi identifier must be released")
            if "links" in spec and not isinstance(spec["links"], list):
                raise ValueError("links must be a list")
        for table, spec in document["tables"].items():
            for link in spec.get("links", []):
                target = document["tables"].get(link.get("table"), {})
                local = spec["fields"].get(link.get("field"), {})
                remote = target.get("fields", {}).get(link.get("target"), {})
                if local.get("op") != "token" or remote.get("op") != "token" or local.get("namespace") != remote.get("namespace"):
                    raise ValueError("linked fields require the same token namespace")
        self.digest = hashlib.sha256(canonical(self._document).encode()).hexdigest()

    @property
    def document(self):
        return json.loads(canonical(self._document))
