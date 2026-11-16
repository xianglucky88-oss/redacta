"""Composable, deterministic transformations. Keys never leave this object."""
import hashlib
import hmac
import math
import re
from datetime import date, timedelta
from .policy import canonical


EMAIL = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")
PHONE = re.compile(r"(?<!\w)\+?\d[\d ()-]{7,}\d(?!\w)")


def classify(row):
    """Heuristic hints only; these hints never auto-authorize publication."""
    hints = {}
    for key, value in row.items():
        name, sample = key.casefold(), str(value or "")
        if "email" in name or EMAIL.search(sample):
            hints[key] = "email"
        elif any(p in name for p in ("phone", "mobile")) or PHONE.search(sample):
            hints[key] = "phone"
        elif any(p in name for p in ("address", "name", "identity")):
            hints[key] = "direct_identifier"
        else:
            hints[key] = "unclassified"
    return hints


class Transformer:
    def __init__(self, key, extensions=None):
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("provide at least 32 bytes of key material")
        self._key = key
        self.extensions = extensions or {}

    def digest(self, namespace, value):
        message = canonical([namespace, value]).encode()
        return hmac.new(self._key, message, hashlib.sha256).hexdigest()

    def apply(self, value, rule, subject=None):
        op = rule["op"]
        if value is None:
            return None
        if op == "keep":
            return value
        if op == "token":
            # String identifiers use the same normalization on both sides of a join.
            normalized = value.strip().casefold() if isinstance(value, str) else value
            return self.digest("token:" + rule["namespace"], normalized)
        if op == "mask":
            return rule.get("replacement", "[REDACTED]")
        if op == "scrub":
            return PHONE.sub("[PHONE]", EMAIL.sub("[EMAIL]", str(value)))
        if op == "bucket":
            if isinstance(value, bool):
                raise ValueError("boolean is not an amount")
            number = float(value)
            if not math.isfinite(number):
                raise ValueError("non-finite amount")
            width = rule["width"]
            lower = math.floor(number / width) * width
            return f"[{lower:g},{lower + width:g})"
        if op == "date_shift":
            if subject in (None, ""):
                raise ValueError("missing date shift subject")
            window = rule.get("days", 30)
            normalized = subject.strip().casefold() if isinstance(subject, str) else subject
            offset = int(self.digest("date:" + rule.get("namespace", "subject"), normalized), 16) % (2 * window + 1) - window
            return (date.fromisoformat(value) + timedelta(days=offset)).isoformat()
        if op in self.extensions:
            return self.extensions[op](value, rule, subject)
        raise ValueError(f"unsupported transformation: {op}")
