"""Deterministic internal fingerprints; no persistent device identity or state."""
import hashlib
import json

def fingerprint(*parts):
    value = json.dumps(parts, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(value.encode()).hexdigest()
