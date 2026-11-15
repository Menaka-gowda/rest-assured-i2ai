"""Shared helpers for recon and defense checks. See docs/contract.md.

Standard library only. Works on Python 3.10+.
"""

from datetime import datetime, timezone
from urllib.parse import urlparse

REQUIRED_FIELDS = (
    "check_name",
    "target",
    "status",
    "severity",
    "evidence",
    "raw_output",
    "timestamp",
)
ALLOWED_STATUS = ("pass", "warn", "fail", "error", "simulated", "not_tested")
ALLOWED_SEVERITY = ("info", "low", "medium", "high")
LOCAL_HOSTS = ("localhost", "127.0.0.1")


def make_result(check_name, target, status, severity, evidence, raw_output=None):
    """Build a contract-shaped result dict with a UTC timestamp, then validate it."""
    result = {
        "check_name": check_name,
        "target": target,
        "status": status,
        "severity": severity,
        "evidence": evidence,
        "raw_output": raw_output if raw_output is not None else {},
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    validate_result(result)
    return result


def validate_result(result):
    """Raise ValueError with a clear message if result breaks the contract."""
    if not isinstance(result, dict):
        raise ValueError(f"result must be a dict, got {type(result).__name__}")

    missing = [f for f in REQUIRED_FIELDS if f not in result]
    if missing:
        raise ValueError(f"result is missing required field(s): {', '.join(missing)}")

    for field in ("check_name", "target", "evidence"):
        if not isinstance(result[field], str) or not result[field].strip():
            raise ValueError(f"'{field}' must be a non-empty string")

    if result["status"] not in ALLOWED_STATUS:
        raise ValueError(
            f"invalid status {result['status']!r}; allowed: {', '.join(ALLOWED_STATUS)}"
        )
    if result["severity"] not in ALLOWED_SEVERITY:
        raise ValueError(
            f"invalid severity {result['severity']!r}; allowed: {', '.join(ALLOWED_SEVERITY)}"
        )
    if not isinstance(result["raw_output"], dict):
        raise ValueError("'raw_output' must be a dict")

    ts = result["timestamp"]
    if not isinstance(ts, str) or not ts.endswith("Z"):
        raise ValueError(
            f"invalid timestamp {ts!r}; must be ISO 8601 UTC ending in 'Z', "
            "e.g. 2026-11-11T18:00:00Z"
        )
    try:
        # Python 3.10's fromisoformat does not accept 'Z', so swap it first.
        datetime.fromisoformat(ts[:-1] + "+00:00")
    except ValueError:
        raise ValueError(f"invalid timestamp {ts!r}; not valid ISO 8601") from None


def is_local_target(url):
    """Return True only for http(s) URLs whose host is localhost or 127.0.0.1."""
    if not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url.strip())
        host = parsed.hostname
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    if parsed.username is not None or parsed.password is not None:
        return False
    return host in LOCAL_HOSTS
