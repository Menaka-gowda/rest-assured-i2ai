"""Read-only recon checks against MockBank (KI-3).

Each function is check_name(target_url: str) -> dict and follows docs/contract.md.
Owner: Kidus. Defense throttling stays in defense/ (Moustafa).
"""

import re
import urllib.error
import urllib.request
from urllib.parse import urljoin

from recon.base import is_local_target, make_result

USER_AGENT = "AI-Recon-Aggregator/1.0"


def _fetch(url: str, timeout: float = 5):
    """GET url and return (headers_dict_lower, body_text). Raises on HTTP/network errors."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.read().decode("utf-8", errors="ignore")
    return headers, body


def check_security_headers(target_url: str) -> dict:
    """Audit HTTP response headers for CSP, HSTS, and X-Content-Type-Options."""
    if not is_local_target(target_url):
        return make_result(
            "security_headers",
            target_url,
            "error",
            "high",
            f"Safety block: Target '{target_url}' is not on localhost.",
        )

    try:
        headers, _ = _fetch(target_url)
    except Exception as e:
        return make_result(
            "security_headers",
            target_url,
            "error",
            "medium",
            f"Failed to connect to target: {e}",
        )

    missing = []
    if "content-security-policy" not in headers:
        missing.append("Content-Security-Policy")
    if "strict-transport-security" not in headers:
        missing.append("Strict-Transport-Security (HSTS)")
    if "x-content-type-options" not in headers:
        missing.append("X-Content-Type-Options")

    if missing:
        status = "fail" if len(missing) >= 2 else "warn"
        evidence = f"Target is missing critical security headers: {', '.join(missing)}."
        severity = "medium"
    else:
        status = "pass"
        evidence = "All standard defensive security headers are configured."
        severity = "info"

    return make_result(
        "security_headers",
        target_url,
        status,
        severity,
        evidence,
        raw_output={
            "missing_headers": missing,
            "headers_received": list(headers.keys()),
        },
    )


def check_metadata_disclosure(target_url: str) -> dict:
    """Inspect server banners, X-Powered-By, robots.txt, and AI assistant cues."""
    if not is_local_target(target_url):
        return make_result(
            "metadata_disclosure",
            target_url,
            "error",
            "high",
            f"Safety block: Target '{target_url}' is not on localhost.",
        )

    disclosures = []
    raw = {}
    try:
        headers, html = _fetch(target_url)

        if "server" in headers:
            disclosures.append(
                f"Server header exposes software banner: '{headers['server']}'"
            )
            raw["server"] = headers["server"]
        if "x-powered-by" in headers:
            disclosures.append(
                f"X-Powered-By exposes backend runtime: '{headers['x-powered-by']}'"
            )
            raw["x_powered_by"] = headers["x-powered-by"]

        robots_url = urljoin(target_url, "/robots.txt")
        try:
            _, robots_text = _fetch(robots_url, timeout=3)
            disallowed = re.findall(r"Disallow:\s*(/\S*)", robots_text)
            if disallowed:
                disclosures.append(
                    f"robots.txt disallows and enumerates internal paths: {disallowed}"
                )
                raw["disallowed_paths"] = disallowed
        except Exception:
            pass

        # Full-page scan plus /chat follow so the AI cue is not truncated away.
        ai_cues = ("/api/chat", "Virtual AI Assistant", "TreasuryBot")
        if any(cue in html for cue in ai_cues) or 'href="/chat"' in html:
            raw["discovered_ai_endpoint"] = "/api/chat"
            if 'href="/chat"' in html and "TreasuryBot" not in html:
                try:
                    _, chat_html = _fetch(urljoin(target_url, "/chat"), timeout=3)
                    if any(cue in chat_html for cue in ai_cues):
                        raw["discovered_ai_page"] = "/chat"
                except Exception:
                    pass

    except Exception as e:
        return make_result(
            "metadata_disclosure",
            target_url,
            "error",
            "medium",
            f"Error inspecting metadata: {e}",
        )

    if disclosures:
        return make_result(
            "metadata_disclosure",
            target_url,
            "fail",
            "medium",
            " ".join(disclosures),
            raw_output=raw,
        )
    return make_result(
        "metadata_disclosure",
        target_url,
        "pass",
        "info",
        "No verbose server banners or exposed robots paths detected.",
        raw_output=raw,
    )


def check_caching_csrf(target_url: str) -> dict:
    """Evaluate login form submission security and anti-CSRF token presence."""
    if not is_local_target(target_url):
        return make_result(
            "caching_and_csrf",
            target_url,
            "error",
            "high",
            f"Safety block: Target '{target_url}' is not on localhost.",
        )

    try:
        _, html = _fetch(target_url)
    except Exception as e:
        return make_result(
            "caching_and_csrf",
            target_url,
            "error",
            "medium",
            f"Error accessing login surface: {e}",
        )

    issues = []
    if "<form" in html:
        if 'action="/login"' in html or 'action="http://' in html:
            issues.append("Login form action submits over plain unencrypted HTTP.")
        if not re.search(r'name=["\']csrf[-_]?token["\']', html, re.IGNORECASE):
            issues.append("No anti-CSRF token verification field found in login form.")

    if issues:
        return make_result(
            "caching_and_csrf",
            target_url,
            "warn",
            "medium",
            " ".join(issues),
            raw_output={"issues": issues},
        )
    return make_result(
        "caching_and_csrf",
        target_url,
        "pass",
        "info",
        "Form submits securely with anti-CSRF protection.",
        raw_output={},
    )


# Callable catalog for CLI / agent wiring (KI-3)
RECON_CHECKS = {
    "security_headers": check_security_headers,
    "metadata_disclosure": check_metadata_disclosure,
    "caching_and_csrf": check_caching_csrf,
}
