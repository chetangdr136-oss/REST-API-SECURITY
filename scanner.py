"""Safe, low-impact REST API security checks for authorized targets."""
from __future__ import annotations
import argparse
import json
import time
from dataclasses import asdict, dataclass
from typing import Optional
from urllib.parse import urlparse, urljoin

import requests

@dataclass
class Finding:
    check: str
    severity: str
    status: str
    evidence: str
    recommendation: str

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    if not parsed.netloc:
        raise ValueError("Please enter a valid URL, such as http://127.0.0.1:5001")
    return url.rstrip("/")

def request(session, method, url, **kwargs):
    try:
        return session.request(method, url, timeout=5, allow_redirects=True, **kwargs)
    except requests.RequestException as exc:
        return exc

def assess(base_url: str, token: Optional[str] = None, burst_count: int = 5):
    base_url = normalize_url(base_url)
    session = requests.Session()
    findings = []
    headers = {"User-Agent": "Educational-REST-API-Security-Assessment/1.0"}

    # Baseline request
    response = request(session, "GET", base_url + "/", headers=headers)
    if isinstance(response, Exception):
        return {
            "target": base_url,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "findings": [asdict(Finding(
                "Connectivity", "High", "Error", str(response),
                "Confirm the API is running and that the URL is reachable."
            ))]
        }

    # Security headers
    expected_headers = {
        "Strict-Transport-Security": "Use HTTPS and configure HSTS on production HTTPS services.",
        "X-Content-Type-Options": "Set X-Content-Type-Options: nosniff.",
        "Content-Security-Policy": "Define a suitable Content-Security-Policy where browser content is served.",
        "Cache-Control": "Apply suitable cache controls to sensitive API responses."
    }
    for header, recommendation in expected_headers.items():
        if header.lower() not in {h.lower() for h in response.headers}:
            severity = "Medium" if header != "Strict-Transport-Security" else "Low"
            findings.append(Finding(
                "Security headers", severity, "Potential issue",
                f"Response did not include {header}.",
                recommendation
            ))

    # CORS check: send a benign cross-origin Origin header and inspect response.
    cors = request(session, "GET", base_url + "/", headers={**headers, "Origin": "https://example-attacker.invalid"})
    if not isinstance(cors, Exception):
        allow_origin = cors.headers.get("Access-Control-Allow-Origin", "")
        allow_credentials = cors.headers.get("Access-Control-Allow-Credentials", "").lower()
        if allow_origin == "*" and allow_credentials == "true":
            findings.append(Finding(
                "CORS configuration", "High", "Potential issue",
                "Wildcard Access-Control-Allow-Origin was combined with credentials enabled.",
                "Allow only trusted origins. Never combine wildcard origins with credentialed access."
            ))
        elif allow_origin == "*":
            findings.append(Finding(
                "CORS configuration", "Low", "Review",
                "The API returned Access-Control-Allow-Origin: *.",
                "Confirm that public cross-origin access is intended; restrict origins for sensitive APIs."
            ))
        else:
            findings.append(Finding(
                "CORS configuration", "Info", "No obvious issue",
                f"Access-Control-Allow-Origin: {allow_origin or '(not present)'}",
                "Keep the allowlist limited to trusted origins."
            ))

    # Authentication comparison on a conventional protected path.
    protected_url = base_url + "/api/profile"
    unauth = request(session, "GET", protected_url, headers=headers)
    auth_headers = {**headers}
    if token:
        auth_headers["Authorization"] = "Bearer " + token
    auth = request(session, "GET", protected_url, headers=auth_headers) if token else None

    if not isinstance(unauth, Exception):
        if unauth.status_code == 200:
            findings.append(Finding(
                "Authentication enforcement", "High", "Potential issue",
                f"GET /api/profile returned HTTP 200 without an Authorization header.",
                "Require authentication on private endpoints and verify identity server-side."
            ))
        elif unauth.status_code in (401, 403):
            findings.append(Finding(
                "Authentication enforcement", "Info", "Pass",
                f"Unauthenticated request returned HTTP {unauth.status_code}.",
                "Continue checking authorization for each user role and resource."
            ))
        else:
            findings.append(Finding(
                "Authentication enforcement", "Info", "Inconclusive",
                f"Unauthenticated request returned HTTP {unauth.status_code}.",
                "Confirm the endpoint and its expected authentication policy manually."
            ))
    if token and auth is not None and not isinstance(auth, Exception):
        findings.append(Finding(
            "Bearer token comparison", "Info", "Observed",
            f"With supplied test token, /api/profile returned HTTP {auth.status_code}.",
            "Verify token signature, issuer, audience, expiry, scopes, and role checks."
        ))

    # Harmless input validation probe. It does not use exploit strings.
    probe_url = base_url + "/api/search"
    probe = request(session, "GET", probe_url, headers=headers, params={"q": ["<script>"]})
    if not isinstance(probe, Exception):
        if probe.status_code >= 500:
            findings.append(Finding(
                "Input validation", "Medium", "Potential issue",
                f"A simple unexpected input produced HTTP {probe.status_code}.",
                "Validate and constrain input types/lengths; return safe 4xx errors instead of server errors."
            ))
        else:
            findings.append(Finding(
                "Input validation", "Info", "Basic probe completed",
                f"Unexpected input produced HTTP {probe.status_code}. This alone does not prove safe handling.",
                "Use schema validation, output encoding, parameterized queries, and endpoint-specific tests."
            ))

    # Small request burst to observe rate-limit signals; intentionally not a load test.
    statuses = []
    for _ in range(max(1, min(burst_count, 8))):
        r = request(session, "GET", base_url + "/health", headers=headers)
        if isinstance(r, Exception):
            statuses.append("request error")
        else:
            statuses.append(str(r.status_code))
        time.sleep(0.08)
    if "429" in statuses:
        findings.append(Finding(
            "Rate limiting", "Info", "Signal detected",
            f"HTTP 429 appeared in a small burst: {', '.join(statuses)}.",
            "Confirm limits are appropriate per user, IP, and sensitive operation."
        ))
    else:
        findings.append(Finding(
            "Rate limiting", "Low", "Not detected by small probe",
            f"No HTTP 429 response in {len(statuses)} low-volume requests: {', '.join(statuses)}.",
            "Consider per-client rate limits, burst controls, and monitoring. This small test is not conclusive."
        ))

    return {
        "target": base_url,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "findings": [asdict(f) for f in findings]
    }

def main():
    parser = argparse.ArgumentParser(description="Educational REST API security assessment")
    parser.add_argument("url", help="Base URL of an API you own or are authorized to test")
    parser.add_argument("--token", help="Optional authorized Bearer test token")
    parser.add_argument("--burst", type=int, default=5, help="Small rate-limit observation count (1-8)")
    parser.add_argument("--output", default="assessment.json", help="JSON output file")
    args = parser.parse_args()
    result = assess(args.url, args.token, args.burst)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(json.dumps(result, indent=2))
    print(f"\nSaved results to {args.output}")

if __name__ == "__main__":
    main()
