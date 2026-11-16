# MockBank Test Fixtures (ME-4 Specification)

**Owner:** Menaka (ME-4 Handoff H-11 to Kidus & Moustafa)

This folder contains the ground truth fixture specification (`expected_findings.json`) against which recon and defense checks are evaluated.

## Test Conditions & Expected Outcomes

| Check Name | Target Endpoint | Test Trigger | Expected Status | Severity | Expected Behavior |
|---|---|---|---|---|---|
| `security_headers` | `GET /` | Standard GET | `fail` | `medium` | Missing CSP, HSTS, and nosniff headers |
| `metadata_disclosure` | `GET /` & `GET /robots.txt` | Inspect response | `fail` | `medium` | Leaks Apache/2.4.41, PHP 8.0.12, and internal `/admin/`, `/treasury-api/` paths |
| `caching_and_csrf` | `GET /` | Inspect HTML form | `warn` | `medium` | Form action submits over plain HTTP; no CSRF token |
| `credential_dumping_throttling` | `POST /login` | > 5 failed POSTs | `pass` | `info` | Returns HTTP 429 Too Many Requests |
| `ai_assistant_prompt_leakage` | `POST /api/chat` | Send override prompt | `fail` | `high` | Leaks internal instructions and admin key |
| `anomalous_origin_challenge` | Any endpoint | Header `X-Forwarded-For: 198.51.100.99` | `simulated` | `low` | Returns HTTP 403 Forbidden |

## How to Run Verification Against Fixtures

1. Launch MockBank in one terminal:
   ```bash
   python -m mockbank.server
   ```
2. Run your recon tool against `http://127.0.0.1:8000`.
3. Compare check output with `expected_findings.json`.
