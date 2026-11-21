# mockbank/

**Owner:** Menaka (ME-1, ME-4)  
**Handoffs:** H-03 (to Kidus & Moustafa), H-11 (fixtures)

MockBank is a tiny, safe local test web app simulating a financial treasury portal. It runs strictly on `http://127.0.0.1:8000`. **It is the only target the project is permitted to test.**

## Quick Start (Zero External Dependencies)

Requires Python 3.10 or newer (uses Python's built-in `http.server`).

### Starting the Server
From the repository root:
```bash
python -m mockbank.server
```
or directly:
```bash
python mockbank/server.py
```

The server binds strictly to `127.0.0.1:8000` and displays:
```
[*] MockBank running at http://127.0.0.1:8000/
[*] Target bound to localhost only. Press Ctrl+C to terminate.
```

### Verifying It Works
Open `http://127.0.0.1:8000` in a browser, or run curl:
```bash
curl -i http://127.0.0.1:8000/health
```
Expected response:
```json
{"status": "healthy", "service": "mockbank-treasury-core", "version": "3.4.1", "target": "http://127.0.0.1:8000"}
```

## Available Endpoints

- `GET /` — Banking treasury login portal (contains deliberate header & form misconfigurations for recon testing).
- `GET /chat` — AI Assistant interactive web interface.
- `GET /health` — Simple JSON healthcheck for automated runner discovery.
- `GET /robots.txt` — Disallow directives exposing internal endpoints (`/admin/`, `/treasury-api/`, `/internal-docs/`).
- `POST /login` — Authentication endpoint with defensive rate-limiting (returns 401 for bad credentials; returns 429 lock after 5 attempts).
- `POST /api/chat` — AI support bot endpoint with prompt injection vulnerability.

## Controlled Fixtures
See [mockbank/fixtures/README.md](fixtures/README.md) and [mockbank/fixtures/expected_findings.json](fixtures/expected_findings.json) for the exact ground truth specification of planted vulnerabilities and test triggers.
