# recon/

**Owner:** Kidus (KI-2 helpers, KI-3 checks)

Read-only recon checks against the local MockBank app. Each check is a function
`check_name(target_url: str) -> dict` that follows [docs/contract.md](../docs/contract.md).
Shared helpers live in `base.py` (`make_result`, `validate_result`, `is_local_target`).

## Callable checks (KI-3)

| Function | Module | Expected on MockBank |
|---|---|---|
| `check_security_headers` | `recon.checks` | `fail` (missing CSP / HSTS / nosniff) |
| `check_metadata_disclosure` | `recon.checks` | `fail` (leaky banners + robots paths) |
| `check_caching_csrf` | `recon.checks` | `warn` (plain HTTP login, no CSRF token) |

Import for CLI / agent wiring:

```python
from recon import RECON_CHECKS, check_security_headers

result = check_security_headers("http://127.0.0.1:8000")
# or: RECON_CHECKS["security_headers"](url)
```

MockBank must be running (`python -m mockbank.server`). Defense throttling is
owned by Moustafa under `defense/`, not here. KI-5 will expand this catalog.
