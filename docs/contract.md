# Check Result Contract

This is the shared contract between recon checks, the defense test, the agent and
the report. **It is the source of truth.** If any other document (including the
team PDFs) disagrees with it, this file wins.

## The function

Every check is a plain Python function:

```python
def check_name(target_url: str) -> dict:
    ...
```

It takes the target URL and returns one result dict. Use `make_result(...)` from
`recon/base.py` to build it, so the shape is always right.

## Required fields

| Field | Type | Meaning |
|---|---|---|
| `check_name` | str | Name of the check, e.g. `security_headers` |
| `target` | str | The URL that was checked |
| `status` | str | One of the allowed status values below |
| `severity` | str | One of the allowed severity values below |
| `evidence` | str | One short human-readable sentence explaining the result |
| `raw_output` | dict | Machine-readable details (can be `{}`) |
| `timestamp` | str | ISO 8601 UTC, ending in `Z`, e.g. `2026-11-11T18:00:00Z` |

All seven fields are required. No field may be missing.

### `status`

One of: `pass`, `warn`, `fail`, `error`, `simulated`, `not_tested`

> **Note:** the team PDFs only list `pass`, `warn`, `fail` and `error`. The contract
> also allows `simulated` and `not_tested`. This file is the source of truth.

- `pass`: the check ran and found nothing wrong
- `warn`: partial or weak protection
- `fail`: the protection is missing
- `error`: the check could not run, or refused the target
- `simulated`: the condition was faked locally (e.g. spoofed headers), so the result is not real evidence
- `not_tested`: the check can't be meaningfully run on localhost

### `severity`

One of: `info`, `low`, `medium`, `high`

## Example result

```json
{
  "check_name": "security_headers",
  "target": "http://127.0.0.1:8000",
  "status": "warn",
  "severity": "low",
  "evidence": "Response is missing Content-Security-Policy.",
  "raw_output": {"header_present": false},
  "timestamp": "2026-11-11T18:00:00Z"
}
```

## Safety rules

1. **Localhost only.** Every check must call `is_local_target(target_url)` first.
   If the target is not `localhost` or `127.0.0.1`, the check sends no request
   and returns a result with `status: "error"`.
2. **No fake passes.** Anything that can't be meaningfully tested on localhost
   (real TLS, real geo, VPN or Tor routing) is reported as `simulated` or
   `not_tested`, never `pass`.

## Definitions

- **Agent:** the LLM program that decides which checks to run and calls them as tools.
- **Check:** one Python function that tests one thing and returns one result dict.
- **Tool:** a check as exposed to the agent (name, description, `target_url` input).
- **Report:** the one-page summary built from all the check results.
- **MockBank:** our tiny local test web app on `http://127.0.0.1:8000`. The only allowed target.

## Changing this contract

The schema is **frozen**. To change it:

1. Open one PR that edits only this file (plus `recon/base.py` if needed).
2. Post a heads-up in team chat before merging, so nobody is surprised.
