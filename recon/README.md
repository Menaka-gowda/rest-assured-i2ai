# recon/

**Owner:** Kidus

Read-only recon checks against the local MockBank app. Each check is a function
`check_name(target_url: str) -> dict` that follows [docs/contract.md](../docs/contract.md).
Shared helpers live in `base.py` (`make_result`, `validate_result`, `is_local_target`).
