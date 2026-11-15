# AI Recon Aggregator

A grad class project. An AI agent picks and runs safe, read-only recon checks
against MockBank, a tiny test web app running on your own machine, and then
writes a one-page report of what it found.

## Safety rules

- **Localhost only.** The only target is MockBank on `http://127.0.0.1:8000`
  (or `localhost`). Every check must refuse any other target.
- **No real organizations.** Never point anything at a real website, company or service.
- **No real credentials.** Synthetic usernames and fake data only. Never commit secrets.
- **No client details.** This repo is public. Refer only to "the client". No names.
- **Read-only.** Checks observe. The one exception is a small, bounded
  failed-login test against MockBank (see `defense/`).
- Things that can't be tested on localhost (real TLS, real geo/VPN/Tor routing)
  are reported as `simulated` or `not_tested`, never `pass`.

## Setup

Needs Python 3.10 or newer.

```bash
python -m venv .venv
```

Activate it (Windows PowerShell: `.venv\Scripts\Activate.ps1`; macOS/Linux: `source .venv/bin/activate`), then:

```bash
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and fill in values locally (`.env` is gitignored):

```bash
cp .env.example .env
```

Run the tests:

```bash
python -m unittest discover -s tests -v
```

## Folder ownership

| Path | Owner | Purpose |
|---|---|---|
| `recon/` | Kidus | Read-only recon checks + shared helpers (`base.py`) |
| `defense/` | Moustafa | Bounded MockBank-only failed-login test |
| `agent/` | Menaka | LLM tool-calling agent |
| `report/` | Menaka | One-page report generation |
| `mockbank/` | Menaka | Tiny local test app |
| `tests/` | Moustafa | Tests and demo status |
| `docs/` | Justin (Kidus signs off technical criteria) | Documentation, contract, checklist |
| `main.py` | Moustafa | CLI entry point (placeholder for now) |

The result format every check must return is in [docs/contract.md](docs/contract.md).

## Team workflow

- One branch per person (e.g. `kidus/recon-headers`). Don't push straight to `main`.
- Small pull requests: one feature or fix each, so reviews are quick.
- After each work session, post a short update in the group chat: what you did,
  what's next, anything blocking you.
