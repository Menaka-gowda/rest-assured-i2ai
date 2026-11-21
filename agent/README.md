# agent/

**Owner:** Menaka (ME-2, ME-5, ME-6)  
**Handoffs:** H-05 to Moustafa (CLI integration interface), H-14 to Moustafa & Justin (trace evidence)

## Overview

The `ReconAgent` is an autonomous LLM tool-calling agent designed to conduct bounded, safe reconnaissance against MockBank on `http://127.0.0.1:8000`.

Instead of running a blind hardcoded script, the agent demonstrates **dynamic tool selection**:
1. Checks perimeter defensive headers.
2. Checks server banners and `/robots.txt`.
3. If `/api/chat` or conversational endpoints are detected in metadata, the agent dynamically invokes `ai_conversational_endpoint` to probe prompt leakage.
4. Audits login form CSRF/caching and tests simulated anomalous origin behavior.
5. Emits an execution trace recording thoughts, actions, and observations.

## CLI Integrator Interface (for Moustafa, `main.py`)

Using the agent from `main.py` is simple:

```python
from agent.agent import ReconAgent

# Initialize with target (enforces localhost only)
agent = ReconAgent(target_url="http://127.0.0.1:8000")

# Run autonomous plan
recon_data = agent.run()

# Access results (every item adheres strictly to docs/contract.md)
results_list = recon_data["results"]
execution_trace = recon_data["trace"]
```

## Safety Boundaries
- **Localhost Only:** Every check enforces `is_local_target(target_url)`. Any non-localhost URL is rejected immediately with an `error` status.
- **Contract Compliant:** All check functions return results generated via `make_result(...)` in `recon/base.py`.
- **Honest Labeling:** Simulated checks (such as origin IP header injection) report status `simulated`, never a false `pass`.
