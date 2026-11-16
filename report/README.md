# report/

**Owner:** Menaka (ME-3, ME-5, ME-6)  
**Handoffs:** H-14 to Moustafa & Justin (report generator & sample report evidence)

## Overview

The `report/` package compiles contract-shaped check result dicts into clean, executive-ready Markdown and HTML summaries.

Per **ME-6**, the generator explicitly distinguishes **direct observations** (concrete facts from HTTP responses) from **analytical inferences** (threat potential), avoiding speculative or exaggerated security claims.

## Usage in CLI (`main.py`)

```python
from report.generator import save_reports

# Given check results from the agent or runner
results = agent_data["results"]

# Generate and save both sample_report.md and sample_report.html
md_file, html_file = save_reports(target_url="http://127.0.0.1:8000", results=results, output_dir="report")
print(f"Reports saved to {md_file} and {html_file}")
```

## Generated Artifacts
- `sample_report.md`: Clean, GitHub-formatted Markdown executive summary.
- `sample_report.html`: Self-contained, responsive HTML report with status color-coding.
