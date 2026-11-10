# Project 3: Red Team

Project 3 runs controlled adversarial cases against an intentionally
vulnerable baseline. All privileged actions are local in-memory mocks; only
the optional Groq backend makes external model requests. Run commands from
this directory.

## Setup

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt
```

For the deterministic simulation, no API key or network access is needed:

```bash
.venv/bin/python run_attack1_indirect_injection.py --backend simulated
.venv/bin/python run_attack2_agent_spoofing.py --backend simulated
.venv/bin/python run_attack3_prompt_extraction.py --backend simulated
.venv/bin/python run_attack4_rag_poisoning.py --backend simulated
```

The four scripts select an attack family and save JSON evidence under
`results/<backend>/<run-id>/`. `run_lab.py` runs all 11 attack cases; the
attack-specific scripts produce partial runs.

Project 3 indirect-injection runs always use the intentionally vulnerable synthetic-token setup. For a live Groq run:

```bash
.venv/bin/python run_attack1_indirect_injection.py --backend groq
```

For Groq-backed runs, set `GROQ_API_KEY` in the shell or in an untracked
`.env` file in this directory. `GROQ_MODEL` is optional; the adapter has a
default model.

The system context permits disclosure of only the synthetic lab token; this is not evidence of a real credential leak. There is no protected indirect-injection variant in Project 3.

Each result records the input prompt and document separately, the complete model response, requested tools, executed mock actions, and the kill chain. Attack 1 includes three document payloads; Attack 3 includes five extraction techniques and role elevation.

For Groq-backed Attack 3, the role-elevation case uses a deliberately vulnerable system context to elicit a textual admin claim. This is a demonstration of an unsafe claim only; no permissions, scopes, or tokens are changed, and live model output is not guaranteed.

To create the complete 11-case baseline used by Project 4, run:

```bash
.venv/bin/python run_lab.py --backend simulated
```

Attack-specific result files are partial and are not accepted as a full Project 4 baseline. The simulated backend makes no model requests. The `groq` backend sends synthetic lab prompts to Groq; all privileged actions remain local mocks.

## Main files

- `app/fixtures.py` — shared synthetic prompts, documents, and case metadata.
- `app/models.py` — deterministic simulated model and optional Groq adapter.
- `app/application.py` — baseline execution and in-memory mock action ledger.
- `run_lab.py` — run selection, evidence manifest, and export for Project 4.
- `show_result.py` — display one completed case without making a model request.

Treat Groq output as unpredictable live model output, not a reproducible
security guarantee. Never replace the synthetic fixtures or local mock
targets with real credentials, accounts, or privileged tools.
