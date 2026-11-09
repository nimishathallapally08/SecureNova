# Project 3: Red Team

Run commands from this directory. The four scripts run one attack category and save JSON evidence under `results/<backend>/<run-id>/`.

```bash
.venv/bin/python run_attack1_indirect_injection.py --backend simulated
.venv/bin/python run_attack2_agent_spoofing.py --backend simulated
.venv/bin/python run_attack3_prompt_extraction.py --backend simulated
.venv/bin/python run_attack4_rag_poisoning.py --backend simulated
```

Project 3 indirect-injection runs always use the intentionally vulnerable synthetic-token setup. For a live Groq run:

```bash
.venv/bin/python run_attack1_indirect_injection.py --backend groq
```

The system context permits disclosure of only the synthetic lab token; this is not evidence of a real credential leak. There is no protected indirect-injection variant in Project 3.

Each result records the input prompt and document separately, the complete model response, requested tools, executed mock actions, and the kill chain. Attack 1 includes three document payloads; Attack 3 includes five extraction techniques and role elevation.

For Groq-backed Attack 3, the role-elevation case uses a deliberately vulnerable system context to elicit a textual admin claim. This is a demonstration of an unsafe claim only; no permissions, scopes, or tokens are changed, and live model output is not guaranteed.

To create the complete 11-case baseline used by Project 4, run:

```bash
.venv/bin/python run_lab.py --backend simulated
```

Attack-specific result files are partial and are not accepted as a full Project 4 baseline. The simulated backend makes no model requests. The `groq` backend sends synthetic lab prompts to Groq; all privileged actions remain local mocks.
