# SecureNova

SecureNova is a project portfolio for identity security in an AI chatbot
environment. It moves from threat modeling and identity design to controlled
red-team exercises, defensive controls, and policy/compliance documentation.

## Projects

| Project | Focus | Documentation |
|---|---|---|
| 01 — Threat Model | Identity inventory, STRIDE analysis, attack trees, risk register, and MITRE ATLAS mapping | [Project 1 README](./01-threat-model/README.md) · [Project report](./01-threat-model/Project1.pdf) |
| 02 — IAM Design | Auth0 identity, scoped API access, PKCE login, and token rotation | [Project 2 README](./02-iam-design/README.md) · [Project report](./02-iam-design/Project2.pdf) |
| 03 — Red Team | Synthetic attack cases and vulnerable-baseline evidence | [Project 3 README](./03-red-team/README.md) |
| 04 — Blue Team | Guardrails, signed agent identity, detection, and before/after comparison | [Project 4 README](./04-blue-team/README.md) |
| 05 — Policy | AI identity security policy and compliance mapping | [Project 5 README](./05-policy/README.md) |

The projects are arranged in a typical assessment sequence: use Project 1 to
identify threats, Project 2 to model identity controls, Project 3 to exercise
attack scenarios, Project 4 to evaluate defenses against the same cases, and
Project 5 to document governance requirements.

## Run the offline red/blue-team workflow

The simulation makes no model requests and all privileged actions are local
in-memory mocks. Create a virtual environment and install dependencies for
each code project separately.

First, generate the full Project 3 baseline:

```bash
cd 03-red-team
python -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python run_lab.py --backend simulated
```

The command prints the generated run directory. Use its `results.json` as the
input to Project 4:

```bash
cd ../04-blue-team
python -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python run_lab.py compare --backend simulated \
  --baseline ../03-red-team/results/simulated/<run-id>/results.json
```

Replace `<run-id>` with the directory name printed by the Project 3 run.
Project 4 creates comparison reports and evidence under its `results/`
directory. See each project README for individual attack runs, Groq-backed
experiments, and the opt-in Auth0 operations.

## Safety and evidence scope

- Use only the synthetic fixtures and disposable test tenants described in
  the project documentation.
- Groq-backed runs send synthetic prompts to an external model provider;
  simulation mode does not.
- Mock tool actions never modify real accounts or issue real refunds.
- Results are demonstrations of the included lab behavior, not proof of
  production security or observed production incidents.
- Never commit credentials, refresh tokens, or real user data.
