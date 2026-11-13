# Project 4: Blue Team

Project 4 compares the Project 3 baseline with hardened controls: NeMo
Guardrails input/output filtering, Ed25519 agent identity, backend scope
enforcement, anomaly detection, and reporting. All privileged actions are
in-memory mocks. Run commands from this directory.

## Setup

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Local controls

Replay the attack fixtures through NeMo input/output rails:

```bash
.venv/bin/python -m app.guardrails

.venv/bin/python -m app.evidence identity
.venv/bin/python -m app.evidence detection

.venv/bin/python run_lab.py compare --backend simulated \
  --baseline ../03-red-team/results/simulated/<run-id>/results.json \
  --show_prompt
```

The evidence commands write unique records below `results/`. A comparison
requires the complete 11-case Project 3 export, produced by
`03-red-team/run_lab.py --backend simulated`; a single-attack export is not a
valid comparison baseline. Add `--show_prompt` to print each test case's
document and user-input payload as it is evaluated. The prompt and document
are also saved in each case record in `results.json`. To generate a fresh
baseline and hardened comparison without importing Project 3 evidence, run:

```bash
.venv/bin/python run_lab.py compare --backend simulated
```

Other entry-point operations:

```bash
.venv/bin/python run_lab.py baseline --backend simulated
.venv/bin/python run_lab.py detect <events.json> --output <alerts.json>
```

## Auth0 operations (opt-in)

Auth0 operations require a disposable test tenant and local `.env` settings.
They are deliberately gated by `--confirm-test-tenant`:

```bash
.venv/bin/python -m app.auth0 verify --confirm-test-tenant
.venv/bin/python -m app.auth0 apply --confirm-test-tenant
.venv/bin/python -m app.auth0 deploy-action --confirm-test-tenant
.venv/bin/python -m app.auth0 rotation --confirm-test-tenant
```

`verify` reads settings; `apply` changes token lifetimes and refresh-token
rotation; `deploy-action` deploys and binds the risk-block Action; `rotation`
consumes a refresh token and intentionally replays it. Do not use a production
tenant or user for these operations.

To obtain the refresh token for the rotation probe, run the PKCE login from
Project 2 with capture explicitly enabled. After sign-in, the token is saved
to the ignored, mode-`0600` `02-iam-design/.refresh_token` file and is never
printed:

```bash
cd ../02-iam-design
CAPTURE_REFRESH_TOKEN=1 .venv/bin/python auth_flows/pkce_login.py
```

Then, from `04-blue-team`, run the probe; it reads that file directly and does
not print the token:

```bash
.venv/bin/python -m app.auth0 rotation --confirm-test-tenant
```

The rotation probe consumes the old token and its replay can revoke the token
family. Use a disposable test user. The included post-login Action blocks
users whose `app_metadata.securenova_risk` is `high` or whose
`app_metadata.securenova_risk_score` is at least 80. No Auth0 command is run by
the local simulation.

## Main files

- `app/application.py` — baseline/hardened orchestration and in-memory tools.
- `app/identity.py` — signed message envelopes and replay/expiry checks.
- `app/guardrails.py` and `config/rails/` — recorded-input and output-rail
  replay using NeMo.
- `app/detection.py` — timestamped event rules and deterministic replay.
- `app/auth0.py` and `actions/riskblock.js` — opt-in tenant hardening and
  risk-based login action.
- `app/reporting.py` — comparison metrics and findings.

Evidence and generated reports are written under `results/`; do not treat
simulated or synthetic-event results as production telemetry.
