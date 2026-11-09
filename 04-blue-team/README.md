# Project 4: Blue Team

Run commands from this directory. The controls are available independently:

```bash
# Replay every Project 3 fixture through NeMo input/output rails
.venv/bin/python -m app.guardrails

# Generate standalone Ed25519 or anomaly-detection evidence
.venv/bin/python -m app.evidence identity
.venv/bin/python -m app.evidence detection

# Compare a complete Project 3 baseline with the hardened simulation
.venv/bin/python run_lab.py compare --backend simulated \
	--baseline ../03-red-team/results/simulated/<run-id>/results.json
```

The guardrail replay includes all attack fixtures and the ordinary-user control. Evidence is written under `results/`; the comparison requires the full 11-case output from `03-red-team/run_lab.py`, not a single-attack export.

Auth0 operations are opt-in and must use a disposable test tenant with local `.env` values:

```bash
.venv/bin/python -m app.auth0 verify --confirm-test-tenant
.venv/bin/python -m app.auth0 apply --confirm-test-tenant
.venv/bin/python -m app.auth0 deploy-action --confirm-test-tenant
.venv/bin/python -m app.auth0 rotation --confirm-test-tenant
```

To obtain the refresh token for the rotation probe, run the PKCE login from `02-iam-design` with capture explicitly enabled. After completing sign-in, the token is stored in the ignored, mode-`0600` `02-iam-design/.refresh_token` file and is never printed:

```bash
cd ../02-iam-design
CAPTURE_REFRESH_TOKEN=1 python auth_flows/pkce_login.py
```

Then, from `04-blue-team`, run the probe; it reads that file directly and does not print the token:

```bash
.venv/bin/python -m app.auth0 rotation --confirm-test-tenant
```

The rotation probe consumes the old token and its replay can revoke the token family. Use a disposable test user. The included post-login Action blocks users whose `app_metadata.securenova_risk` is `high` or whose `app_metadata.securenova_risk_score` is at least 80. No Auth0 command is run by the local simulation.
