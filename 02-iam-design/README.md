# Project 2: IAM Design

An Auth0-backed identity layer for SecureNova. The project demonstrates a
human-user login flow, machine-to-machine access, scoped API authorization,
and token rotation. Its consolidated report is [Project2.pdf](./Project2.pdf).

## Components

- `backend/app.py` — Flask API that validates RS256 access tokens against
  Auth0's JWKS, checks issuer and audience, and enforces `read:ai-data` on
  `POST /chat` and `write:admin` on `GET /admin`.
- `auth_flows/pkce_login.py` — interactive Authorization Code + PKCE login
  client. It exercises both API endpoints and can optionally capture a
  refresh token for the Project 4 rotation probe.
- `auth_flows/rotation_demo.py` — obtains a short-lived M2M access token,
  calls `/chat`, waits for expiry, and confirms that replay is rejected.
- `actions/add-agent-id-claim.js` — Auth0 post-login Action that adds a
  namespaced `agent_id` claim to ID and access tokens.
- `.env.example` — local configuration template. Copy it to `.env` in this
  directory and fill in credentials from a test tenant. `.env` is ignored by
  Git.
- `logs/rotation.log` and `links/screenshots/` — demonstration evidence.

## Local setup

Use Python 3.10 or later. From this directory, install the runtime
dependencies and configure the Auth0 values:

```bash
python -m venv .venv
.venv/bin/pip install flask 'pyjwt[crypto]' requests python-dotenv
cp .env.example .env
```

Set `AUTH0_DOMAIN`, `API_AUDIENCE`, `CLIENT_ID`, `CLIENT_SECRET`, `M2M_ID`,
and `M2M_SECRET` in `.env`. Keep real credentials out of source control and
screenshots.

Start the API and login client in separate terminals, both from this directory:

```bash
.venv/bin/python backend/app.py
.venv/bin/python auth_flows/pkce_login.py
```

For the M2M expiry/replay demonstration, start the API and run:

```bash
.venv/bin/python auth_flows/rotation_demo.py
```

The token's expiration wait is intentional. The API is a local demonstration,
not a production service.

## Auth0 design

- API audience: `https://api.securenova.ai`
- Scopes: `read:ai-data` and `write:admin`
- Demo user and admin roles are assigned in Auth0; the API makes authorization
  decisions from the validated token scopes.
- The rotation probe in Project 4 sets access-token lifetime to 300 seconds
  and refresh-token rotation. The original Project 2 replay demonstration
  uses a short-lived M2M access token.

## Optional two-application SSO demonstration

The login client accepts `PORT`, `APP_NAME`, and `CALLBACK_URL` so two
instances can run simultaneously. Forward port 3001 privately in VS Code and
add its exact callback and logout URLs to the Auth0 application's allowlists.
For distinct applications, create a second Regular Web Application in the
same Auth0 tenant and supply its credentials through a separate, untracked
environment file:

```bash
AUTH_ENV_FILE="$HOME/.config/securenova-reports.env" \
PORT=3001 APP_NAME="SecureNova Reports" \
CALLBACK_URL="https://<your-forwarded-host>-3001.app.github.dev/" \
.venv/bin/python auth_flows/pkce_login.py
```

That file must define `AUTH0_DOMAIN`, `API_AUDIENCE`, `CLIENT_ID`, and
`CLIENT_SECRET`. Exported shell variables take precedence. Sign in to the
first app, then select **Sign in** in the second app using the same browser
profile. Auth0 may still request consent or MFA. Each application has a
separate local session; do not sign out between SSO steps.