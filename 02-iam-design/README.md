# 02 — IAM Design (Auth0 Implementation)
Auth0-backed identity layer for the SecureNova AI platform: a Regular Web
Application for the chat service, a Machine-to-Machine application for the
AI agent, custom scopes, MFA, attack protection, short-lived credential
rotation, and a post-login Action adding a custom agent identity claim.
## Structure
- `backend/app.py` — Flask API validating RS256 JWTs against Auth0's JWKS,
 enforcing scope-based access on `/chat` (read:ai-data) and `/admin`
 (write:admin).
- `auth_flows/pkce_login.py` — Authorization Code + PKCE login flow for a
 human user, used to prove a user-level token is rejected (403) on the
 admin endpoint.
- `auth_flows/rotation_demo.py` — obtains a 60-second M2M token, calls
 `/chat` successfully, then replays the expired token to confirm a 401.
- `actions/add-agent-id-claim.js` — Auth0 post-login Action source that adds
 a custom `agent_id` claim to the ID and access tokens.
- `env/.env.example` — template for required environment variables. Copy to
 `.env` and fill in real values locally; `.env` is gitignored.
- `logs/rotation.log` — timestamped terminal evidence of the rotation test.
- `screenshots/` — evidence captures used in `Project2.pdf`.
## Setup
1. `pip install -r requirements.txt` (flask, pyjwt[crypto], requests,
  python-dotenv)
2. Copy `env/.env.example` to `env/.env` and fill in your Auth0 tenant
  domain, API audience, and both applications' client ID/secret.
3. Run `python backend/app.py` in one terminal.
4. Run `python auth-flows/pkce_login.py` in a second terminal to log in as
  a test user and exercise the API.
5. Run `python auth-flows/rotation_demo.py` to test M2M token rotation.
## Key config
- API: `SecureNova API` (`https://api.securenova.ai`), scopes
 `read:ai-data` and `write:admin`, RBAC enabled.
- Users: `user1@test.com` (role `ai-user`), `admin1@test.com`
 (role `ai-admin`).
- Token TTL: 60s (Project 2 rotation test), later raised to 300s
 (Project 4 hardening).

## Two-Application SSO Demo

The forwarded port-3001 URL needs a running server. The current login script
supports multiple instances using `PORT`, `APP_NAME`, and `CALLBACK_URL`.
From this directory, leave the first app running and start the second in
another terminal:

```bash
PORT=3001 APP_NAME="SecureNova Reports" CALLBACK_URL="https://ubiquitous-spork-w99jrv4xq45f9j4q-3001.app.github.dev/" python pkce_login.py
```

This command reuses the first app's Auth0 client configuration. To demonstrate
SSO between two distinct Auth0 applications, create a second **Regular Web
Application** in the **same Auth0 tenant**. Put its configuration in a separate,
untracked environment file outside the repository, such as
`~/.config/securenova-reports.env`, containing `AUTH0_DOMAIN`, `API_AUDIENCE`,
`CLIENT_ID`, and `CLIENT_SECRET`. Use the second application's client ID and
secret, not the first application's or the M2M application's credentials.
Then start it with:

```bash
AUTH_ENV_FILE="$HOME/.config/securenova-reports.env" PORT=3001 APP_NAME="SecureNova Reports" CALLBACK_URL="https://ubiquitous-spork-w99jrv4xq45f9j4q-3001.app.github.dev/" python pkce_login.py
```

Variables already exported in the shell take precedence over the environment
file. Protect that file and never commit or share its client secret.

In the second Auth0 application's settings, add the following exact URL to
both **Allowed Callback URLs** and **Allowed Logout URLs**:

```text
https://ubiquitous-spork-w99jrv4xq45f9j4q-3001.app.github.dev/
```

If reusing the first Auth0 client, add this URL to that client's allowlists
alongside its port-3000 URL instead. In VS Code's **Ports** panel, forward port
3001 and keep it private.

To demonstrate SSO:

1. Sign in to the port-3000 app.
2. In the same browser profile, open the port-3001 app and select **Sign in**.
3. Auth0 should reuse its existing session without asking for credentials
  again, then return to the second app. Consent or MFA may still be required
  by tenant policy.

Each app has its own local session. Opening the second home page alone does
not establish a session; selecting **Sign in** starts the Auth0 redirect.
Do not sign out between these steps, because sign-out ends the Auth0 SSO
session. It does not automatically clear the other app's existing local session.