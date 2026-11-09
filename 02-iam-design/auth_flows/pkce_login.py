import base64
import hashlib
import os
import secrets
import urllib.parse
import webbrowser
from threading import Timer
from pathlib import Path

import requests
from dotenv import load_dotenv
from flask import Flask, abort, redirect, render_template_string, request, session

load_dotenv(dotenv_path=os.getenv("AUTH_ENV_FILE"))
D, CID, SEC = os.environ["AUTH0_DOMAIN"], os.environ["CLIENT_ID"], os.environ["CLIENT_SECRET"]
AUD = os.environ["API_AUDIENCE"]
PORT = int(os.getenv("PORT", "3000"))
APP_NAME = os.getenv("APP_NAME", "SecureNova")
CB = os.getenv("CALLBACK_URL", f"https://ubiquitous-spork-w99jrv4xq45f9j4q-{PORT}.app.github.dev/")
CAPTURE_REFRESH_TOKEN = os.getenv("CAPTURE_REFRESH_TOKEN", "").lower() in {"1", "true", "yes"}

app = Flask(__name__)
app.secret_key = secrets.token_bytes(32)
app.config.update(
   SESSION_COOKIE_NAME=f"securenova_login_{PORT}",
   SESSION_COOKIE_HTTPONLY=True,
   SESSION_COOKIE_SECURE=CB.startswith("https://"),
   SESSION_COOKIE_SAMESITE="Lax",
)
tokens = {}


def store_refresh_token(token: str) -> Path:
   path = Path(os.getenv(
      "REFRESH_TOKEN_FILE", Path(__file__).resolve().parents[1] / ".refresh_token"
   )).expanduser()
   path.parent.mkdir(parents=True, exist_ok=True)
   flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
   descriptor = os.open(path, flags, 0o600)
   with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
      os.fchmod(stream.fileno(), 0o600)
      stream.write(token + "\n")
   return path

HOME = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
   <title>{{ app_name }} | Home</title>
  <style>
   :root { color-scheme: light; --ink: #192b25; --accent: #006c50; }
   * { box-sizing: border-box; }
   body { margin: 0; color: var(--ink); background: #f4f7f5;
         font: 16px Georgia, serif; }
   header { border-bottom: 1px solid #cbd8d0; background: white; }
   nav, main { max-width: 880px; margin: auto; padding: 24px; }
   nav { display: flex; align-items: center; justify-content: space-between;
        gap: 16px; flex-wrap: wrap; }
   .brand { font-size: 24px; font-weight: bold; }
   main { padding-top: 56px; }
   h1 { font-size: 32px; margin: 12px 0 24px; }
   h2 { font-size: 20px; margin: 0; }
   .status { color: var(--accent); font: 14px Verdana, sans-serif; }
   .endpoint { display: flex; align-items: center; justify-content: space-between;
            gap: 20px; padding: 24px 0; border-top: 1px solid #cbd8d0;
            flex-wrap: wrap; }
   code { display: block; margin-top: 8px; overflow-wrap: anywhere; }
   button, .button { display: inline-block; border: 1px solid var(--accent);
     border-radius: 4px; background: var(--accent); color: white; padding: 12px 18px;
     font: 14px Verdana, sans-serif; text-decoration: none; cursor: pointer; }
   .logout { background: white; color: var(--accent); }
   .notice { border-left: 3px solid #b46b00; padding: 16px; background: #fff6df;
           overflow-wrap: anywhere; }
   footer { margin-top: 40px; font-size: 14px; color: #53665c; }
   @media (max-width: 480px) { main { padding-top: 28px; } h1 { font-size: 28px; } }
  </style>
</head>
<body>
  <header><nav>
   <span class="brand">{{ app_name }}</span>
   {% if logged_in %}
   <form method="post" action="/logout">
     <input type="hidden" name="csrf" value="{{ csrf }}">
     <button class="logout" type="submit">Sign out</button>
   </form>
   {% endif %}
  </nav></header>
  <main>
   <div class="status">{{ 'Signed in' if logged_in else 'Signed out' }}</div>
   <h1>{{ 'Your workspace' if logged_in else 'Welcome to ' ~ app_name }}</h1>
   {% if message %}<p class="notice" role="status">{{ message }}</p>{% endif %}
   {% if logged_in %}
     {% for endpoint, title, method in [('chat', 'AI chat', 'POST'), ('admin', 'Administration', 'GET')] %}
     <section class="endpoint">
      <div><h2>{{ title }}</h2><code>{{ method }} /{{ endpoint }}</code></div>
      <form method="post" action="/check/{{ endpoint }}">
        <input type="hidden" name="csrf" value="{{ csrf }}">
        <button type="submit">Check access</button>
      </form>
     </section>
     {% endfor %}
   {% else %}
     <a class="button" href="/login">Sign in</a>
   {% endif %}
   <footer>Identity &amp; access portal</footer>
  </main>
</body>
</html>"""


def home_page(message=None, status=200):
   session.setdefault("csrf", secrets.token_urlsafe(32))
   return render_template_string(
      HOME, logged_in=session.get("sid") in tokens,
      csrf=session["csrf"], message=message, app_name=APP_NAME,
   ), status


@app.after_request
def prevent_caching(response):
   response.headers["Cache-Control"] = "no-store"
   response.headers["Referrer-Policy"] = "no-referrer"
   response.headers["X-Frame-Options"] = "DENY"
   return response


@app.get("/login")
def login():
   verifier = secrets.token_urlsafe(40)
   challenge = base64.urlsafe_b64encode(
      hashlib.sha256(verifier.encode()).digest()
   ).rstrip(b"=").decode()
   session["verifier"] = verifier
   session["state"] = secrets.token_urlsafe(32)
   scopes = "openid profile read:ai-data write:admin"
   if CAPTURE_REFRESH_TOKEN:
      scopes += " offline_access"
   return redirect(f"https://{D}/authorize?" + urllib.parse.urlencode({
      "response_type": "code", "client_id": CID, "redirect_uri": CB,
      "scope": scopes, "audience": AUD,
      "state": session["state"], "code_challenge": challenge,
      "code_challenge_method": "S256",
   }))


@app.get("/")
def home():
   if "code" not in request.args and "error" not in request.args:
      return home_page(session.pop("message", None))
   expected_state = session.pop("state", None)
   verifier = session.pop("verifier", None)
   if not expected_state or not secrets.compare_digest(
      request.args.get("state", ""), expected_state
   ) or not verifier:
      return home_page("Login could not be verified. Please sign in again.", 400)
   if "error" in request.args:
      session["message"] = "Sign-in was not completed. Please try again."
      return redirect("/")
   try:
      response = requests.post(f"https://{D}/oauth/token", json={
         "grant_type": "authorization_code", "client_id": CID,
         "client_secret": SEC, "code": request.args["code"],
         "code_verifier": verifier, "redirect_uri": CB,
      }, timeout=15)
      response.raise_for_status()
      token_response = response.json()
      token = token_response.get("access_token")
      if not isinstance(token, str) or not token:
         raise ValueError("Missing access token")
      refresh_path = None
      if CAPTURE_REFRESH_TOKEN:
         refresh_token = token_response.get("refresh_token")
         if not isinstance(refresh_token, str) or not refresh_token:
            raise ValueError("Auth0 did not issue a refresh token; check offline access settings")
         refresh_path = store_refresh_token(refresh_token)
   except (OSError, requests.RequestException, ValueError):
      session["message"] = "Sign-in failed. Please try again."
      return redirect("/")
   tokens.pop(session.get("sid"), None)
   session.clear()
   session["sid"] = secrets.token_urlsafe(32)
   tokens[session["sid"]] = token
   if refresh_path:
      session["message"] = f"Refresh token saved securely to {refresh_path.name}."
   return redirect("/")


@app.before_request
def validate_form():
   if request.method == "POST":
      expected = session.get("csrf")
      if not expected or not secrets.compare_digest(request.form.get("csrf", ""), expected):
         abort(400)


@app.post("/check/<endpoint>")
def check_access(endpoint):
   if endpoint not in ("chat", "admin"):
      abort(404)
   token = tokens.get(session.get("sid"))
   if not token:
      return redirect("/")
   method = "POST" if endpoint == "chat" else "GET"
   try:
      response = requests.request(
         method, f"http://localhost:5000/{endpoint}",
         headers={"Authorization": f"Bearer {token}"}, timeout=10,
      )
      outcomes = {200: "Access granted", 401: "Session expired or invalid. Sign in again",
               403: "Access denied: insufficient permissions"}
      result = outcomes.get(response.status_code, "Request failed")
      session["message"] = f"{method} /{endpoint}: {response.status_code} - {result}."
   except requests.RequestException:
      session["message"] = "The API is unavailable. Check that it is running on port 5000."
   return redirect("/")


@app.post("/logout")
def logout():
   tokens.pop(session.get("sid"), None)
   session.clear()
   return redirect(f"https://{D}/v2/logout?" + urllib.parse.urlencode({
      "client_id": CID, "returnTo": CB,
   }))


if __name__ == "__main__":
   print(f"{APP_NAME} home: {CB}")
   Timer(1, lambda: webbrowser.open(CB)).start()
   app.run(host="0.0.0.0", port=PORT, debug=False)
