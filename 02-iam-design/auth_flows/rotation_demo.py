import os, time, requests
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()
D, AUD = os.environ["AUTH0_DOMAIN"], os.environ["API_AUDIENCE"]
ts = lambda: datetime.now().strftime("%H:%M:%S")

def response_body(response):
   try:
      return response.json()
   except requests.exceptions.JSONDecodeError:
      return response.text

def print_response(label, response):
   reason = "Unauthorised" if response.status_code == 401 else response.reason
   print(f"[{ts()}] {label} ->", response.status_code, reason, response_body(response), flush=True)

r = requests.post(f"https://{D}/oauth/token", json={
   "grant_type": "client_credentials", "client_id": os.environ["M2M_ID"],
   "client_secret": os.environ["M2M_SECRET"], "audience": AUD}).json()

tok = r["access_token"]
print(f"[{ts()}] Token issued, expires_in={r['expires_in']}s", flush=True)

h = {"Authorization": f"Bearer {tok}"}
resp = requests.post("http://localhost:5000/chat", headers=h)
print_response("POST /chat", resp)
if resp.status_code != 200:
   print("Initial request failed. Check the API audience and M2M read:ai-data permission. Replay will still run.", flush=True)

wait_seconds = int(r["expires_in"]) + 5
print(f"[{ts()}] Waiting {wait_seconds}s for token to expire...", flush=True)
time.sleep(wait_seconds)
resp = requests.post("http://localhost:5000/chat", headers=h)
print_response("REPLAY /chat", resp)