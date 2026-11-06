# refresh_rotation_test.py - old refresh token rejected after rotation
import os, requests
from dotenv import load_dotenv
load_dotenv()
D, CID, SEC = os.environ["AUTH0_DOMAIN"], os.environ["CLIENT_ID"], os.environ["CLIENT_SECRET"]

# Use a refresh_token you captured from the PKCE flow's token response
old_refresh = os.environ["OLD_REFRESH_TOKEN"]

r1 = requests.post(f"https://{D}/oauth/token", data={
    "grant_type": "refresh_token", "client_id": CID, "client_secret": SEC,
    "refresh_token": old_refresh})
print("First use ->", r1.status_code, r1.json().get("refresh_token", "")[:20], "...")

new_refresh = r1.json()["refresh_token"]

r2 = requests.post(f"https://{D}/oauth/token", data={
    "grant_type": "refresh_token", "client_id": CID, "client_secret": SEC,
    "refresh_token": old_refresh})  # replay the OLD one
print("Replay old token ->", r2.status_code, r2.json())