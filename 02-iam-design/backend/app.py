import os, jwt
from functools import wraps
from flask import Flask, request, jsonify
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientError
from dotenv import load_dotenv

load_dotenv()
DOMAIN, AUD = os.environ["AUTH0_DOMAIN"], os.environ["API_AUDIENCE"]
jwks = PyJWKClient(f"https://{DOMAIN}/.well-known/jwks.json")
app = Flask(__name__)

def require_scope(scope):
    def deco(f):
        @wraps(f)
        def wrapper(*a,**kw):
            auth = request.headers.get("Authorization","")
            scheme, _, token = auth.partition(" ")
            if scheme.lower() != "bearer" or not token:
                return jsonify(error="missing token"), 401

            try:
                # Resolve the signing key and verify issuer, audience, and signature
                # before trusting claims.
                key = jwks.get_signing_key_from_jwt(token).key
                claims = jwt.decode(token,key,algorithms=["RS256"],audience=AUD,issuer=f"https://{DOMAIN}/")
            
            except jwt.ExpiredSignatureError:
                return jsonify(error="token expired"), 401
            except (jwt.InvalidTokenError, PyJWKClientError) as e:
                return jsonify(error=f"invalid token: {e}"), 401
            granted = claims.get("scope","").split()
            # A valid token is not sufficient; each route also requires its
            # own delegated scope.
            if scope not in granted:
                return jsonify(error="insufficient scope", required=scope), 403
            request.claims = claims
            return f(*a,**kw)
        return wrapper
    return deco

@app.post("/chat")
@require_scope("read:ai-data")
def chat():
    return jsonify(reply="ok",caller=request.claims.get("sub"))

@app.get("/admin")
@require_scope("write:admin")
def admin():
    return jsonify(secret="admin data")

if __name__ == "__main__":
    app.run(port=5000)