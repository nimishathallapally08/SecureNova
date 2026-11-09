"""Explicit, opt-in Auth0 test-tenant setup and redacted verification evidence."""

import argparse
import base64
import json
import os
import re
import time
from pathlib import Path
from urllib.parse import quote

import requests
from dotenv import load_dotenv

from .reporting import write_json

REFRESH_TOKEN_PATH = (
    Path(__file__).resolve().parents[2] / "02-iam-design" / ".refresh_token"
)


def required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"{name} must be set locally; do not paste it in reports")
    return value


def load_old_refresh_token(path: Path = REFRESH_TOKEN_PATH) -> str:
    token = os.getenv("OLD_REFRESH_TOKEN")
    if token:
        return token
    try:
        token = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError as exc:
        raise RuntimeError(
            "No captured refresh token found; complete PKCE login with "
            "CAPTURE_REFRESH_TOKEN=1 first"
        ) from exc
    if not token:
        raise RuntimeError("The captured refresh-token file is empty")
    return token


def oauth_error_details(response: requests.Response,
                        secrets_to_redact: tuple[str, ...] = ()) -> str:
    try:
        value = response.json()
    except (ValueError, AttributeError):
        return "unknown OAuth error"
    if not isinstance(value, dict):
        return "unknown OAuth error"
    code = value.get("error")
    if not isinstance(code, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", code):
        code = "unknown OAuth error"
    description = value.get("error_description")
    if isinstance(description, str):
        for secret in secrets_to_redact:
            if secret:
                description = description.replace(secret, "[REDACTED]")
        description = " ".join(description.split())[:240]
        if description:
            return f"{code}: {description}"
    return code


def oauth_error_code(response: requests.Response) -> str | None:
    try:
        value = response.json().get("error")
    except (ValueError, AttributeError):
        return None
    return value if isinstance(value, str) else None


class Auth0:
    def __init__(self):
        domain = required("AUTH0_DOMAIN")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", domain):
            raise ValueError("AUTH0_DOMAIN must be a hostname without scheme or path")
        self.base = f"https://{domain}"
        self.session = requests.Session()
        self.session.headers["Authorization"] = "Bearer " + required("AUTH0_MANAGEMENT_TOKEN")

    def api(self, method: str, path: str, payload: dict | None = None):
        response = self.session.request(
            method, self.base + "/api/v2/" + path, json=payload, timeout=30,
        )
        if not response.ok:
            raise RuntimeError(f"Auth0 management {method} {path.split('/')[0]} "
                               f"failed with HTTP {response.status_code}")
        return response.json()

    def settings(self, apply: bool) -> dict:
        api_id = quote(required("AUTH0_API_ID"), safe="")
        client_id = quote(required("CLIENT_ID"), safe="")
        resource = f"resource-servers/{api_id}"
        client_path = f"clients/{client_id}"
        if apply:
            self.api("PATCH", resource, {"token_lifetime": 300,
                                        "token_lifetime_for_web": 300})
            self.api("PATCH", client_path, {"refresh_token": {
                "rotation_type": "rotating", "expiration_type": "expiring",
                "token_lifetime": 2592000, "leeway": 0,
            }})
        api = self.api("GET", resource)
        client = self.api("GET", client_path)
        rotation = client.get("refresh_token", {})
        return {
            "access_token_ttl_300": api.get("token_lifetime") == 300,
            "web_token_ttl_300": api.get("token_lifetime_for_web") == 300,
            "refresh_rotation_enabled": rotation.get("rotation_type") == "rotating",
            "rotation_leeway_seconds": rotation.get("leeway"),
            "checked_at": time.time(),
        }

    def deploy_action(self) -> dict:
        source = (Path(__file__).resolve().parents[1]
                  / "actions/riskblock.js").read_text()
        created = self.api("POST", "actions/actions", {
            "name": "SecureNova lab risk block", "runtime": "node22",
            "supported_triggers": [{"id": "post-login", "version": "v3"}],
            "code": source,
        })
        action_id = created["id"]
        deployed = self.api("POST", f"actions/actions/{action_id}/deploy", {})
        if deployed.get("status") != "built":
            raise RuntimeError("Auth0 Action did not build; existing bindings unchanged")
        bindings = self.api("GET", "actions/triggers/post-login/bindings")
        preserved = [{
            "ref": {"type": "action_id", "value": item["action"]["id"]},
            "display_name": item["display_name"],
        } for item in bindings["bindings"]]
        preserved.append({
            "ref": {"type": "action_id", "value": action_id},
            "display_name": "SecureNova lab risk block",
        })
        self.api("PATCH", "actions/triggers/post-login/bindings", {"bindings": preserved})
        actual = self.api("GET", "actions/triggers/post-login/bindings")
        return {"action_deployed_and_bound": any(
            item["action"]["id"] == action_id for item in actual["bindings"]
        ), "login_test": "pending interactive flagged/unflagged account tests"}


def rotation_probe(leeway: float) -> dict:
    if not 0 <= leeway <= 300:
        raise ValueError("--leeway must be between 0 and 300 seconds")
    domain = required("AUTH0_DOMAIN")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", domain):
        raise ValueError("AUTH0_DOMAIN must be a hostname")
    old = load_old_refresh_token()
    data = {"grant_type": "refresh_token", "client_id": required("CLIENT_ID")}
    secret = os.getenv("CLIENT_SECRET")
    if secret:
        data["client_secret"] = secret

    def exchange(token: str) -> requests.Response:
        return requests.post(f"https://{domain}/oauth/token",
                             data={**data, "refresh_token": token}, timeout=30)

    first = exchange(old)
    if not first.ok:
        raise RuntimeError(
            "First refresh failed: HTTP "
            f"{first.status_code} ({oauth_error_details(first, (old, secret or ''))})"
        )
    issued = first.json()
    new = issued.get("refresh_token")
    if not isinstance(new, str) or not new or new == old:
        raise RuntimeError("Refresh rotation did not issue a different refresh token")
    if issued.get("expires_in") != 300:
        raise RuntimeError("Fresh access token lifetime was not 300 seconds")
    # JWT inspection is supplementary; expires_in is the TLS-protected issuer response.
    jwt_ttl = None
    access = issued.get("access_token", "")
    if isinstance(access, str) and access.count(".") == 2:
        encoded = access.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        jwt_ttl = claims["exp"] - claims["iat"]
        if jwt_ttl != 300:
            raise RuntimeError("Issued JWT exp - iat was not 300 seconds")
    time.sleep(leeway + 1)
    second = exchange(old)
    if second.status_code not in (400, 401, 403) or oauth_error_code(second) != "invalid_grant":
        raise RuntimeError(
            "Old refresh token replay was not rejected with invalid_grant: "
            f"HTTP {second.status_code} ({oauth_error_details(second, (old, secret or ''))})"
        )
    return {
        "first_exchange": "passed", "different_refresh_token_issued": True,
        "expires_in": 300, "jwt_ttl_inspected_not_signature_verified": jwt_ttl,
        "old_token_rejected": True, "replay_http_status": second.status_code,
        "old_token_replay_error": "invalid_grant",
        "warning": "Reuse detection may revoke the entire test token family.",
        "checked_at": time.time(),
    }


def main(argv: list[str] | None = None) -> None:
    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("verify", "apply", "deploy-action", "rotation"))
    parser.add_argument("--confirm-test-tenant", action="store_true")
    parser.add_argument("--leeway", type=float, default=0)
    parser.add_argument("--output", type=Path,
                        default=Path(__file__).resolve().parents[1]
                        / "results/auth0-verification.json")
    args = parser.parse_args(argv)
    if not args.confirm_test_tenant:
        parser.error("--confirm-test-tenant is required, even for token consumption")
    if args.operation == "rotation":
        result = rotation_probe(args.leeway)
    elif args.operation == "deploy-action":
        result = Auth0().deploy_action()
    else:
        result = Auth0().settings(apply=args.operation == "apply")
        if not all(result[key] for key in (
            "access_token_ttl_300", "web_token_ttl_300", "refresh_rotation_enabled"
        )):
            write_json(args.output, result)
            raise RuntimeError("Auth0 settings do not meet the hardening requirements")
    write_json(args.output, result)
    print(json.dumps(result, indent=2))
    print(f"Redacted Auth0 evidence saved: {args.output}")


if __name__ == "__main__":
    main()
