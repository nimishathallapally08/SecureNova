"""Project 4 Ed25519 sender binding, expiry, audience, and replay checks."""

import base64
import json
import time
import uuid
from dataclasses import asdict, dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)


class IdentityError(ValueError):
    pass


@dataclass(frozen=True)
class Envelope:
    sender: str
    recipient: str
    message: str
    scope: str
    expires_at: float
    nonce: str
    signature: str = ""

    def signing_bytes(self) -> bytes:
        # Canonical serialization ensures sender and receiver sign the same
        # complete envelope.
        fields = asdict(self)
        del fields["signature"]
        return json.dumps(fields, sort_keys=True, separators=(",", ":"),
                          allow_nan=False).encode()


class AgentIdentity:
    def __init__(self, name: str):
        self.name = name
        self.key = Ed25519PrivateKey.generate()

    def send(self, recipient: str, message: str, scope: str,
             now: float | None = None) -> Envelope:
        issued = time.time() if now is None else now
        envelope = Envelope(self.name, recipient, message, scope,
                            issued + 300, uuid.uuid4().hex)
        fields = asdict(envelope)
        fields["signature"] = base64.b64encode(
            self.key.sign(envelope.signing_bytes())
        ).decode()
        return Envelope(**fields)


class Receiver:
    def __init__(self, name: str, trusted: dict[str, Ed25519PublicKey]):
        self.name = name
        self.trusted = trusted
        self.seen: set[str] = set()

    def verify(self, envelope: Envelope, now: float | None = None) -> str:
        key = self.trusted.get(envelope.sender)
        if key is None:
            raise IdentityError(f"untrusted sender: {envelope.sender}")
        if envelope.recipient != self.name:
            raise IdentityError("recipient mismatch")
        try:
            signature = base64.b64decode(envelope.signature, validate=True)
        except ValueError as exc:
            raise IdentityError("malformed signature") from exc
        try:
            key.verify(signature, envelope.signing_bytes())
        except InvalidSignature as exc:
            raise IdentityError("signature invalid: message was tampered")
        current = time.time() if now is None else now
        if envelope.expires_at <= current:
            raise IdentityError("message expired")
        if envelope.expires_at > current + 300:
            raise IdentityError("message lifetime exceeds 300 seconds")
        if envelope.nonce in self.seen:
            raise IdentityError("message replay rejected")
        # Mark the nonce only after all checks pass, so invalid messages cannot consume it.
        self.seen.add(envelope.nonce)
        return envelope.message
