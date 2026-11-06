# agent_signing.py - Ed25519 message signing, verification, tamper detection
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

with open("agent_private.pem", "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
with open("agent_public.pem", "wb") as f:
    f.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
print("Key pair generated: agent_private.pem, agent_public.pem")

message = b"TRANSFER:order_4471:approved"
signature = private_key.sign(message)
print(f"\nOriginal message: {message}")
print(f"Signature (hex): {signature.hex()[:40]}...")

try:
    public_key.verify(signature, message)
    print("[VERIFIED] Original message signature is valid")
except InvalidSignature:
    print("[REJECTED] Original message failed verification")

tampered = b"TRANSFER:order_4472:approved"  # one char changed (4471 -> 4472)
try:
    public_key.verify(signature, tampered)
    print("[VERIFIED] Tampered message passed (BUG)")
except InvalidSignature:
    print(
        f"[REJECTED] Tampered message signature verification FAILED - message integrity compromised"
    )
