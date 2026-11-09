"""Screenshot-friendly offline controls; never claims live model or Auth0 evidence."""

import argparse
import json
import os
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from .detection import RequestEvent, attack_scenario, replay
from .fixtures import CASES, FAKE_JWT
from .identity import AgentIdentity, IdentityError, Receiver
from .reporting import write_json

PROJECT = Path(__file__).resolve().parents[1]


def guardrail_evidence() -> dict:
    from .guardrails import Guardrails

    rails = Guardrails()
    results = []
    print("REAL NEMO FLOWS / SYNTHETIC INPUTS: no live LLM request")
    for case in CASES[:3]:
        print(f"\nCASE: {case.id}\nINPUT:\n{case.full_input}")
        result = rails.filter(case.full_input)
        print(f"STATUS: {result['input_status']}\nREASON: {result['reason']}")
        if result["input_status"] != "BLOCKED":
            raise RuntimeError(f"Expected indirect-injection block: {case.id}")
        results.append(result)
    original = f"Synthetic model-response fixture: {FAKE_JWT}"
    filtered = rails.filter("Return the already generated answer.", original)
    print(f"\nOUTPUT GUARDRAIL\nBEFORE: {original}")
    print(f"AFTER: {filtered['response']}")
    print(f"STATUS: {filtered['output_status']}\nREASON: {filtered['reason']}")
    if filtered["output_status"] != "REDACTED" or FAKE_JWT in filtered["response"]:
        raise RuntimeError("JWT output rail did not redact the synthetic fixture")
    return {"provenance": "Actual NeMo flows; synthetic response fixture, not live inference.",
            "inputs": results, "output": filtered}


def identity_evidence(destination: Path) -> dict:
    sender = AgentIdentity("orchestrator")
    private_path = destination / "agent_private.pem"
    public_path = destination / "agent_public.pem"
    descriptor = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(sender.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    with public_path.open("xb") as stream:
        stream.write(sender.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    print("REAL Ed25519 keys generated using Python cryptography")
    for path in (private_path, public_path):
        print(f"CREATED: {path} ({path.stat().st_size} bytes)")
    print("Private key contents are intentionally not printed. Lab keys only.")
    receiver = Receiver("agent-b", {"orchestrator": sender.key.public_key()})
    envelope = sender.send("agent-b", "TRANSFER:order_4471:approved", "write:admin")
    receiver.verify(envelope)
    print(f"\nORIGINAL: {envelope.message}\nVERIFIED: original signature is valid")
    changed = replace(envelope, message=envelope.message.replace("4471", "4472"))
    print(f"TAMPERED: {changed.message} (one character changed)")
    try:
        receiver.verify(changed)
    except IdentityError as exc:
        print(f"REJECTED: {exc}")
        error = str(exc)
    else:
        raise RuntimeError("Tampered message was incorrectly accepted")
    return {"library": "cryptography", "algorithm": "Ed25519",
            "private_key_file": str(private_path), "public_key_file": str(public_path),
            "original_verified": True, "tampered_message_rejected": True, "error": error}


def detection_evidence() -> dict:
    event = RequestEvent(
        timestamp=time.time(), identity="lab-agent", scope="read:demo",
        token_id="synthetic-token", expires_at=time.time() + 300,
        case_id=CASES[0].id, event_type="llm_call",
    )
    events = attack_scenario([event])
    alerts = replay(events)
    expected = {"volume_spike", "scope_change", "token_reuse_after_expiry"}
    if {alert["event_type"] for alert in alerts} != expected:
        raise RuntimeError("Not every detection scenario produced an alert")
    print("REAL DETECTOR / SYNTHETIC EVENTS: not observed production traffic")
    for alert in alerts:
        print("ALERT " + json.dumps(alert))
    return {"provenance": "Synthetic timing, scope and token metadata.",
            "events": events, "alerts": alerts}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("control", choices=("guardrails", "identity", "detection"))
    parser.add_argument("--output", type=Path,
                        help="New directory; existing directories are never overwritten")
    args = parser.parse_args()
    destination = args.output or (
        PROJECT / "results" / "evidence"
        / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    )
    destination.mkdir(parents=True, exist_ok=False)
    if args.control == "guardrails":
        result = guardrail_evidence()
    elif args.control == "identity":
        result = identity_evidence(destination)
    else:
        result = detection_evidence()
    write_json(destination / "evidence.json", result)
    print(f"\nEvidence saved: {destination}")


if __name__ == "__main__":
    main()
