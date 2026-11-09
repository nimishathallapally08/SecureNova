"""Replay logged attacks and model responses through NeMo input/output rails."""

import argparse
import json
import re
from pathlib import Path
from typing import TypedDict

from nemoguardrails import LLMRails, RailsConfig
from nemoguardrails.rails.llm.options import GenerationResponse

from .output import count_jwts, redact_output

HERE = Path(__file__).resolve().parents[1]
LOGS = HERE / "config" / "fixtures"
BLOCK_PATTERNS = [
    re.compile(r"\bignore\s+(?:(?:all|prior|previous)\s+)*instructions\b", re.I),
    re.compile(r"\[ORCHESTRATOR\]", re.I),
    re.compile(r"SYSTEM OVERRIDE", re.I),
    re.compile(r"\brepeat everything above\b", re.I),
    re.compile(r"\bDAN\b"),
    re.compile(r"\b(?:system|internal)\s+(?:prompt|instructions|credential|tokens?)\b", re.I),
    re.compile(
        r"\b(?:admin\s+role\s+claim|confirm\s+my\s+role\s+is\s+admin|"
        r"grant\s+write:admin)\b", re.I,
    ),
]


class Payload(TypedDict):
    source: str
    payload_id: int
    payload: str
    response: str


class Result(TypedDict):
    source: str
    payload_id: int
    payload: str
    framework: str
    mode: str
    status: str
    input_status: str
    output_status: str
    reason: str
    jwt_count: int
    response: str


def check_input(text: str) -> tuple[bool, str]:
    for pattern in BLOCK_PATTERNS:
        if pattern.search(text):
            return False, f"blocked: matched pattern '{pattern.pattern}'"
    return True, "passed input rules"


def build_rails() -> LLMRails:
    rails = LLMRails(RailsConfig.from_path(str(HERE / "config" / "rails")))
    rails.register_action(check_input, name="check_attack_input")
    rails.register_action(count_jwts, name="count_output_jwts")
    rails.register_action(redact_output, name="redact_output_jwts")
    return rails


class Guardrails:
    def __init__(self):
        self.rails = build_rails()
        self.sequence = 0

    def filter(self, text: str, response: str = "") -> Result:
        self.sequence += 1
        return run_payload(self.rails, Payload(
            source="integrated_application", payload_id=self.sequence,
            payload=text, response=response,
        ))


def load_payloads(paths: list[Path]) -> list[Payload]:
    payloads: list[Payload] = []
    for path in paths:
        value = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(value, list):
            entries = value
        elif isinstance(value, dict) and isinstance(value.get("cases"), list):
            entries = value["cases"]
        elif isinstance(value, dict) and isinstance(value.get("retrieved_chunks"), list):
            chunks = value["retrieved_chunks"]
            question = value.get("user_question")
            if not all(isinstance(chunk, str) for chunk in chunks) or not isinstance(question, str):
                raise ValueError(f"{path}: retrieved_chunks and user_question must be strings")
            entries = [{
                "payload": "\n".join(chunks) + "\n\nUser question: " + question,
                "response": value.get("response") or "",
            }]
        else:
            raise ValueError(f"{path}: expected a list, cases list, or RAG fixture")
        for index, entry in enumerate(entries, 1):
            if not isinstance(entry, dict):
                raise ValueError(f"{path}: entry {index} must be an object")
            text = entry.get("payload", entry.get("prompt"))
            response = entry.get("response") or ""
            payload_id = entry.get("payload_id", index)
            if not isinstance(text, str) or not isinstance(response, str):
                raise ValueError(
                    f"{path}: entry {index} needs a string payload/prompt and response"
                )
            if type(payload_id) is not int:
                raise ValueError(f"{path}: entry {index} payload_id must be an integer")
            payloads.append(
                Payload(source=path.name, payload_id=payload_id, payload=text, response=response)
            )
    if not payloads:
        raise ValueError("No payloads found")
    return payloads


def run_payload(rails: LLMRails, payload: Payload) -> Result:
    # Disabling dialog generation replays the saved response through output rails.
    generated = rails.generate(
        messages=[
            {
                "role": "context",
                "content": {
                    "bot_message": payload["response"],
                    "input_allowed": None,
                    "input_reason": None,
                    "jwt_count": None,
                },
            },
            {"role": "user", "content": payload["payload"]},
        ],
        options={
            "rails": {"input": True, "dialog": False, "output": True},
            "output_vars": True,
        },
    )
    if not isinstance(generated, GenerationResponse):
        raise RuntimeError("NeMo did not return generation metadata")
    context = generated.output_data
    if context is None or not isinstance(context.get("input_allowed"), bool):
        raise RuntimeError("NeMo input rail did not complete")
    input_allowed = context["input_allowed"]
    reason = context.get("input_reason")
    if not isinstance(reason, str):
        raise RuntimeError("NeMo input rail did not provide a reason")
    if not isinstance(generated.response, list) or not generated.response:
        raise RuntimeError("NeMo did not return a text response")
    response = generated.response[0].get("content")
    if not isinstance(response, str):
        raise RuntimeError("NeMo did not return a text response")
    jwt_count = 0
    if input_allowed:
        count = context.get("jwt_count")
        if type(count) is not int or count < 0:
            raise RuntimeError("NeMo output rail did not complete")
        jwt_count = count
    if count_jwts(response):
        raise RuntimeError("JWT-shaped output escaped redaction")
    output_blocked = input_allowed and jwt_count > 0
    if output_blocked:
        reason = f"redacted {jwt_count} JWT-shaped string(s)"
    return Result(
        source=payload["source"],
        payload_id=payload["payload_id"],
        payload=redact_output(payload["payload"]),
        framework="nemoguardrails",
        mode="recorded_response_replay",
        status="BLOCKED" if not input_allowed or output_blocked else "PASS",
        input_status="PASS" if input_allowed else "BLOCKED",
        output_status=("REDACTED" if output_blocked else "PASS")
        if input_allowed else "SKIPPED",
        reason=reason,
        jwt_count=jwt_count,
        response=response,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--payloads", type=Path, nargs="+",
        default=[LOGS / f"attack{number}_{name}.json" for number, name in (
            (1, "indirect_injection"), (2, "agent_spoofing"),
            (3, "prompt_extraction"), (4, "rag_poisoning"),
        )],
        help="JSON logs containing payload/prompt and recorded response strings",
    )
    parser.add_argument("--output", type=Path, default=HERE / "results" / "guardrail_results.json")
    args = parser.parse_args()
    payloads = load_payloads(args.payloads)
    rails = build_rails()
    results = [run_payload(rails, payload) for payload in payloads]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    for result in results:
        print(f"[{result['status']}] {result['source']}:{result['payload_id']} "
              f"input={result['input_status']} output={result['output_status']} "
              f"-> {result['reason']}")
    blocked = sum(result["status"] == "BLOCKED" for result in results)
    print(f"Recorded-response replay: {blocked} blocked, "
          f"{len(results) - blocked} passed. Results: {args.output}")


if __name__ == "__main__":
    main()
