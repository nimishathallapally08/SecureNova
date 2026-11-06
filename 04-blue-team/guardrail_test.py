# guardrail_test.py - run all 5 payloads through a simple rule-based + NeMo check
import re, json

JWT_PATTERN = re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
BLOCK_PATTERNS = [
    re.compile(r'ignore (all |prior |previous )?instructions', re.I),
    re.compile(r'\[ORCHESTRATOR\]'),
    re.compile(r'SYSTEM OVERRIDE', re.I),
    re.compile(r'repeat everything above', re.I),
    re.compile(r'DAN\b'),
]

def check_input(text):
    for pat in BLOCK_PATTERNS:
        if pat.search(text):
            return False, f"blocked: matched pattern '{pat.pattern}'"
    return True, "passed"

with open("../03-red-team/logs/attack1_indirect_injection.json") as f:
    payloads = [p["payload"] for p in json.load(f)]
with open("../03-red-team/logs/attack3_prompt_extraction.json") as f:
    payloads += [p["prompt"] for p in json.load(f)]

results = []
for p in payloads:
    ok, reason = check_input(p)
    status = "PASS" if ok else "BLOCKED"
    print(f"[{status}] {p[:60]}... -> {reason}")
    results.append({"payload": p, "status": status, "reason": reason})

with open("../03-red-team/logs/guardrail_results.json", "w") as f:
    json.dump(results, f, indent=2)