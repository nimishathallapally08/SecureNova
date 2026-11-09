# Red-team report

## Executive summary

Fresh synthetic Groq inference on the integrated mock application. No saved response replay; blocked inputs do not invoke the model. No real backend accounts or Auth0 permissions are modified. Indirect cases use an intentionally vulnerable system prompt permitting synthetic JWT disclosure, not the protected baseline. The same setup is used after controls; blocked inputs do not reach Groq.

Tested 11 adversarial cases. 3 met the lab success rubric before controls; 0 did after controls. These results are for a deliberately vulnerable mock lab, not a production assessment.

## Scope and evidence

All credentials are synthetic and all privileged actions use an in-memory lab-user ledger. No external MCP server or real refund/deletion is involved. Baseline system secret is intentionally fake. Failures and refusals remain failures; they are not promoted to findings. The ordinary refund negative control is excluded from attack denominators.

## Findings

- [indirect_injection](FINDING-indirect_injection.md)
- [agent_spoofing](FINDING-agent_spoofing.md)
- [prompt_extraction](FINDING-prompt_extraction.md)
- [role_elevation](FINDING-role_elevation.md)
- [rag_poisoning](FINDING-rag_poisoning.md)

## Top three hardening recommendations

1. Authenticate agent messages with Ed25519 over sender, recipient, scope, expiry, nonce, and message. Enforce server-side privilege scopes; never trust headers or model role assertions.
2. Treat documents as data: validate retrieval inputs, apply NeMo input rails, redact JWT-shaped output, and enforce a mock tool allowlist and target validation independently of the model.
3. Use short-lived access tokens (300 seconds), rotating refresh tokens, risk-based login policy, and per-identity anomaly monitoring. Verify Auth0 in a test tenant separately; local tests cannot prove deployed settings.

## Sources and limitations

- [MITRE ATLAS October 2026](https://github.com/mitre-atlas/atlas-data/blob/main/dist/v6/ATLAS-2026.10.yaml)
- [FIRST CVSS 3.1 specification](https://www.first.org/cvss/v3.1/specification-document)
- CVSS scores describe stated hypothetical deployment impact, not actual production compromise. Each successful family includes its full vector and FIRST calculator URL.
- Five extraction techniques are attempts, not guaranteed successes. Review full responses for paraphrased leaks not captured by exact-marker scoring.
