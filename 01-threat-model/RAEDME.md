# 01 — Threat Model
Covers the SecureNova AI Identity Security threat model: identity inventory,
STRIDE-based DFD, three attack trees, full STRIDE matrix, risk register,
and MITRE ATLAS technique mapping.
- `identity-inventory/` — the 6 identities, their auth mechanism and privilege level
- `dfd/` — Threat Dragon data-flow diagram with 3 trust boundaries
- `attack-trees/` — LLM key exfiltration, agent spoofing, RAG poisoning
- `stride-matrix/` — full STRIDE matrix across all 9 data flows
- `risk-register/` — all threats scored (Likelihood x Impact), ranked, with owners
- `atlas-mapping/` — MITRE ATLAS technique IDs for each attack tree
- `screenshots/` — evidence captures used in Project1.pdf