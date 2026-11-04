# MITRE ATLAS technique mapping
## Tree 1: LLM API key exfiltration
- **Technique ID:** AML.T0051.001
- **Name:** LLM Prompt Injection: Indirect
- **Why it fits:** the primary path in this tree is a malicious instruction hidden
 inside a document the agent later reads, not a prompt typed directly by the user —
 this is the defining trait of the indirect sub-technique.
- **Source:** https://atlas.mitre.org/techniques/AML.T0051.001
## Tree 2: Agent identity spoofing
- **Technique ID:** AML.T0055
- **Name:** Unsecured Credentials
- **Why it fits:** the attack relies on a long-lived or unsigned M2M token /
 orchestrator message being reused or forged because the agent has no way to
 cryptographically verify sender identity — a credential-security gap rather
 than a model-manipulation technique.
- **Source:** https://atlas.mitre.org/techniques/AML.T0055
## Tree 3: RAG chunk poisoning
- **Technique ID:** AML.T0070
- **Name:** RAG Poisoning
- **Why it fits:** the attacker injects malicious content into the retrieval
 knowledge base, which the agent then retrieves and treats as an instruction —
 this directly matches the RAG poisoning technique.
- **Source:** https://atlas.mitre.org/techniques/AML.T0070