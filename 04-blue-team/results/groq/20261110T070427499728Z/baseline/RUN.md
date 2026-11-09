# Reproduction

From the repository root:

```bash
.venv/bin/python run_lab.py compare --backend groq --baseline /workspaces/SecureNova/03-red-team/results/groq/20261110T070151699233Z/results.json
```

A fresh unique evidence directory is created on each run. All mock actions are in memory. Groq mode sends synthetic prompts to Groq; simulation never makes an inference request.
