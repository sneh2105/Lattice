# Scenario 05 — Fraudulent transaction via combined capabilities

**Attack chain:** Database lookup (account details) → wire transfer tool → fraud

## Setup
An OpenAI Agents SDK-style HR/finance agent that can look up account data
AND initiate wire transfers — a classic fraud chain if either tool's input
can be influenced by untrusted content.

## Run
```bash
agentscan source finance_agent.py
```

## Expected result
- Risk score: **≥55/100**
- CRITICAL finding: `initiate_wire_transfer` → `financial_transaction` capability
- Attack path: "Fraudulent transaction path"
- MITRE ATLAS: AML.T0051, AML.T0048

## The fix
Require human approval for any transaction above a threshold. Never let
an agent both read account data and initiate transfers without a
human-in-the-loop checkpoint.
