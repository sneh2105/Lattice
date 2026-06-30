# AgentScan Evaluation Kit

Five canonical attack scenarios plus a safe baseline. This is what to run
to evaluate AgentScan before deploying it anywhere — including against
production-adjacent infrastructure.

## How to use this if you're evaluating AgentScan

```bash
git clone <this repo>
cd agentscan && pip install -e ".[dev]"
agentscan doctor examples/vulnerable_agents/01_prompt_injection   # confirm AgentScan knows what it's looking at
cd examples/vulnerable_agents
python run_benchmark.py   # runs all 7 vulnerable + 1 safe scenario, checks against documented thresholds
```

Every scenario has a `README.md` documenting: the attack chain, the exact
command to run, the expected output, and the recommended fix. None of
these scenarios touch real infrastructure — they're isolated config/code
fixtures with no live credentials, no network calls, no execution of the
"dangerous" tools themselves. AgentScan only ever performs static analysis.

## Scenarios

| # | Scenario | Tests | Min risk score |
|---|---|---|---|
| 01 | Prompt injection → shell | `agent` scanner, attack path detection | 50 |
| 02 | Credential exfiltration | `agent` scanner, multi-tool chaining | 70 |
| 03 | Shell execution (real source) | `source` scanner, AST extraction, file:line evidence | 40 |
| 04 | Database exfiltration via MCP | `mcp` scanner, no-auth detection | 60 |
| 05 | Financial fraud chain | `source` scanner, financial_transaction capability | 55 |
| — | Safe scoped agent (baseline) | False-positive check | must be 0 |

## Why this exists

Most security tooling evaluations end with "what did this catch that our
existing scanner didn't?" This kit makes that comparison concrete: run the
same 7 vulnerable agents through AgentScan and through whatever else you're
evaluating (Semgrep, Snyk, etc.), and compare what each one surfaces.
Generic SAST tools will flag `subprocess.run()` as a code smell; they won't
connect "this combined with secret access forms a credential exfiltration
path" — that's the attack-graph reasoning AgentScan adds.

## Keeping this honest

`run_benchmark.py` is the source of truth — it actually runs every scenario
and checks output against the documented thresholds. If a README claims a
result the scanner doesn't actually produce, the benchmark fails and that's
a bug to fix (in the scanner or the README), not something to paper over.
Run it after every change to the scanning logic.
