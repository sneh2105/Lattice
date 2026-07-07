# Benchmarks

## The evaluation kit

`agentscan benchmark` runs 12 scenarios against bundled fixtures in
[`examples/vulnerable_agents/`](examples/vulnerable_agents/): 11 intentionally
vulnerable agents covering a distinct attack pattern each, plus one safe
baseline. Every scenario documents its expected risk score, expected attack
path count, and *why* -- see each scenario's own `README.md`.

Run it yourself:

```bash
pip install -e ".[dev]"
agentscan benchmark
```

## Current results (v0.4.6)

```
  Scenario                             Risk     Paths    Status
  ------------------------------------ -------- -------- ----------
  Prompt injection -> shell            56       1        PASS
  Secret exfiltration                  76       2        PASS
  Shell exec (real source code)        40       0        PASS
  Database exfil via MCP               48       1        PASS
  Financial fraud chain                60       1        PASS
  Amazon Nova Act credential + shell   100      6        PASS
  Custom in-house agent (no framework) 100      3        PASS
  No-code platform export (Dify-style) 100      2        PASS
  PydanticAI + LlamaIndex              88       3        PASS
  n8n workflow (no-code)               100      5        PASS
  Haystack agent                       100      2        PASS
  Safe scoped search agent             0        -        PASS

  12/12 scenarios passed
```

**Zero false positives on the safe baseline** -- a well-scoped, read-only
search agent scores 0/100 with no findings. This is the benchmark that
matters most: a scanner that flags calculators and weather lookups as
CRITICAL is worse than no scanner, because it trains reviewers to ignore
its output.

Two scenarios (`Shell exec (real source code)`, `Haystack agent`) show a
nonzero risk score with fewer attack paths than you might expect from the
capabilities present -- this is correct, not a gap. A single-capability
agent (shell access alone, with nothing to chain it to) doesn't form a
combination-based attack path per the rules in
[`DETECTION.md`](DETECTION.md#attack-chain-rules-dangerous_combinations),
even though the individual finding is still reported at full severity.

## What "PASS" means here

Each scenario has a documented *minimum* expected risk score and expected
attack-path presence (not exact-match) -- the benchmark is checking "did
detection work at all," not "does the score match to the decimal." See
`agentscan/benchmark.py`'s `SCENARIOS` list for the exact thresholds, and
each scenario's own README for the reasoning behind that threshold.

## Test suite

274 unit tests, `pytest tests/unit/ -q`. Breakdown by area:

| Area | What's covered |
|---|---|
| Scanners (source/agent/mcp/supply chain) | Every supported framework pattern, wrapper-class inheritance, AST behavioral detection, keyword/token co-occurrence edge cases (typosquat false positives, shell-verb token pairs) |
| Attack graph | Path/node/edge construction from `attack_paths`, no-orphan-nodes invariant, no-duplicate-hop invariant, distinct node types for `eval()` vs `subprocess` |
| Compliance / DPIA | Control mapping, posture/score computation, disposition-awareness (score must move after a finding is dispositioned) |
| Risk register | All 4 disposition states, expiry handling, raw vs governed scoring math |
| Drift detection | Fingerprint stability under re-worded findings, new/resolved/escalated classification |
| CLI | Every subcommand, exit code contract, Windows-specific encoding/path handling |
| Dashboard backend | Every `/api/*` route, GitHub clone-and-scan, canonical merged-result consistency across Compliance/PDF/SARIF/Graph |

## Adversarial testing

Beyond the standard benchmark, the following adversarial inputs have been
tested and pass without crashing, hanging, or silently producing a wrong
result:

- Case-sensitivity variants (`RUN_SHELL_COMMAND`, `FetchCloudSECRET`)
- Terminal escape-sequence injection in tool docstrings (ANSI codes
  attempting to spoof output or corrupt the terminal)
- A 2MB file with 20,001 tools, one genuinely dangerous tool buried at the
  end (scanned in ~2.4s, correctly identified)
- 3,000-level deep nested JSON (no stack overflow, no hang)
- Circular filesystem symlinks (no infinite loop)
- Two tools sharing an identical name with different capabilities (both
  tracked and reported separately)
- Unsupported languages (e.g. TypeScript/Mastra) -- reports an honest
  "not yet supported" rather than a false-clean scan

## Benchmark your own fork

If you add framework support or change detection logic, run the full suite
plus the benchmark before opening a PR:

```bash
pytest tests/unit/ -q      # must show 274 passed (or more, if you added tests)
agentscan benchmark          # must show 12/12
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full PR checklist.
