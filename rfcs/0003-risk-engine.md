# RFC 0003: Risk Scoring Engine

**Status:** Partially implemented -- current model documented below is
what actually runs today. The CVSS-style multi-factor model in the
"Proposed direction" section is **not yet built**. This distinction is
kept deliberately explicit throughout this document, because overclaiming
sophistication in a security tool's scoring methodology is worse than
having a simple, honestly-documented one.

**Location:** `agentscan/risk_register.py`, `agentscan/compliance/framework_mapper.py`

---

## What actually runs today

Two independent scores, both computed as a **flat per-finding severity
weight, summed and capped at 100.** No graph depth, no privilege level, no
exploitability sub-score, no attack complexity factor -- those are the
proposed direction (below), not the current implementation.

```python
_SEVERITY_WEIGHT = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 3, "INFO": 0}
```

**Residual technical risk (`raw_score`):** sum of `_SEVERITY_WEIGHT` over
every finding *except* ones confirmed `false_positive` or `remediated`.
Findings marked `accepted_risk` still count here -- the underlying risk
objectively still exists in the code; accepting it must never make the
number look like the code got safer.

**Governed risk (`governed_score`):** the same sum, but *also* excluding
`accepted_risk` findings. This is the number a reviewer who's done a
disposition pass should act on -- a documented, owned, reviewed risk is a
different governance state than an unreviewed one.

```python
def compute_governed_score(findings, raw_score=None):
    residual = [f for f in findings if f.status not in {"false_positive", "remediated"}]
    governed = [f for f in residual if f.status != "accepted_risk"]
    return {
        "raw_score": min(100, sum(_SEVERITY_WEIGHT[f.severity] for f in residual)),
        "governed_score": min(100, sum(_SEVERITY_WEIGHT[f.severity] for f in governed)),
        ...
    }
```

A separate, similarly simple weighting exists for compliance posture
specifically (`SEVERITY_PENALTY` in `framework_mapper.py`: `CRITICAL=22,
HIGH=14, MEDIUM=6, LOW=2`) -- slightly different weights because compliance
posture and raw technical risk are answering related but distinct
questions ("can we make a compliance claim" vs. "what does the code
expose"), and conflating them into one number was an earlier bug (see
`rfcs/0003`'s "History" section below).

### Why per-finding, not per-control

An earlier version of the compliance score weighted each *implicated
control* (not each finding) at a flat 25 points, uncapped per finding.
Since a single finding routinely maps to 4+ mandatory controls
simultaneously (RBI + DPDP + ISO 42001 + SOC 2 frequently regulate the same
underlying capability), one heavily-regulated finding could already
saturate the score to 0 regardless of how many total findings existed --
making the compliance score a de facto binary gate that never moved even
after resolving most of a scan's findings. Rewriting to weight per
*finding* (capped, using the finding's own severity) instead of per
*control implicated* fixed this. See the regression test
`test_compliance_score_moves_after_disposition` for the exact scenario
this was verified against (16 -> 58 after resolving 4 of 6 findings).

---

## Proposed direction (not yet built)

If this scoring model grows toward something closer to a CVSS-style
specification, the axes that would need to be added, and why each one is
currently missing information the model would need:

| Proposed factor | What it would capture | Why it's not in v1 |
|---|---|---|
| **Graph depth** | A finding reachable in 1 hop from an attacker-controlled entry point is more urgent than one reachable only via a 4-hop chain | The attack graph (RFC 0002) already computes path length and `_score_exploitability()` for *graph paths* specifically -- but this isn't fed back into the flat per-finding severity score, so two findings of the same severity are weighted identically regardless of how deep in the graph they sit |
| **Privilege level required** | A finding requiring an already-authenticated internal caller is different from one reachable from an unauthenticated prompt | Lattice does not currently model authentication/authorization boundaries as a graph property distinct from the entry-point/crown-jewel model |
| **Exploitability sub-score** | Distinct from severity -- how easy is this specific finding to actually trigger, independent of how bad the outcome would be | Partially exists as `AttackPath.severity` and the graph's `exploitability` field for *paths*, but not as an independent axis on individual findings |
| **Attack complexity** | Does exploitation require chaining multiple conditions, or is it a single-step trigger? | Related to graph depth above; not currently a scored, independent factor |
| **Confidence as a score multiplier** | A `LOW`-confidence CRITICAL finding (heuristic keyword match) currently scores identically to a `HIGH`-confidence CRITICAL finding (explicit `eval()` detection) | Confidence is displayed per finding (see [`DETECTION.md`](../DETECTION.md#severity-and-confidence)) but does not currently modulate the numeric score |

Building this properly would mean defining a scoring function of the form:

```
finding_score = f(severity, confidence, graph_depth, exploitability, attack_complexity)
```

rather than the current `finding_score = _SEVERITY_WEIGHT[severity]`, and
validating that the new function doesn't reintroduce the exact "score
doesn't move when it should" class of bug that motivated the per-finding
rewrite described above. Any contribution toward this should start with a
new RFC (0008 or later) proposing the specific weighting function and the
regression tests that would pin its behavior against known before/after
scenarios -- not a direct PR to `_SEVERITY_WEIGHT`.

---

## History (bugs that shaped this design)

- **v0.3.x:** raw score was passed through unchanged regardless of
  disposition -- marking a finding `false_positive` didn't change the
  number at all. Fixed by computing both scores fresh from the annotated
  finding list rather than accepting a pre-computed value as a parameter.
- **v0.4.5:** confirmed via direct test that all three non-`open` statuses
  behaved identically (all only affected the governed score). Per-status
  semantics (accepted stays in raw; false-positive/remediated removed from
  both) were introduced at this point.
- **v0.4.6:** the per-control (not per-finding) compliance scoring bug
  described above, discovered when a real disposition pass (5 of 7
  findings resolved) produced zero visible score movement.

Each of these is now a named regression test in `tests/unit/test_risk_register.py`
and `tests/unit/test_compliance.py` -- see those files for the exact
before/after assertions.
