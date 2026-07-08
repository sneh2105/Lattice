# Design Philosophy

The README says what Lattice does. This page says why it exists and the
positions it deliberately takes -- the things you'd only learn by talking
to whoever built it, written down instead.

## Why this exists

Every AI agent security conversation eventually turns into a permission
checklist: does the agent have shell access, does it have secrets, does it
touch the network. Checklists are comfortable because they're easy to
audit and easy to build tooling around. They are also the wrong question.

An attacker doesn't care about your checklist. An attacker who controls a
prompt cares about one thing: **what is the shortest path from here to
something valuable.** A checklist tells you an agent has three risky
capabilities. It doesn't tell you whether those three capabilities connect
into a single exploitable chain, or sit in unrelated, never-co-invoked
parts of the codebase. Those are enormously different risk profiles that
look identical on a checklist.

Lattice exists because the industry kept answering "is this dangerous" with
a list of yes/no flags, and the actually useful answer is a graph.

## Positions this project takes, on purpose

**Static analysis over LLM-based scanning, even though an LLM would catch
more novel obfuscation.** Determinism is not negotiable for a security
tool whose output feeds a CI/CD gate -- `--fail-on HIGH` has to mean the
same thing on every run, and drift detection requires comparing two scans
that were produced the same way. An LLM-based scanner can't promise that.
See [`ARCHITECTURE.md`](ARCHITECTURE.md#why-ast-based-static-analysis-not-an-llm-based-scanner).

**A wrong-but-honest "coverage gap" over a clean scan we can't stand
behind.** If Lattice sees framework imports it can't map to any concrete
tool registration, it says so, at `MEDIUM` severity, naming what it tried.
It does not report zero findings and let that read as "verified safe." A
scanner's silence should never be mistaken for a guarantee.

**Findings never disappear, even when resolved.** A finding marked
accepted, false-positive, or remediated stays visible in every report,
moved to a clearly-labeled section, with the full reasoning (who, when,
why) attached. Hiding a reviewed finding would make the audit trail less
complete than the original, unreviewed scan -- which defeats the purpose
of having a review process at all.

**Two risk numbers, not one, once anything has been reviewed.** Accepting
a risk must never make the underlying code look objectively safer than it
is -- the risk is real, you've just chosen to tolerate it with a
compensating control. Only a confirmed false positive or a confirmed fix
should move the number that describes what the code actually contains.
Collapsing "residual risk" and "governed risk" into one score would let a
disposition decision quietly rewrite history.

**Say what's out of scope as clearly as what's in scope.** The
[`THREAT_MODEL.md`](THREAT_MODEL.md) spends as many words on what Lattice
does *not* catch -- runtime prompt injection, model-level red-teaming,
TypeScript agents, AI gateway config -- as on what it does. A security
tool that implies broader coverage than it has is a worse tool than one
that's precise about its edges, because the gap only surfaces at the worst
possible time: after an incident, not during evaluation.

**One canonical function per concern, enforced by convention, not by a
type system.** `_build_merged_result()` for "what did we find,"
`filter_by_disposition()` for "what's still open." Every consumer -- the
dashboard, the PDF, the compliance report, the attack graph -- calls the
same function rather than re-deriving its own version. This project
learned this lesson the expensive way, three separate times, before
writing it down as a rule. See [`ARCHITECTURE.md`](ARCHITECTURE.md) for
the specific bugs each violation caused.

**Local-first, not a hosted product.** The entire premise is that your
code doesn't leave your machine. A hosted "paste your repo here" version
would either be a fake canned demo or require rebuilding the tool as a
sandboxed, upload-only, rate-limited service -- a legitimately different
product, not a deployment option for this one. See
[`ROADMAP.md`](ROADMAP.md#explicitly-not-planned).

## What "done" looks like for a finding

Not "flagged." A finding is done when a human has looked at it and it's in
one of four states -- open, accepted with a documented compensating
control, confirmed false, or confirmed fixed -- each with a name and a
reason attached. A pile of unreviewed CRITICAL findings that nobody has
triaged is not meaningfully safer than having run no scanner at all; the
review step is not optional overhead, it's the actual point.
