# RFC 0001: Capability Model

**Status:** Implemented
**Location:** `agentscan/scanners/capabilities.py`

## Problem

Every agent framework has its own vocabulary for what a tool does.
LangChain's `@tool` decorator wraps a function with a docstring. CrewAI's
`BaseTool` subclass has a `description` field. MCP manifests describe tools
via JSON Schema. n8n exports nest tool definitions inside a workflow node
graph. None of these formats agree on how to say "this tool can execute
shell commands" or "this tool can read secrets."

If each scanner (`source_scanner.py`, `agent_scanner.py`, `mcp_scanner.py`)
invented its own answer to "is this tool dangerous," three things would go
wrong:

1. **Divergence.** A fix for a false positive in the source scanner
   wouldn't apply to the same false positive pattern in the MCP scanner.
   This happened in practice, twice, before this RFC's design was adopted --
   see the changelog entries for the `refund`/`run` keyword bugs.
2. **No cross-scanner attack chains.** If `source_scanner` calls a tool
   "shell-ish" and `mcp_scanner` calls the same kind of tool "exec-capable,"
   you can never build an attack path that spans a Python agent calling out
   to an MCP server, because the vocabularies don't line up.
3. **No single place to reason about detection accuracy.** Every
   capability-keyword false positive/negative bug this project has hit
   (`query_prod_db` flagged as shell exec because of the substring "run";
   `calculate_refund_estimate` flagged as a financial transaction because
   of the substring "refund") required a fix that could only be verified
   correct if there was one keyword list, not three.

## Decision

One canonical capability vocabulary, defined once, imported by every
scanner:

```python
# agentscan/scanners/capabilities.py
CAPABILITY_MAP = {
    "shell_exec": {...},
    "code_execution": {...},
    "secret_access": {...},
    "cloud_api": {...},
    "network_egress": {...},
    "database": {...},
    "file_read": {...},
    "file_write": {...},
    "email_send": {...},
    "financial_transaction": {...},
}
```

Every scanner's job is reduced to: **map whatever this framework's native
tool representation looks like into a `Finding` object carrying zero or
more of these capability tags.** The capability tags are the only thing
downstream systems (attack path detection, the graph engine, compliance
control mapping) ever look at. None of them know or care whether a finding
came from a LangChain `@tool` decorator, a raw MCP manifest, or an n8n
workflow node.

### Detection is two-stage, not one

A single detection mechanism (keyword matching alone) has an unavoidable
tradeoff: loosen the keywords and you get false positives (`query_prod_db`
flagged for `shell_exec` because its description says "run a query");
tighten them and you get false negatives (`run_remediation_script` missed
because "remediation" sits between the verb and the target token).

The resolution: two independent, additive detection mechanisms per
capability.

1. **Keyword/phrase matching** on the tool's normalized name + description
   -- fast, catches the obvious cases.
2. **Token co-occurrence** (currently implemented for `shell_exec`) --
   splits the name+description into tokens and checks for co-occurrence of
   a verb-class token (`run`, `exec`, `invoke`) and a target-class token
   (`script`, `command`, `process`) *anywhere* in the tool, not adjacent.
   This is what correctly distinguishes `run_remediation_script` (flagged)
   from `query_prod_db` (not flagged) without re-introducing the bug either
   fix alone created.
3. **AST behavioral detection** (source scanner only) -- walks the actual
   function body for calls to a fixed list of dangerous stdlib/SDK
   functions (`eval`, `exec`, `subprocess.run`, `boto3.client("secretsmanager")`),
   independent of what the function is named or documented as doing. This
   is the layer that catches a tool named `utility_helper` with a bland
   docstring that calls `eval()` internally.

See [`DETECTION.md`](../DETECTION.md) for the full mechanics of each layer.

## Alternatives considered

**Per-scanner capability detection, reconciled at the graph layer.**
Rejected: this defers the divergence problem rather than solving it, and
every "reconciliation" layer added another place a fix could apply to one
scanner's vocabulary but not another's.

**A single regex/keyword list with no token co-occurrence layer.**
Rejected: tested this in an earlier version. It cannot simultaneously catch
`run_remediation_script` and reject `query_prod_db` -- any keyword list
permissive enough to catch the former also catches the latter, and any
keyword list tight enough to reject the latter also misses the former. See
`test_supply_chain_scanner.py::test_real_typosquats_still_caught` and the
adjacent tests for the specific regression tests that pin this behavior.

**LLM-based capability classification** (ask a model "does this tool
description imply shell access?"). Rejected for the same reasons covered in
[`ARCHITECTURE.md`](../ARCHITECTURE.md#why-ast-based-static-analysis-not-an-llm-based-scanner):
breaks determinism, adds API cost and a data-leaves-the-machine dependency,
and isn't auditable the same way a fixed rule set is.

## Consequences

- Adding a new framework means writing a translator from that framework's
  native format into `Finding` objects carrying the shared capability tags
  -- never inventing a new vocabulary. See [`EXTENDING.md`](../EXTENDING.md).
- A capability keyword fix made once in `capabilities.py` applies to every
  scanner simultaneously. This is now enforced by convention, not by a
  type system -- a scanner that hardcodes its own keyword list instead of
  importing from `capabilities.py` would compile fine and silently
  reintroduce the divergence problem. Reviewers should treat a
  scanner-local keyword list as a request-changes signal in PR review.
- MCP's native tag vocabulary (`MCP-SHELL`, `MCP-DATABASE`, etc.) is a
  known exception -- it predates this RFC and is aliased onto the standard
  vocabulary at the points that need a unified view (see
  `_MCP_TAG_TO_CAPABILITY` in `graph/engine.py`), rather than having been
  migrated to use `capabilities.py` directly. This is technical debt, not
  a design choice -- tracked in [`ROADMAP.md`](../ROADMAP.md).
