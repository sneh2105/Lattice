# RFC 0004: Trust Flow and Cross-Server Trust

**Status:** Implemented. Less battle-tested than RFC 0001/0002/0003 --
this subsystem has seen less adversarial testing than the core scan
pipeline, and is not currently wired into the dashboard.
**Location:** `agentscan/graph/trust_flow.py` (single-agent trust
boundaries), `agentscan/scanners/mcp_trust_chain.py` (cross-server MCP
trust propagation)

## Problem

The attack graph (RFC 0002) answers "is there a connected path from an
entry point to a crown jewel." It does not, by itself, answer a related
but distinct question: **does data flow from an untrusted source to a
privileged sink without passing through anything that would sanitize or
validate it along the way?**

This matters because not every edge in the graph is equally dangerous. An
agent that reads a user's message and passes it, unmodified, into a SQL
query has a trust-boundary violation a content-filtered, validated pipeline
doesn't. The attack graph alone doesn't distinguish these two cases if both
happen to have the same node/edge shape.

A second, related problem is specific to MCP: when an agent trusts
multiple MCP servers, and those servers themselves call each other, trust
should not be assumed to propagate cleanly. A well-configured server that
calls into a poorly-configured one inherits some of that server's risk.
Neither the single-scan attack graph nor the trust-flow model above
addresses this, because both operate on one server/agent's data at a time.

## Decision: two related but separate models

### 1. Trust flow within a single agent (`trust_flow.py`)

A four-level trust lattice, classified per node:

```python
class TrustLevel(str, Enum):
    UNTRUSTED   = "untrusted"    # user input, tool results, RAG docs, external data
    SEMI_TRUSTED = "semi_trusted" # internal memory, prior agent outputs
    TRUSTED     = "trusted"       # system prompt, hardcoded config
    PRIVILEGED  = "privileged"    # crown jewels -- the sinks we care about
```

`analyse_trust_flow(graph)` walks every edge in an already-built
`AttackGraph`, classifies the trust level on each side, and flags any edge
where data flows from a lower trust level to a higher one (`UNTRUSTED ->
PRIVILEGED` being the worst case) **unless** an intervening node matches a
known sanitization pattern (`SANITISATION_MARKERS`: guardrail, validator,
sanitiser, filter, allowlist, etc., checked against node labels and
properties).

This is deliberately modeled after the classical Bell-LaPadula
"no read up / no write down" lattice from multi-level security, applied to
data provenance in an agent's tool graph instead of process/file
permissions.

### 2. Cross-server MCP trust propagation (`mcp_trust_chain.py`)

A separate model for the specific case of multiple MCP servers that call
each other. Each server gets a `declared_trust` score (from the same
`trust_score()` logic used in RFC 0002's single-graph model -- based on
authentication configuration and its own tool risk profile), and then trust
*propagates* through declared or inferred call relationships:

```python
chain = MCPTrustChain()
chain.add_server("https://mcp.server-a.com")
chain.add_server("./server_b.json")
chain.declare_calls("server-a", "server-b")   # A calls B
report = chain.analyse()
```

The key output is `effective_trust` per server -- its own trust score,
reduced by how much lower-trust servers it depends on "poison" it. A
well-configured server (`declared_trust=90`) that calls into an
unauthenticated one (`declared_trust=20`) does not keep its own high score;
`effective_trust` reflects the weakest link in its dependency chain, and
`poisoned_by` names exactly which server(s) caused the reduction.

`CrossServerPath` objects represent attack paths that specifically cross a
server boundary -- distinguishing "compromise achievable entirely within
one server" from "requires chaining through a second, separately-operated
server," which matters for whose team owns the fix.

## Why two separate models instead of one

They operate on different data shapes. Trust flow analyzes a single
already-built `AttackGraph`'s internal edges. Cross-server trust chain
analyzes a *set of servers* and the declared/inferred relationships
*between* them, building a unified graph as an output rather than taking
one as input. Merging them into one model would require either flattening
cross-server relationships into single-agent graph edges (losing the
distinct "which server owns this risk" information) or teaching the
single-agent trust-flow model about a concept (multiple independently
administered servers) it has no other reason to know about.

## Consequences and known limitations

- **Sanitization detection is pattern-matched on node labels/properties,
  not verified.** A node labeled `content_filter` is trusted to actually
  filter content -- there's no way for a static analyzer to confirm a
  function called `sanitize_input()` actually sanitizes anything. This is
  the same class of assumption documented in
  [`THREAT_MODEL.md`](../THREAT_MODEL.md#assumptions-and-their-failure-modes)
  for the rest of the detection pipeline.
- **Trust propagation currently uses declared or inferred call
  relationships** (`chain.declare_calls(...)`) rather than automatically
  discovering them from code -- there is no automatic detection of "server
  A's code calls server B" yet. A user must declare the relationship
  explicitly for cross-server analysis to run.
- **Not wired into the dashboard.** This is CLI/API-only currently (via
  `MCPTrustChain` directly, or `agentscan graph` subcommands that expose
  parts of it) -- see [`ROADMAP.md`](../ROADMAP.md) for the plan to surface
  this in the dashboard's Attack Graph tab.
