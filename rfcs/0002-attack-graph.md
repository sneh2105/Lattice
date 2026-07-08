# RFC 0002: Attack Graph

**Status:** Implemented
**Location:** `agentscan/graph/engine.py`, `agentscan/graph/nodes.py`

## Problem

A capability inventory ("this agent has `shell_exec`, `secret_access`, and
`network_egress`") tells you what's theoretically possible. It doesn't tell
you the thing an attacker and a security reviewer both actually want to
know: **is there a real, connected chain from something an attacker
controls to something worth stealing?**

The difference matters concretely. An agent with a `shell_exec` tool and,
separately, a `secret_access` tool that are never callable in the same
conversation turn (because application logic gates them behind different
states) is a different risk profile from an agent where a single prompt
injection can trigger both in sequence. A capability list can't distinguish
these. A graph can.

## Decision

Model the agent's attack surface as a directed graph and ask graph
questions of it: reachability, shortest path, and blast radius -- the same
primitives used in classical attack-graph literature (Sheyner et al.,
Ammann et al.), applied to AI agent tool composition instead of network
host exploitation.

### Node types

```python
class NodeType(str, Enum):
    ENTRY_POINT = "entry_point"   # attacker-controlled input surface
    AGENT       = "agent"          # the LLM/agent itself
    MCP_SERVER  = "mcp_server"     # an MCP server the agent trusts
    TOOL        = "tool"           # a specific callable tool
    PROCESS     = "process"        # a spawned OS process / code execution runtime
    RESOURCE    = "resource"       # a file, database, or other data store
    NETWORK     = "network"        # an external network destination
    CROWN_JEWEL = "crown_jewel"    # something worth stealing (marked explicitly)
```

`code_execution` (eval/exec) and `shell_exec` (subprocess) are deliberately
distinct `PROCESS`-type nodes with different labels, not the same node --
they are different exploitation mechanisms with different remediation, and
collapsing them loses information a responder needs.

### Edge types

```python
class EdgeType(str, Enum):
    INJECTS     = "injects"      # attacker input reaches the agent
    CALLS       = "calls"        # agent invokes a tool
    READS       = "reads"        # tool reads a resource/credential
    WRITES      = "writes"       # tool writes to a resource
    EXECUTES    = "executes"     # tool executes code/commands
    EXFILTRATES = "exfiltrates"  # tool sends data to a network destination
    ESCALATES   = "escalates"    # tool escalates privilege (e.g. cloud API access)
    DEPENDS_ON  = "depends_on"   # structural dependency, not an attack step
    TRUSTS      = "trusts"       # cross-server trust relationship (MCP)
```

Each edge is weighted with a `confidence` (0.0-1.0) and, where applicable,
a list of MITRE ATLAS technique IDs.

### Graph construction: built from `attack_paths`, not independently derived

This is the single most important design decision in this RFC, because
getting it wrong is what caused a real, multi-round bug in this project's
history.

**What doesn't work:** building the graph from
`ScanResult.metadata["capabilities_detected"]` via a separately-maintained
capability-to-edge map, then running the graph's own pathfinding
independently of whatever `ScanResult.attack_paths` already computed. This
produces two parallel, divergent notions of "what attack paths exist" --
one used by the PDF/compliance/JSON output, one used by the graph -- that
can show different counts, different names, and can silently omit findings
that don't fit the graph's own capability-map assumptions. This is exactly
what happened to AST-behavioral findings like `eval()` detection, which had
no entry in the earlier capability-to-edge map and simply never appeared
as a graph node.

**What we do instead:** `build_graph_from_scan()` walks `ScanResult.attack_paths`
directly -- the exact list every other output format reads from -- and
`graph_paths_from_attack_paths()` converts each `AttackPath` into exactly
one `GraphPath`, one-to-one, bypassing the graph's own independent
pathfinding for this purpose entirely. See
[`ARCHITECTURE.md`](../ARCHITECTURE.md#attack-graph-built-from-attack_paths-not-re-derived)
for the full history of this bug and its fix, and
`test_graph_paths_exactly_match_pdf_attack_paths` for the regression test
that pins the invariant.

The graph's own pathfinding (`find_attack_paths()`, described below) is
still real and still used -- for graphs built directly via `add_node()`/
`add_edge()` calls (the trust-flow and cross-server-MCP subsystems, which
don't originate from a `ScanResult.attack_paths` list at all) -- but it is
not the mechanism the primary scan-to-graph pipeline uses.

### Graph algorithms

```python
def reachable_from(self, start_id, min_confidence=0.5) -> set[str]:
    """BFS from start_id, following only edges at or above min_confidence."""

def shortest_path(self, start_id, end_id, min_confidence=0.5) -> list[str] | None:
    """BFS shortest path between two specific nodes."""

def find_attack_paths(self, min_confidence=0.5) -> list[GraphPath]:
    """
    For every attacker-controlled entry point and every crown jewel,
    check reachability via BFS, then compute the shortest connecting path.
    Deduplicates by (entry, crown) pair, keeping the highest-scoring path.
    Sorted by composite_score = exploitability x impact, descending.
    """

def blast_radius(self, entry_id) -> dict:
    """
    From a single entry point, what is the total reach? Returns every
    crown jewel reachable and an aggregate impact score (capped at 100).
    This answers 'if an attacker controls this one entry point, how bad
    can it get in total' -- distinct from a single attack path, which
    answers 'what's the shortest way to one specific target.'
    """

def trust_score(self, node_id) -> dict:
    """
    0-100 trust score for a node (primarily MCP servers): starts at 100,
    penalized for TRUSTS edges into it from lower-trust sources and for
    missing authentication.
    """
```

Path scoring (`_score_exploitability`) is a function of edge confidence
values and path length -- a longer chain with lower-confidence edges scores
lower than a short, high-confidence chain to the same target, which is why
`find_attack_paths()`'s results are sorted with the most credible chain
first.

## Alternatives considered

**A flat list of (capability-pair) -> (attack path) rules with no graph at
all.** This is actually what `agent_scanner.py`'s `DANGEROUS_COMBINATIONS`
does, and it's the *source* of the `attack_paths` list the graph consumes
-- it's necessary but not sufficient. It can tell you "this agent has a
credential-exfiltration-shaped pair of tools" but can't answer
`blast_radius()`-style questions (aggregate reach from one entry point
across every possible target) or represent a chain longer than two hops.
The graph is what makes those questions answerable at all.

**A full formal attack-graph model with probabilistic edge weights and
Bayesian path scoring** (the more academically rigorous end of the attack
graph literature). Rejected for v1 as more machinery than the confidence
values Lattice's detection layer can actually produce honestly -- our
`confidence` values are `HIGH`/`MEDIUM`/`LOW` categorical judgments from
the detection layer, not calibrated probabilities, and pretending
otherwise with a probabilistic model would be a false precision claim.

## Consequences

- Any new detection mechanism that produces `AttackPath` objects (see RFC
  0001) is automatically graph-visible with no graph-specific code needed,
  because the graph is built from that list directly.
- A capability finding that never combines into a multi-tool `AttackPath`
  (e.g. a lone `eval()` finding with no paired capability) still needs
  explicit standalone-path handling in `build_graph_from_scan()` --
  otherwise it would be a real, CRITICAL finding with zero graph
  representation. This is handled (see `test_standalone_critical_finding_appears_as_graph_path`)
  but is a recurring category of edge case worth remembering when adding
  new detection rules.
- `AttackGraph.__init__` supports a `prepopulate` flag: `True` (default)
  pre-populates every known entry-point/crown-jewel node, which is what the
  trust-flow and MCP-trust-chain subsystems rely on when building a graph
  manually via `add_node()`/`add_edge()`. The scan-to-graph pipeline uses
  `prepopulate=False` and calls `prune_disconnected_nodes()` explicitly,
  because a graph built from real attack paths should never show a
  disconnected placeholder node with zero edges (this was itself a bug --
  see the "no orphan nodes" test).
