# Intermediate Representation

Every supported framework -- LangChain, CrewAI, AutoGen, MCP, n8n, and the
rest -- normalizes into the same two-layer intermediate representation
before any detection logic runs. This document explains that pipeline.
See [RFC 0001](rfcs/0001-capability-model.md) for the design reasoning
behind why this exists.

## The pipeline

```
LangChain @tool decorator
CrewAI BaseTool subclass (incl. wrapper inheritance)
AutoGen register_function()
OpenAI Agents SDK @function_tool
Google ADK before_model_callback
Semantic Kernel @sk.kernel_function
Amazon Bedrock Agents trace stream
Amazon Nova Act @tool
PydanticAI @agent.tool
LlamaIndex FunctionTool.from_defaults()
Haystack Tool()
Dify DSL (model_config.agent_mode.tools)
n8n workflow JSON
Flowise workflow JSON
MCP manifest / live server (JSON Schema tools)
Raw API schema (no framework)
            |
            |  each framework's native scanner (source_scanner.py /
            |  agent_scanner.py / mcp_scanner.py) extracts:
            |    - tool name
            |    - tool description / docstring
            |    - (source_scanner only) the AST body of the tool function
            v
    ExtractedTool  /  raw tool dict
       name: str
       description: str
       source_file, line_number (if from source code)
       framework_hint: str
            |
            |  _detect_capabilities() / AST behavioral walk / token
            |  co-occurrence check -- see DETECTION.md
            v
        Finding
          id: str                    (stable, derivable identity)
          title: str
          severity: Severity          (CRITICAL / HIGH / MEDIUM / LOW / INFO)
          confidence: ConfidenceLevel (HIGH / MEDIUM / LOW)
          tags: list[str]             <- THE capability vocabulary (RFC 0001)
          evidence: list[Evidence]
          explanation, impact, remediation: str
          mitre_atlas: list[str]
            |
            |  DANGEROUS_COMBINATIONS matching (agent_scanner.py /
            |  mcp_scanner.py): if a set of Findings' tags collectively
            |  satisfy a known dangerous capability pair, build:
            v
        AttackPath
          id, title, severity
          steps: list[Finding]        <- the SAME Finding objects, not copies
          entry_point, impact: str
          mitre_atlas: list[str]
            |
            v
        ScanResult
          target: str
          scanner_type: str
          findings: list[Finding]
          attack_paths: list[AttackPath]
          metadata: dict               (capabilities_detected, cap_to_tools,
                                         dependency_files, mcp_manifests_found, ...)
            |
            |  risk_register.annotate_finding_objects() attaches .status
            |  to each Finding IN PLACE (see below)
            v
   ================================================================
   Every consumer reads this ONE ScanResult -- see ARCHITECTURE.md
   ================================================================
            |
            +--> graph/engine.py::build_graph_from_scan()
            |      walks .attack_paths directly -> AttackGraph (RFC 0002)
            |
            +--> compliance/framework_mapper.py::map_findings_to_controls()
            |      walks .findings, filtered by disposition -> ComplianceReport
            |
            +--> compliance/dpia.py::generate_dpia()
            |      walks .findings / .attack_paths, filtered by disposition
            |
            +--> outputs/{terminal,json_output,html_report}.py
                   walk .findings / .attack_paths directly
```

## Why this shape specifically

**Two layers, not one.** `Finding` is the atomic unit -- "this one tool has
this one capability, with this evidence." `AttackPath` is a composition of
Findings -- "these particular Findings, taken together, form a complete
exploit chain." Keeping them as separate types (rather than, say, a single
`Finding` that sometimes represents a chain) means every consumer can
choose which granularity it needs: the Findings tab wants the atomic view,
the Attack Graph and PDF's "Critical Attack Paths" section want the
composed view, and both are always available from the same `ScanResult`
without re-deriving either from the other.

**`AttackPath.steps` holds the same `Finding` *objects*, not copies.** This
is a specific, load-bearing detail: because Python objects are references,
mutating a `Finding`'s `.status` attribute once (via
`annotate_finding_objects`) is visible through *every* `AttackPath` that
references that Finding, with no separate propagation step needed. This is
what makes disposition-awareness (accepting a risk, marking a false
positive) automatically consistent across the Findings tab, the Attack
Graph, and the Compliance/PDF output -- there's no second data structure
that could fall out of sync. Verified directly in `test_attack_path_steps_are_same_finding_objects_as_scan_result` (tests/unit/test_graph_engine.py).

**`tags: list[str]` is the only thing detection-consumers look at.**
Nothing downstream of Finding construction knows or cares which framework
produced a Finding. The Attack Graph's node-type mapper
(`_node_spec_for_finding`), the compliance control mapper
(`CONTROL_LIBRARY`), and the attack-chain matcher (`DANGEROUS_COMBINATIONS`)
all key exclusively on `finding.tags`. This is what RFC 0001 calls the
capability model, and it's the reason adding a new framework never requires
touching the graph, compliance, or attack-chain code at all -- see
[`EXTENDING.md`](EXTENDING.md).

**`metadata: dict` is the escape hatch, deliberately unstructured.**
Framework-specific or scan-specific data that doesn't fit the Finding/
AttackPath model (discovered dependency files, MCP manifest paths, raw
capability lists for debugging) lives here rather than being forced into
the typed model. This is a pragmatic choice, not a purity one -- it means
new scan-time context can be added without a schema migration, at the cost
of `metadata` not being type-checked the way `Finding`/`AttackPath` are.

## A worked example

A LangChain tool and an MCP manifest tool, both granting shell execution,
normalize to structurally identical `Finding` objects at the tag level:

```python
# From source_scanner.py, parsing:
#   @tool
#   def run_shell(cmd: str) -> str:
#       """Run a shell command."""
#       import subprocess
#       return subprocess.run(cmd, shell=True).stdout
Finding(
    id="AGT-CAP-SHELL_EXEC-RUN_SHELL",
    title="Tool 'run_shell' grants shell execution",
    severity=Severity.CRITICAL,
    tags=["tool-permissions", "shell_exec", "source-extracted"],
    ...
)

# From mcp_scanner.py, parsing an MCP manifest with a "run_shell" tool
# entry -- NOTE: MCP's own tag vocabulary is aliased onto the standard
# one here, not migrated to use it directly yet (see RFC 0001's
# "Consequences" section for this known technical debt):
Finding(
    id="MCP-SHELL-RUN_SHELL",
    title="MCP tool exposes shell execution: 'run_shell'",
    severity=Severity.CRITICAL,
    tags=["mcp-tool", "MCP-SHELL"],   # aliased to "shell_exec" at graph-consumption time
    ...
)
```

Both are `shell_exec`-tagged (directly or via the MCP alias table) by the
time anything downstream looks at them -- the graph, the compliance
mapper, and the attack-chain matcher treat a LangChain shell tool and an
MCP shell tool identically, which is exactly the point of having one
capability vocabulary instead of per-framework ones.
