# Extending Lattice: Adding a New Framework

Step-by-step for adding support for an agent framework Lattice doesn't yet
cover. If you're extending detection logic instead (new capability, new
attack chain), see [`DETECTION.md`](DETECTION.md) and
[`rfcs/0001-capability-model.md`](rfcs/0001-capability-model.md) first --
this guide is specifically about framework support.

Read [`INTERMEDIATE_REPRESENTATION.md`](INTERMEDIATE_REPRESENTATION.md)
before starting. The one-sentence version of what you're building: **a
translator from the new framework's native tool-definition syntax into
`Finding` objects carrying tags from the shared capability vocabulary.**
You are never inventing a new vocabulary, a new detection mechanism, or a
new output format.

## Step 1: Identify the extraction point

Two cases:

**The framework is Python source code** (a decorator, a class, a
registration function call) -> you're extending `source_scanner.py`.

**The framework is a declarative config format** (YAML, JSON, a workflow
export) -> you're extending `agent_scanner.py`'s `_extract_tools()`.

Look at how an existing, similar framework is handled first. If the new
framework uses a decorator like LangChain's `@tool`, look at how that's
matched in `source_scanner.py`. If it's a no-code JSON export like n8n or
Dify, look at those specific branches in `agent_scanner.py`.

## Step 2: Write the visitor / extraction logic

**For source code (AST-based):**

Add the decorator/class/call pattern to the relevant constant
(`TOOL_DECORATOR_NAMES`, `TOOL_REGISTRATION_CALLS`) or, if the pattern is
structurally different from what's already handled (e.g. it requires
inspecting a method call's keyword arguments rather than a decorator),
add a new `visit_*` method to the AST `NodeVisitor` class in
`source_scanner.py`.

If the framework requires resolving one level of indirection (e.g. an
internal wrapper class, similar to the CrewAI `BaseTool` wrapper-class
case already handled), follow the same three-pass pattern already used:
collect import aliases, identify abstract wrapper classes, then walk again
treating those wrapper names as additional known bases. See
[RFC 0001](rfcs/0001-capability-model.md) and the existing wrapper-class
code in `source_scanner.py` for the exact pattern.

**For declarative configs:**

Add a branch to `_extract_tools()` in `agent_scanner.py` that recognizes
the new format's structure (usually: some nested key path to a list of
tool-shaped dicts) and normalizes each entry into the same
name/description shape the rest of the function expects.

## Step 3: Extract name + description, nothing else

At this extraction stage, you're only pulling out:
- The tool's name
- Its description/docstring (or the closest equivalent -- a field, a
  comment, whatever the framework uses to say what the tool does)
- (Source scanner only) A reference to the function's AST body, so
  behavioral detection (Step 4) can walk it

You are **not** deciding whether the tool is dangerous at this stage --
that's the capability detection layer's job, and it's shared across every
framework already (see Step 4). If you find yourself writing keyword
matching or a dangerous-function check specific to your new framework,
stop -- that logic belongs in `capabilities.py`, applied uniformly, not
duplicated per-framework. This exact duplication is the mistake
[RFC 0001](rfcs/0001-capability-model.md) exists to prevent.

## Step 4: Confirm capability detection "just works"

Once your extracted tool reaches `_detect_capabilities()` (called
uniformly regardless of which scanner produced the tool), keyword
matching, token co-occurrence, and (for source-scanned tools) AST
behavioral detection all apply automatically. You should not need to write
any new detection logic for a new framework -- if a real, obviously
dangerous tool in your new framework's syntax *isn't* getting flagged, the
gap is almost certainly in Step 2/3 (the tool isn't being extracted
correctly, or its description isn't reaching the detection layer), not in
the detection logic itself.

## Step 5: Add framework detection to `doctor.py`

So `agentscan doctor .` can tell a user "yes, I see a `<new framework>`
agent here" before they commit to a specific scan command. Add the
framework's characteristic import/signature to `FRAMEWORK_SIGNATURES`.

## Step 6: Write tests

- A test in `tests/unit/test_source_scanner.py` (or `test_agent_scanner.py`
  for declarative formats) that builds a real fixture file in the new
  framework's syntax and asserts the expected tool(s) and capability
  tag(s) are extracted correctly.
- If the framework has a dangerous-pattern edge case worth pinning (e.g.
  a naming convention that could produce a false positive/negative), add
  that as an explicit regression test -- see the existing
  `test_real_typosquats_still_caught` /
  `test_langchain_not_flagged_as_typosquat` pair in
  `test_supply_chain_scanner.py` for the shape this should take.
- Add a fixture file to `examples/test_batch/` for manual/exploratory
  testing distinct from the pytest fixtures.

## Step 7: Add an eval-kit scenario (recommended, not required)

A documented attack scenario using the new framework is worth more than a
unit test alone -- it's runnable evidence, not just an assertion. See
[`CONTRIBUTING.md`](CONTRIBUTING.md#3-new-eval-kit-scenarios) for the exact
steps (create `examples/vulnerable_agents/NN_name/`, add to `SCENARIOS` in
`benchmark.py`, update the scenario count in `README.md`/`BENCHMARKS.md`).

## Step 8: Update the framework table

`README.md`'s "Supported frameworks" list and the table in
[`BENCHMARKS.md`](BENCHMARKS.md) should both mention the new framework once
it's tested and working.

## Done

Run the full check before opening a PR:

```bash
pytest tests/unit/ -q      # must pass, including your new tests
agentscan benchmark          # must still show 12/12 (or more, if you added a scenario)
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full PR checklist,
including the Windows-compatibility constraints (pure ASCII source, no
f-string quote nesting) that apply to any new Python file you add.
