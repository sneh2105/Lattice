# Contributing to AgentScan

Thanks for contributing. AgentScan is Apache 2.0 licensed.

## Setup

```bash
git clone https://github.com/agentscan/agentscan
cd agentscan
pip install -e ".[dev]"
pytest tests/unit/
```

## Priority areas

- **Agent config parsers** — AutoGen, LangGraph, CrewAI format support in `agent_scanner.py`
- **npm scanner** — `supply_chain_scanner.py` has a placeholder; implement it
- **MITRE ATLAS mappings** — expand the technique library in `graph/nodes.py`
- **MCP server signatures** — add new dangerous tool patterns to `mcp_scanner_v2.py`
- **Integration tests** — scan real public MCP servers, add to `tests/integration/`

## Adding a finding

Every finding must have:
- `evidence` — at least one `Evidence` object with source, field, observed_value, explanation
- `remediation` — a concrete action (not "review this")
- `mitre_atlas` — at least one MITRE ATLAS technique
- `confidence` — HIGH only if structural evidence; MEDIUM for heuristics

## Running tests

```bash
pytest tests/unit/ -v
pytest tests/unit/ --cov=agentscan --cov-report=term-missing
```

## Pull requests

- One feature or fix per PR
- Tests required for new scanners or graph features
- Update `CHANGELOG.md` with a one-line summary
