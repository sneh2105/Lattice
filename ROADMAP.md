# Roadmap

What's stable today, what's actively being worked on, and what's explicitly
not planned. Updated as of v0.4.6.

---

## Stable and production-ready

- **Static scanning** (`source`, `agent`, `mcp`, `supply`) across 17
  agent/no-code frameworks -- see the framework table in
  [`README.md`](README.md#supported-frameworks)
- **Attack path detection** via capability combinations, with AST
  behavioral detection to catch obfuscated/vaguely-named dangerous tools
- **CI/CD integration** -- SARIF export, `--fail-on` gating, GitHub Actions
  and Bitbucket Pipelines examples
- **Compliance mapping** -- RBI/DPDP/ISO 42001/EU AI Act/NIST AI RMF/SOC
  2/SEBI CSCRF, with a PDF audit report generator
- **The dashboard** (`agentscan ui`) -- local web UI, GitHub clone-and-scan,
  attack graph visualization, risk disposition workflow, drift detection

## Actively being hardened

- **Runtime monitoring SDK** (`agentscan runtime`) -- functional for
  LangChain/CrewAI/AutoGen/OpenAI-based agents but not yet wired into the
  dashboard, and the static-vs-runtime finding correlation is still manual
- **Cross-server MCP trust chains** -- detecting attack paths that span
  multiple MCP servers is implemented but has seen less adversarial testing
  than the single-scan paths above

## Planned, not yet started

- **TypeScript/Mastra support** -- needs a TS-native AST parser. Meaningful
  scope; tracked as a "good first substantial contribution" if you want to
  take it on (see [`CONTRIBUTING.md`](CONTRIBUTING.md))
- **AI gateway governance config scanning** (Bifrost, TrueFoundry,
  Cloudflare AI Gateway) -- currently out of scope entirely; see
  [`THREAT_MODEL.md`](THREAT_MODEL.md#explicitly-out-of-scope)
- **Deeper wrapper-class resolution** -- currently resolves one level of
  internal base-class indirection; two or more hops isn't caught
- **PyPI packaging** -- not yet published; install from source only. Will
  publish once the CLI surface has been stable through a few more real-world
  usage rounds
- **A dedicated `agentscan disposition` CLI subcommand** -- currently
  setting a finding's status (accepted/false-positive/remediated) is a
  dashboard-only workflow; a CLI equivalent would let this integrate into
  scripted/headless review processes

## Explicitly not planned

These come up as feature requests periodically. Documenting the reasoning
here so it doesn't need re-litigating on every issue.

- **Runtime prompt-injection blocking** -- this is a different product
  category (a guardrail sitting in the live traffic path), not a static
  scanner. Recommending Lakera Guard / LLM Guard / NeMo Guardrails for this
  is more honest than half-building it here.
- **LLM-based detection** (asking a model "is this code dangerous?") --
  breaks determinism, which CI gating and drift detection both depend on.
  See [`ARCHITECTURE.md`](ARCHITECTURE.md#why-ast-based-static-analysis-not-an-llm-based-scanner)
  for the full reasoning.
- **A hosted, "scan without installing anything" web version** -- the
  entire value proposition of this tool is that your code never leaves
  your machine. A hosted version would either be a fake canned demo or
  require building a genuinely separate sandboxed product (upload-only, no
  real filesystem access, rate-limited). That's a different, much later
  project, not a feature of this one.

---

Have a request that isn't here? Open an issue -- this list reflects
current thinking, not a locked commitment, and a well-argued case for
re-prioritizing something is welcome.
