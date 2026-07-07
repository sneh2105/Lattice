# CLI Reference

Full command reference. Every command also supports `--help` for inline docs.

---

## Zero-setup evaluation

```bash
agentscan demo
```
Runs all 12 bundled attack scenarios plus a safe baseline, with narrated
output. No config, no target needed -- this is how you verify the install
worked and see what a finding looks like end to end.

```bash
agentscan benchmark
```
Same 12 scenarios, compact pass/fail table. Use this in your own CI to
confirm a Lattice upgrade didn't regress detection before you rely on it.

---

## Environment detection

```bash
agentscan doctor [path]
```
Detects which agent frameworks, tool registration patterns, MCP manifests,
and dependency files exist in a directory, before you commit to a specific
scan command. Defaults to the current directory. Recommended first command
when pointing Lattice at a new codebase.

---

## Scanning your code

```bash
agentscan source <path> [options]
```
Scans Python source via AST. `<path>` can be a single file or a directory
(scanned recursively). This is the command for real agent code --
LangChain, CrewAI, AutoGen, etc.

```bash
agentscan agent <config> [options]
```
Scans a declarative YAML/JSON agent config. Also handles Dify, n8n, and
Flowise workflow exports (auto-detected from structure).

```bash
agentscan mcp <manifest.json | https://server-url> [--timeout SECONDS]
```
Scans an MCP server -- either a local manifest file or a live server
endpoint (fetched over HTTP with the given timeout, default 10s).

```bash
agentscan supply pypi:<name> | npm:<name> | hf:<org/model> | dataset:<org/name>
agentscan supply --manifest requirements.txt|package.json|pyproject.toml [--max-packages N]
```
Scans a single package/model/dataset, or every dependency listed in a
manifest file in one call (capped at `--max-packages`, default 20, to
bound CI runtime).

### Shared options (`source`, `agent`, `mcp`, `supply`)

| Flag | Effect |
|---|---|
| `--output {text,json,sarif,html}` | Output format. Default `text`. `sarif` uploads to GitHub's Security tab. `html` writes a self-contained report file. |
| `--open` | Generate an HTML report and open it in your default browser immediately (serves over `localhost`, not `file://`, so embedded scripts aren't blocked by browser CSP) |
| `--output-file FILE` | Write output to a file instead of stdout |
| `--fail-on {CRITICAL,HIGH,MEDIUM}` | Exit code 1 if any finding at or above this severity is present. Exit code 2 on a scan error (bad path, malformed config) -- always distinct from exit 1, so a CI gate can tell "found problems" apart from "the scan itself failed to run." |
| `--verbose` | Full finding detail including evidence |

---

## Comparing scans over time

```bash
agentscan diff <target> --save-baseline
agentscan diff <target>
agentscan diff <target> --fail-on-new
agentscan diff <target> --fail-on-escalated
```
Fingerprint-based drift detection (matches findings by ID + tags, not
exact wording, so a re-worded description doesn't look like a new finding).
`--save-baseline` captures the current scan as the comparison point.
Without it, compares against the last saved baseline and reports
new/resolved/escalated/de-escalated/unchanged counts. `--fail-on-new` and
`--fail-on-escalated` are CI gates: exit 1 if anything new appeared, or if
any finding's severity got worse, since the baseline.

```bash
agentscan diff <target> --output json
```
Machine-readable drift output for piping into other tools.

---

## Attack graph

```bash
agentscan graph agent <config> [--open] [--export-html FILE]
agentscan graph mcp <manifest>
```
Renders the attack graph -- entry point, tool chain, crown jewel -- as
terminal ASCII art by default, or as an interactive D3.js graph with
`--open`/`--export-html`.

---

## Compliance and audit

```bash
agentscan compliance map <target>
```
Finding-to-control mapping across RBI AI-ACT&RS, DPDP Rules 2025, ISO
42001, EU AI Act, NIST AI RMF, SOC 2, and SEBI CSCRF. Only counts findings
still in `open` status toward the reported posture/score -- see
`risk_register.py`'s disposition workflow below.

```bash
agentscan compliance dpia <target>
```
Generates a Data Protection Impact Assessment document.

```bash
agentscan compliance audit <target> --organisation "Acme Corp" --output-file audit.pdf
```
Generates the full PDF: cover page, executive summary (with raw vs
governed risk score), findings table, control mapping, DPIA, and risk
acceptance register (if any findings have been dispositioned).

---

## Risk disposition (accepting, disputing, or closing findings)

There is currently no dedicated CLI subcommand for setting a finding's
disposition -- this is a dashboard-only workflow (`agentscan ui`, Findings
tab, per-finding status picker). What the CLI *does* expose:

- Every scan command reflects existing dispositions automatically (a
  finding marked `accepted_risk`/`false_positive`/`remediated` in the
  dashboard shows its status in subsequent `agentscan source`/`agent`/`mcp`
  runs, and is excluded from governed scoring in every output format).
- `agentscan diff` and `agentscan compliance` both read the same
  disposition state.

If you need to set dispositions from a script rather than the dashboard,
call `agentscan.risk_register.set_finding_status()` directly from Python --
see `risk_register.py` for the four valid statuses (`open`, `accepted_risk`,
`false_positive`, `remediated`) and their required fields (reason,
reviewer, optional expiry).

---

## The dashboard

```bash
agentscan ui [--port N] [--no-browser]
```
Starts the local web dashboard and opens your browser to it. `--port`
pins a specific port (default: random free port). `--no-browser` starts
the server without launching a browser tab (useful if you're forwarding
the port from a remote machine).

Dashboard tabs: Summary, Attack Graph, Findings (with per-finding status
picker), Compliance, Supply Chain (auto-reads dependency manifests from
the scanned target, no paste required), Health (`doctor` output inline),
Export (PDF/SARIF/JSON/Markdown, plus drift baseline capture/compare).

Input modes: paste a GitHub URL (clones automatically), drop/upload local
files, type a local path, or point at a live MCP URL.

---

## Runtime monitoring (separate, less mature subsystem)

```bash
agentscan runtime analyse <session.json>
agentscan runtime flow --config <agent.yaml> [--has-rag]
agentscan runtime goals --config <agent.yaml>
```
Analyzes an actual runtime session transcript rather than static code --
see [`ARCHITECTURE.md`](ARCHITECTURE.md#whats-runtime-for) for what this
does and doesn't cover. Not wired into the dashboard.

---

## Exit codes (every scan command)

| Code | Meaning |
|---|---|
| `0` | Clean scan, no findings above the `--fail-on` threshold (or no threshold set) |
| `1` | Scan ran successfully, findings at or above the `--fail-on` threshold were found |
| `2` | The scan itself failed to run (bad path, malformed config, unreadable file) |

This distinction matters for CI/CD: exit 2 must never be silently treated
as "clean" by a pipeline gate. A mistyped config path should fail the
build loudly, not report false success.
