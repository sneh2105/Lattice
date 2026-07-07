# Contributing to Lattice

Thanks for your interest. Lattice is a focused tool -- contributions that sharpen
detection accuracy, expand framework coverage, or improve the evaluation kit are
most welcome. Read [ARCHITECTURE.md](ARCHITECTURE.md) first if you're touching
the scanning pipeline, compliance/DPIA generation, or the Attack Graph --
there's a single-source-of-truth principle (`_build_merged_result()` /
`filter_by_disposition()`) that every new consumer must follow, or you'll
reintroduce a bug class this project has already fixed three times.

---

## Before you start

```bash
git clone https://github.com/sneh2105/agentscan
cd agentscan
pip install -e ".[dev]"
pytest tests/unit/ -q   # must see 274 passed before you change anything
```

---

## What to contribute

### 1. New framework support
If Lattice misses a framework you use, the fix is usually small:

- Add the tool registration pattern to `agentscan/scanners/source_scanner.py`
  (`TOOL_DECORATOR_NAMES`, `TOOL_REGISTRATION_CALLS`, or a new `visit_*` method)
- Add detection to `agentscan/doctor.py` (`FRAMEWORK_SIGNATURES`)
- Write a test in `tests/unit/test_source_scanner.py`
- Add a fixture file to `examples/test_batch/`

If the framework uses a config/JSON format rather than Python source, the fix
goes in `agentscan/scanners/agent_scanner.py` (`_extract_tools`).

### 2. Capability keyword improvements
If a tool is being false-positived (flagged when it shouldn't be) or missed
(not flagged when it should be), the keyword lists live in
`agentscan/scanners/capabilities.py` — the single canonical source of truth.
All three scanners import from there.

Important constraints:
- Do not add bare verbs like `"run"` or `"execute"` to `shell_exec` keywords.
  Use the token co-occurrence approach (`_has_shell_token_pair`) instead.
- Do not add bare nouns like `"refund"` to `financial_transaction` keywords.
  Require verb-noun compounds like `"issue_refund"`, `"process_refund"`.

### 3. New eval-kit scenarios
A well-documented attack scenario is worth more than a unit test alone:

- Create `examples/vulnerable_agents/NN_name/` with fixture + `README.md`
- The README must document: attack chain, run command, expected result, fix
- Add to `SCENARIOS` in `agentscan/benchmark.py`
- Run `agentscan benchmark` — all scenarios must pass
- Update the scenario count in `README.md` and `tests/unit/test_benchmark_cli.py`

### 4. Compliance framework / control mapping additions
The control library lives in `agentscan/compliance/framework_mapper.py`
(`CONTROL_LIBRARY`). Adding a new framework (a new regulatory regime, a new
industry standard) means adding entries keyed by capability tag, each with
`framework`, `control_id`, `control_name`, `obligation`, and `severity`.
See [DETECTION.md](DETECTION.md) for how capability tags map to findings.

### 5. Bug reports
File an issue with:
- The exact command you ran
- The input file (anonymised if necessary)
- The output you got vs what you expected
- Your Python version and OS

---

## Code standards

- **Pure ASCII in all `.py` files.** Windows reads source as cp1252 by default.
  Non-ASCII characters cause `SyntaxError` on Windows even if they work on Linux.
- **No f-strings with nested same-type quotes** (`f"...c(X, "str")..."`).
  Python 3.10/3.11 rejects these. Python 3.12 silently accepts them.
  Use string concatenation or single-quote f-strings instead.
- **Path joining in tests**: use `str(Path(tmpdir) / "filename")`,
  not `f"{tmpdir}/filename"` — mixed separators break on Windows.
- **Subprocess calls with encoding**: any `subprocess.run(..., text=True)` must
  also pass `encoding="utf-8"` or it will fail on Windows terminals.
- All file writes use `agentscan._fileutil.atomic_write_text()` for safety.

Run the full suite before opening a PR:
```bash
pytest tests/unit/ -q
agentscan benchmark
```

---

## Pull request checklist

- [ ] `pytest tests/unit/ -q` passes (274 tests)
- [ ] `agentscan benchmark` shows 12/12
- [ ] New functionality has a test in `tests/unit/`
- [ ] No non-ASCII characters introduced in `.py` files
- [ ] No f-strings with nested same-type quote literals

---

## Questions or ideas

Open a GitHub issue, or email [sneh2105@gmail.com](mailto:sneh2105@gmail.com).  
Built by [Sneh Singh](https://www.linkedin.com/in/sneh-singh-cs/).
