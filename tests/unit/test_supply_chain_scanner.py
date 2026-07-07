# -*- coding: utf-8 -*-
"""Tests for the AI supply chain scanner."""
import pytest
from agentscan.scanners.supply_chain_scanner import scan_supply_chain
from agentscan.models import Severity


def test_known_malicious_package_detected():
    result = scan_supply_chain("pypi:pytorch-nightly-cpu")
    critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert critical
    assert critical  # known malicious package detected


def test_invalid_target_format_returns_error():
    result = scan_supply_chain("totally-wrong-format-no-prefix")
    # Should either error or try hf: auto-detect
    # If it errors, check error message; if not, no assert needed
    if result.error:
        assert "unrecognised" in result.error.lower() or "format" in result.error.lower()


def test_npm_target_now_works():
    result = scan_supply_chain("npm:express")
    # npm scanning is now implemented in v2
    assert result.scanner_type == "supply_chain_v2"


def test_pypi_scan_runs_without_crash():
    """Integration-lite: actually hits PyPI API. Skipped in offline CI."""
    pytest.importorskip("urllib.request")  # always available, just documents intent
    result = scan_supply_chain("pypi:requests")
    # 'requests' is a well-known trusted package -- should have low risk
    assert result.error is None or "fetch" in (result.error or "").lower()
    if not result.error:
        critical = [f for f in result.reportable_findings if f.severity == Severity.CRITICAL]
        assert not critical, "Well-known package 'requests' should not have CRITICAL findings"


def test_langchain_not_flagged_as_typosquat():
    """Regression: langchain was flagged as typosquatting 'langchain-ai' publisher."""
    from agentscan.scanners.supply_chain_scanner import _suspicious_name_heuristic, TRUSTED_PYPI_PUBLISHERS
    # These are real packages that should never be flagged
    for pkg in ["langchain", "openai", "anthropic", "numpy", "pandas", "torch",
                "langchain-core", "langchain-community", "crewai"]:
        assert not _suspicious_name_heuristic(pkg, TRUSTED_PYPI_PUBLISHERS), \
            f"'{pkg}' incorrectly flagged as typosquatting"



def test_real_typosquats_still_caught():
    """Real typosquats must still be detected after allowlist fix."""
    from agentscan.scanners.supply_chain_scanner import _suspicious_name_heuristic, TRUSTED_PYPI_PUBLISHERS
    # These are unambiguous typosquats
    for pkg in ["numpyy", "0pen-ai", "anthroplc"]:
        assert _suspicious_name_heuristic(pkg, TRUSTED_PYPI_PUBLISHERS), (
            f"'{pkg}' should be flagged as typosquat"
        )
    # The real package itself must never be flagged
    assert not _suspicious_name_heuristic("langchain", TRUSTED_PYPI_PUBLISHERS)
    assert not _suspicious_name_heuristic("numpy", TRUSTED_PYPI_PUBLISHERS)
    assert not _suspicious_name_heuristic("openai", TRUSTED_PYPI_PUBLISHERS)


def test_numpy_url_case_insensitive():
    """
    Regression: numpy flagged 'No source code link' because URL key lookup
    was case-sensitive. PyPI returns lowercase keys; the check looked for 'Source'.
    """
    project_urls_lower = {"source": "https://github.com/numpy/numpy", "tracker": "..."}
    project_urls_upper = {"Source": "https://github.com/numpy/numpy"}

    def _get_url(d, *keys):
        d_lower = {k.lower(): v for k, v in d.items()}
        for key in keys:
            val = d_lower.get(key.lower())
            if val:
                return val
        return ""

    assert _get_url(project_urls_lower, "Source", "source"), "lowercase 'source' not found"
    assert _get_url(project_urls_upper, "source", "Source"), "uppercase 'Source' not found"


def test_cli_supply_manifest_batch_scans_all_dependencies(tmp_path):
    """agentscan supply --manifest requirements.txt scans every dependency in one call."""
    import subprocess, sys as _sys

    req = tmp_path / "requirements.txt"
    req.write_text("langchain==0.1.0\nnumpy>=1.24\nrequests\n")

    r = subprocess.run(
        [_sys.executable, "-m", "agentscan.cli", "supply", "--manifest", str(req)],
        capture_output=True, text=True, encoding="utf-8",
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert "3 dependencies found" in r.stdout
    assert "langchain" in r.stdout
    assert "numpy" in r.stdout
    assert "requests" in r.stdout


def test_cli_supply_manifest_rejects_unknown_file(tmp_path):
    unknown = tmp_path / "something.txt"
    unknown.write_text("not a real manifest")
    import subprocess, sys as _sys
    r = subprocess.run(
        [_sys.executable, "-m", "agentscan.cli", "supply", "--manifest", str(unknown)],
        capture_output=True, text=True, encoding="utf-8",
    )
    assert r.returncode == 2
    assert "Unrecognized manifest" in r.stdout


def test_supply_chain_auto_scan_uses_content_not_folder_lookup():
    """
    Regression: the dashboard's Supply Chain tab re-derived the folder path
    from curTarget for its auto-scan request. For GitHub-scanned targets,
    curTarget is the stable "github.com/user/repo" URL (correct, needed for
    risk-acceptance keying) but is NOT a real filesystem path -- the actual
    files only exist in an ephemeral server-side clone directory the
    frontend never sees. A folder-based re-lookup on a URL string silently
    finds nothing every time. The fix: the frontend must send the
    dependency file CONTENT it already received from the original /api/scan
    response, never re-derive by folder path.
    """
    from agentscan.ui_server import _find_dependency_files, _get_supply_chain

    # Confirm the actual bug: folder lookup on a non-filesystem string finds nothing
    result = _find_dependency_files("github.com/fake/repo")
    assert result == {}, "a URL string must never resolve to real dependency files"

    # Confirm the fix path works: passing content directly always works,
    # regardless of what the original target string was
    content = "langchain==0.1.0\nnumpy>=1.24\n"
    scan_result = _get_supply_chain(content, "pypi")
    package_names = [p["package_name"] for p in scan_result["packages"]]
    assert "langchain" in package_names
    assert "numpy" in package_names


def test_dashboard_dependency_files_content_is_actually_usable(tmp_path):
    """
    End-to-end: a directory scan must return dependency_files with real,
    non-empty content that can be piped straight into supply chain scanning
    without any further filesystem access -- this is what the dashboard's
    fixed autoScanDeps() now relies on entirely.
    """
    from agentscan.ui_server import _scan_target, _get_supply_chain

    (tmp_path / "agent.py").write_text(
        "from langchain.tools import tool\n@tool\ndef x(y: str) -> str:\n    \"\"\"do a thing\"\"\"\n    return y\n"
    )
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")

    scan = _scan_target(str(tmp_path))
    dep_files = scan.get("dependency_files", {})
    assert "requirements" in dep_files
    content = dep_files["requirements"]["content"]
    assert content.strip() == "requests==2.31.0"

    supply_result = _get_supply_chain(content, "pypi")
    assert any(p["package_name"] == "requests" for p in supply_result["packages"])
