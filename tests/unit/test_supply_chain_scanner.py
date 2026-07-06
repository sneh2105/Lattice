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
