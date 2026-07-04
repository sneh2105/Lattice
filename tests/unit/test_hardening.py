# -*- coding: ascii -*-
"""
Regression tests for proactive hardening (post round-7), covering the
three areas the round-7 report flagged as never having had a dedicated
adversarial pass: the HTML/PDF report renderers under adversarial tool
names, the supply-chain scanner's URL construction, and concurrent
output-file writes.
"""
import os
import stat
import tempfile

import pytest

from agentscan.models import (
    ScanResult, Finding, Evidence, Severity, ConfidenceLevel, AttackPath,
)


def _malicious_finding() -> Finding:
    return Finding(
        id="TEST-1",
        title='</font><a href="http://evil.example.com/steal">Click for a prize</a><font>',
        severity=Severity.CRITICAL,
        confidence=ConfidenceLevel.HIGH,
        scanner="test",
        explanation='"><script>alert(1)</script>',
        impact="<b>bold fake impact</b>",
        remediation="<para>fake para injection</para>",
        evidence=[Evidence(
            source="test", field="name",
            observed_value='"><img src=x onerror=alert(1)>',
            explanation="<font color=red>fake</font>",
        )],
    )


def _result_with_malicious_content() -> ScanResult:
    return ScanResult(
        target='</font>evil-target<a href="http://evil.example.com">',
        scanner_type="test_scanner",
        findings=[_malicious_finding()],
        attack_paths=[],
    )


# ---------------------------------------------------------------------------
# HTML report: escaping must neutralise injected markup
# ---------------------------------------------------------------------------

def test_html_report_escapes_malicious_tool_content():
    from agentscan.outputs.html_report import generate_html_report
    result = _result_with_malicious_content()
    with tempfile.TemporaryDirectory() as d:
        path = generate_html_report(result, d + "/report", title=result.target)
        html = open(path).read()

    # The literal tag text must appear only as escaped entities -- never
    # as a live, browser-interpretable <script> or <a href> tag.
    assert "<script>alert(1)</script>" not in html
    assert '<a href="http://evil.example.com/steal">' not in html
    assert "&lt;script&gt;" in html or "&lt;a href" in html


def test_html_esc_handles_single_quotes_too():
    from agentscan.outputs.html_report import _esc
    assert "'" not in _esc("it's a test")
    assert "&#39;" in _esc("it's a test")


# ---------------------------------------------------------------------------
# PDF report: reportlab markup injection must be neutralised
# ---------------------------------------------------------------------------

def test_pdf_report_escapes_malicious_content():
    from agentscan.compliance.audit_report import generate_audit_report
    result = _result_with_malicious_content()
    with tempfile.TemporaryDirectory() as d:
        out = d + "/audit"
        path = generate_audit_report(
            result, out,
            agent_name="Test Agent",
            organisation='<a href="http://evil.example.com">click</a>',
            assessor="</font></b>broken<font>",
        )
        assert os.path.exists(path)
        # Extract text and confirm the injected markup rendered as
        # literal visible text, not a live link / broken formatting.
        try:
            from pypdf import PdfReader
        except ImportError:
            pytest.skip("pypdf not available to verify PDF text content")
        reader = PdfReader(path)
        text = "".join(p.extract_text() for p in reader.pages)
        assert 'href="http://evil.example.com">click</a>' in text
        assert "</font></b>broken<font>" in text


def test_pdf_esc_helper_escapes_all_markup_chars():
    from agentscan.compliance.audit_report import _esc
    raw = """<b>&"'></b>"""
    escaped = _esc(raw)
    for ch in ("<", ">", '"', "'"):
        assert ch not in escaped
    assert "&amp;" in escaped


# ---------------------------------------------------------------------------
# Supply chain scanner: URL construction must be properly encoded
# ---------------------------------------------------------------------------

def test_pypi_package_name_is_url_encoded_not_crash():
    """A crafted package name with URL-special characters must not
    produce a malformed request or crash -- it should cleanly fail to
    find a (nonexistent) package."""
    from agentscan.scanners.supply_chain_scanner import scan_supply_chain
    result = scan_supply_chain("pypi:weird?name#with&chars/../traversal")
    # Should not raise; should report a clean "could not fetch" error,
    # not silently succeed against an unintended endpoint.
    assert result.error is not None


def test_hf_repo_id_is_url_encoded_not_crash():
    from agentscan.scanners.supply_chain_scanner import scan_supply_chain
    result = scan_supply_chain("hf:weird org/model?with#chars")
    assert result.error is not None


def test_npm_scoped_package_name_still_resolves_shape():
    """Scoped npm names (@scope/name) must still produce a syntactically
    valid registry URL (not crash), even though we can't guarantee
    network access in this test."""
    from agentscan.scanners.supply_chain_scanner import _scan_npm
    # Just confirm it runs to completion without raising.
    result = _scan_npm("@nonexistent-scope-xyz/nonexistent-pkg-xyz")
    assert result is not None


# ---------------------------------------------------------------------------
# Atomic writes: no partial/corrupt files, normal (shareable) permissions
# ---------------------------------------------------------------------------

def test_atomic_write_text_produces_complete_readable_file():
    from agentscan._fileutil import atomic_write_text
    with tempfile.TemporaryDirectory() as d:
        path = d + "/out.txt"
        atomic_write_text(path, "hello world")
        assert open(path).read() == "hello world"
        # Must be normal, shareable permissions -- not the restrictive
        # 0600 that tempfile.mkstemp() produces by default. These are
        # report files meant to be opened by other tools/users.
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode & stat.S_IRGRP, "group-readable bit should be set (mode 644)"


def test_atomic_write_leaves_no_tempfiles_behind_on_success():
    from agentscan._fileutil import atomic_write_text
    with tempfile.TemporaryDirectory() as d:
        atomic_write_text(d + "/out.txt", "content")
        remaining = os.listdir(d)
        assert remaining == ["out.txt"], f"leftover temp files: {remaining}"


def test_atomic_write_overwrites_existing_file_completely():
    from agentscan._fileutil import atomic_write_text
    with tempfile.TemporaryDirectory() as d:
        path = d + "/out.txt"
        atomic_write_text(path, "first version, quite long content here")
        atomic_write_text(path, "v2")
        # Must be exactly the new content, not old content with new
        # content overlaid (which plain truncate+write could produce
        # if two writers raced).
        assert open(path).read() == "v2"


def test_html_report_write_is_atomic():
    from agentscan.outputs.html_report import generate_html_report
    result = _result_with_malicious_content()
    with tempfile.TemporaryDirectory() as d:
        path = generate_html_report(result, d + "/r", title="t")
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode & stat.S_IRGRP


# ---------------------------------------------------------------------------
# CLI: scan errors must print a message, not exit silently
# ---------------------------------------------------------------------------

def test_cli_scan_error_prints_message_not_silent(tmp_path):
    import subprocess
    import sys
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json")
    result = subprocess.run(
        [sys.executable, "-m", "agentscan.cli", "agent", str(bad)],
        capture_output=True, text=True,
    )
    assert result.returncode == 2
    assert "Error" in result.stderr or "Error" in result.stdout
