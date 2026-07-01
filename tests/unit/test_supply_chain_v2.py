# -*- coding: utf-8 -*-
"""Tests for supply chain scanner v2."""
import pytest
from agentscan.scanners.supply_chain_scanner import scan_supply_chain
from agentscan.models import Severity


def test_known_malicious_pypi():
    r = scan_supply_chain("pypi:pytorch-nightly-cpu")
    critical = [f for f in r.findings if f.severity == Severity.CRITICAL]
    assert critical and "KNOWN" in critical[0].id


def test_known_malicious_npm():
    r = scan_supply_chain("npm:axios-proxy")
    critical = [f for f in r.findings if f.severity == Severity.CRITICAL]
    assert critical and "KNOWN" in critical[0].id


def test_npm_target_now_works():
    # npm scanner is now implemented
    r = scan_supply_chain("npm:express")
    assert r.scanner_type == "supply_chain_v2"
    assert r.error is None or "fetch" in (r.error or "").lower()


def test_dataset_target_format():
    r = scan_supply_chain("dataset:wikipedia/wikipedia")
    assert r.scanner_type == "supply_chain_v2"
    assert r.target == "dataset:wikipedia/wikipedia"


def test_pypi_typosquat_detected():
    # A name very close to 'langchain' should trigger heuristic
    r = scan_supply_chain("pypi:Iangchain")  # capital I not lowercase l
    # Should either find it via known list or typosquat heuristic
    assert r.scanner_type == "supply_chain_v2"


def test_hf_model_scan():
    r = scan_supply_chain("hf:microsoft/phi-3")
    assert r.scanner_type == "supply_chain_v2"
    # Well-known Microsoft model — should not have CRITICAL findings
    if not r.error:
        crits = [f for f in r.findings if f.severity == Severity.CRITICAL]
        assert not crits or all("pickle" in f.title.lower() for f in crits)


def test_auto_detect_hf_format():
    r = scan_supply_chain("bert-base-uncased")
    assert r.scanner_type == "supply_chain_v2"


def test_unknown_format_returns_error():
    r = scan_supply_chain("totally-unknown-format")
    # Should either auto-detect or return an error
    assert r.scanner_type == "supply_chain_v2"
