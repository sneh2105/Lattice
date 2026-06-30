"""Tests for agentscan demo and agentscan benchmark commands."""
import subprocess
import pytest


def test_demo_command_exits_zero_on_success():
    result = subprocess.run(["agentscan", "demo"], capture_output=True, text=True)
    assert result.returncode == 0
    assert "AgentScan Demo" in result.stdout
    assert "Prompt injection" in result.stdout


def test_demo_command_works_from_any_cwd(tmp_path):
    """Critical: demo must work regardless of the user's current directory."""
    result = subprocess.run(["agentscan", "demo"], capture_output=True, text=True, cwd=tmp_path)
    assert result.returncode == 0
    assert "AgentScan Demo" in result.stdout


def test_benchmark_command_exits_zero_on_success():
    result = subprocess.run(["agentscan", "benchmark"], capture_output=True, text=True)
    assert result.returncode == 0
    assert "7/7 scenarios passed" in result.stdout


def test_benchmark_command_works_from_any_cwd(tmp_path):
    result = subprocess.run(["agentscan", "benchmark"], capture_output=True, text=True, cwd=tmp_path)
    assert result.returncode == 0


def test_demo_reports_no_false_positives_on_safe_baseline():
    result = subprocess.run(["agentscan", "demo"], capture_output=True, text=True)
    assert "no false positives" in result.stdout
