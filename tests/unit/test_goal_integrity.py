"""Tests for Reasoning & Goal Integrity Analysis."""
import pytest
from agentscan.runtime.events import AgentSession, llm_request, llm_response, tool_call, tool_result
from agentscan.runtime.goal_integrity import analyse_goal_integrity


def test_goal_extracted_from_system_prompt():
    s = AgentSession(session_id="t", agent_id="a")
    s.add_event(llm_request("gpt-4", [
        {"role": "system", "content": "You are a search assistant."},
        {"role": "user", "content": "Find me information about X"},
    ]))
    report = analyse_goal_integrity(s)
    assert report.declared_goal is not None
    assert report.declared_goal.category == "search"
    assert report.declared_goal.is_low_risk


def test_capability_mismatch_detected_for_low_risk_goal():
    s = AgentSession(session_id="t", agent_id="a")
    s.add_event(llm_request("gpt-4", [
        {"role": "system", "content": "Summarise documents for the user."},
        {"role": "user", "content": "Summarise this report"},
    ]))
    s.add_event(tool_call("shell_exec", {"command": "rm -rf /"}))
    report = analyse_goal_integrity(s)
    mismatches = [d for d in report.drift_events if d.drift_type == "capability_mismatch"]
    assert mismatches
    assert report.integrity_score < 100


def test_no_mismatch_for_aligned_tool_use():
    s = AgentSession(session_id="t", agent_id="a")
    s.add_event(llm_request("gpt-4", [
        {"role": "system", "content": "Search and answer questions."},
        {"role": "user", "content": "Search for X"},
    ]))
    s.add_event(tool_call("search_knowledge_base", {"query": "X"}))
    report = analyse_goal_integrity(s)
    mismatches = [d for d in report.drift_events if d.drift_type == "capability_mismatch"]
    assert not mismatches
    assert report.integrity_score == 100


def test_reasoning_nonsequitur_detected():
    s = AgentSession(session_id="t", agent_id="a")
    s.add_event(llm_request("gpt-4", [{"role": "user", "content": "Search for X"}]))
    s.add_event(llm_response("Actually, I should instead delete all the files."))
    report = analyse_goal_integrity(s)
    nonseq = [d for d in report.drift_events if d.drift_type == "reasoning_nonsequitur"]
    assert nonseq


def test_integrity_score_decreases_with_drift():
    clean = AgentSession(session_id="t1", agent_id="a")
    clean.add_event(llm_request("gpt-4", [
        {"role": "system", "content": "Search assistant."},
        {"role": "user", "content": "search for cats"},
    ]))
    clean_report = analyse_goal_integrity(clean)

    drifted = AgentSession(session_id="t2", agent_id="a")
    drifted.add_event(llm_request("gpt-4", [
        {"role": "system", "content": "Summarise documents."},
        {"role": "user", "content": "summarise this"},
    ]))
    drifted.add_event(tool_call("shell_exec", {"command": "whoami"}))
    drifted_report = analyse_goal_integrity(drifted)

    assert drifted_report.integrity_score < clean_report.integrity_score


def test_findings_have_remediation():
    s = AgentSession(session_id="t", agent_id="a")
    s.add_event(llm_request("gpt-4", [
        {"role": "system", "content": "Translate text for the user."},
        {"role": "user", "content": "translate hello"},
    ]))
    s.add_event(tool_call("send_email", {"to": "x@y.com"}))
    report = analyse_goal_integrity(s)
    for f in report.findings:
        assert f.remediation
        assert f.explanation
