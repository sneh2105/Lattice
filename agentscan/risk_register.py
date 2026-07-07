# -*- coding: utf-8 -*-
"""
Risk Acceptance Workflow
=========================
Lets a user formally accept a finding as a known, tolerated risk rather than
having it re-appear as an open item on every subsequent scan. Accepted risks
are persisted to disk (JSON file under the user's home directory) so they
survive across scans and across dashboard sessions.

This is deliberately NOT a database -- it's a single JSON file, readable and
auditable by hand, which matters for a compliance-facing feature: someone
reviewing "why was this risk accepted" should be able to open the file directly.
"""
from __future__ import annotations
import json
import time
from pathlib import Path

_REGISTER_PATH = Path.home() / ".agentscan" / "risk_register.json"


def _load_register() -> dict:
    if not _REGISTER_PATH.exists():
        return {}
    try:
        return json.loads(_REGISTER_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_register(data: dict) -> None:
    _REGISTER_PATH.parent.mkdir(parents=True, exist_ok=True)
    _REGISTER_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _key(target: str, finding_id: str) -> str:
    return target + "::" + finding_id


def accept_risk(target: str, finding_id: str, finding_title: str,
                reason: str, accepted_by: str, expires: str = "") -> dict:
    """Record a finding as an accepted risk. Returns the record that was stored."""
    register = _load_register()
    record = {
        "target": target,
        "finding_id": finding_id,
        "finding_title": finding_title,
        "reason": reason,
        "accepted_by": accepted_by or "Unknown",
        "accepted_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "expires": expires or "",
        "status": "accepted",
    }
    register[_key(target, finding_id)] = record
    _save_register(register)
    return record


def revoke_acceptance(target: str, finding_id: str) -> bool:
    """Remove a risk acceptance record. Returns True if one existed."""
    register = _load_register()
    key = _key(target, finding_id)
    if key in register:
        del register[key]
        _save_register(register)
        return True
    return False


def is_accepted(target: str, finding_id: str) -> dict | None:
    """Return the acceptance record if this finding is currently accepted, else None."""
    register = _load_register()
    record = register.get(_key(target, finding_id))
    if not record:
        return None
    # Check expiry
    expires = record.get("expires", "")
    if expires:
        try:
            if time.strftime("%Y-%m-%d") > expires:
                return None  # expired -- treat as not accepted
        except Exception:
            pass
    return record


def list_accepted_for_target(target: str) -> list[dict]:
    """All currently-accepted risks for a given target."""
    register = _load_register()
    out = []
    for key, record in register.items():
        if record.get("target") == target:
            accepted = is_accepted(target, record.get("finding_id", ""))
            if accepted:
                out.append(accepted)
    return out


def annotate_findings(findings: list, target: str) -> list:
    """
    Attach risk_accepted metadata to each finding dict without removing it
    from the list -- accepted risks stay visible but are clearly marked,
    which is the right behavior for an audit trail (silently hiding an
    accepted risk from a compliance report would be worse than showing it
    with a clear "accepted" badge).
    """
    for f in findings:
        record = is_accepted(target, f.get("id", ""))
        f["risk_accepted"] = record is not None
        f["risk_acceptance"] = record
    return findings
