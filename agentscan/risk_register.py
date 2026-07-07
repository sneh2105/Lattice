# -*- coding: utf-8 -*-
"""
Risk Acceptance Workflow
=========================
Lets a user set a per-finding status other than the default "open":
  - open           : normal, unreviewed finding (default -- most findings)
  - accepted_risk  : reviewed, risk is tolerated with compensating controls
  - false_positive : reviewed, determined not to be a real issue
  - remediated     : the underlying issue was fixed but the scanner may
                      still flag the pattern (e.g. pending a re-scan)

Every non-open status requires a reason, a reviewer name, and supports an
optional expiry date. All records persist to a single JSON file (not a
database) so someone auditing "why was this marked accepted_risk" can open
the file directly and read it.

Reports can compute two risk scores from this:
  - RAW score       : as if no status had ever been set (what a first-time
                      scan would show)
  - GOVERNED score  : with accepted_risk / false_positive findings excluded
                      from the score (remediated findings stay excluded too,
                      since they're no longer considered open risk)
Both numbers matter for different audiences: raw is "what does the code
actually contain", governed is "what open risk remains after review" --
a board sign-off wants both, not just one.
"""
from __future__ import annotations
import json
import time
from pathlib import Path

_REGISTER_PATH = Path.home() / ".agentscan" / "risk_register.json"

VALID_STATUSES = {"open", "accepted_risk", "false_positive", "remediated"}

# Statuses that remove a finding from the GOVERNED risk score.
# "open" and any unrecognized status count as still-open risk.
_EXCLUDED_FROM_GOVERNED_SCORE = {"accepted_risk", "false_positive", "remediated"}


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


def set_finding_status(target: str, finding_id: str, finding_title: str,
                       status: str, reason: str, reviewer: str,
                       expires: str = "") -> dict:
    """
    Set a finding's status to one of VALID_STATUSES. Returns the stored record.
    status="open" is equivalent to clearing any prior override.
    """
    if status not in VALID_STATUSES:
        raise ValueError("status must be one of " + ", ".join(sorted(VALID_STATUSES)))

    register = _load_register()
    key = _key(target, finding_id)

    if status == "open":
        if key in register:
            del register[key]
            _save_register(register)
        return {"status": "open", "finding_id": finding_id, "target": target}

    record = {
        "target": target,
        "finding_id": finding_id,
        "finding_title": finding_title,
        "status": status,
        "reason": reason,
        "reviewer": reviewer or "Unknown",
        "set_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "expires": expires or "",
    }
    register[key] = record
    _save_register(register)
    return record


# Back-compat wrapper -- the original API before the 4-state model.
def accept_risk(target: str, finding_id: str, finding_title: str,
                reason: str, accepted_by: str, expires: str = "") -> dict:
    return set_finding_status(target, finding_id, finding_title,
                              "accepted_risk", reason, accepted_by, expires)


def revoke_acceptance(target: str, finding_id: str) -> bool:
    """Remove any status override, reverting a finding to 'open'. Returns True if one existed."""
    register = _load_register()
    key = _key(target, finding_id)
    if key in register:
        del register[key]
        _save_register(register)
        return True
    return False


def get_status(target: str, finding_id: str) -> dict | None:
    """Return the status record if one exists and hasn't expired, else None (meaning 'open')."""
    register = _load_register()
    record = register.get(_key(target, finding_id))
    if not record:
        return None
    expires = record.get("expires", "")
    if expires:
        try:
            if time.strftime("%Y-%m-%d") > expires:
                return None  # expired -- treat as open again
        except Exception:
            pass
    return record


# Back-compat alias
def is_accepted(target: str, finding_id: str) -> dict | None:
    record = get_status(target, finding_id)
    if record and record.get("status") == "accepted_risk":
        return record
    return None


def list_by_status(target: str, status: str | None = None) -> list[dict]:
    """All currently-active status records for a target, optionally filtered by status."""
    register = _load_register()
    out = []
    for key, record in register.items():
        if record.get("target") != target:
            continue
        active = get_status(target, record.get("finding_id", ""))
        if not active:
            continue
        if status is None or active.get("status") == status:
            out.append(active)
    return out


# Back-compat alias
def list_accepted_for_target(target: str) -> list[dict]:
    return list_by_status(target, "accepted_risk")


def annotate_findings(findings: list, target: str) -> list:
    """
    Attach status metadata to each finding dict without removing it from the
    list -- non-open findings stay visible but clearly marked, which is the
    right behavior for an audit trail (silently hiding a finding would be
    worse than showing it with a clear status badge).
    """
    for f in findings:
        record = get_status(target, f.get("id", ""))
        status = record.get("status", "open") if record else "open"
        f["status"] = status
        f["status_record"] = record
        # Back-compat field some UI code still reads
        f["risk_accepted"] = status == "accepted_risk"
        f["risk_acceptance"] = record if status == "accepted_risk" else None
    return findings


def compute_governed_score(findings: list, raw_score: int) -> dict:
    """
    Compute both raw and governed risk scores for a set of already-annotated
    findings (each finding dict must have a "status" and "severity" key, as
    produced by annotate_findings + the normal serializer).

    Governed score = risk contribution of only the findings still "open"
    (i.e. status not in accepted_risk/false_positive/remediated). Uses the
    same severity weighting the main scanner uses so the number is on a
    comparable 0-100 scale, not a re-invented metric.
    """
    SEVERITY_WEIGHT = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 3, "INFO": 0}

    open_findings = [f for f in findings if f.get("status", "open") not in _EXCLUDED_FROM_GOVERNED_SCORE]
    governed_raw = sum(SEVERITY_WEIGHT.get(f.get("severity", "INFO"), 0) for f in open_findings)
    governed_score = min(100, governed_raw)

    excluded_count = len([f for f in findings if f.get("status", "open") in _EXCLUDED_FROM_GOVERNED_SCORE])

    return {
        "raw_score": raw_score,
        "governed_score": governed_score,
        "findings_excluded_from_governed": excluded_count,
        "open_findings_count": len(open_findings),
    }


def annotate_finding_objects(findings: list, target: str) -> None:
    """
    Mutates real Finding objects in place, attaching a `.status` attribute
    (defaulting to "open") and `.status_record` (the full acceptance record,
    or None). Used by every consumer that works with actual ScanResult
    objects -- Compliance, PDF export, SARIF export -- not just the
    dict-serialized dashboard JSON (see annotate_findings for that).

    This is the ONE place risk status gets attached before Compliance/PDF/
    SARIF ever see the findings, so acceptance can never show up in the
    dashboard but silently vanish from the report, or vice versa.
    """
    for f in findings:
        record = get_status(target, getattr(f, "id", ""))
        status = record.get("status", "open") if record else "open"
        f.status = status
        f.status_record = record
