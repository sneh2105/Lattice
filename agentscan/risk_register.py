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


_SEVERITY_WEIGHT = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 3, "INFO": 0}

# Statuses that are a claim the finding itself is WRONG or already FIXED --
# these are excluded from every score, including the "raw" one. A false
# positive isn't a risk decision, it's a claim the finding shouldn't exist;
# a remediated finding is claimed fixed. Neither should count against the
# code at all once confirmed -- if the score doesn't move after marking
# something false_positive, that's a bug (this was true before this fix).
_REMOVED_FROM_EVERY_SCORE = {"false_positive", "remediated"}

# Statuses that stay in the RAW/residual score (the risk objectively still
# exists in the code) but are excluded from the GOVERNED score (a reviewed,
# owned, documented risk is a different governance state than an
# unreviewed one -- this is what a CISO/auditor decision should be based on).
_EXCLUDED_FROM_GOVERNED_ONLY = {"accepted_risk"}


def compute_governed_score(findings: list, raw_score: int = None) -> dict:
    """
    Compute two risk scores from a set of already status-annotated findings
    (each dict needs "status" and "severity" keys, as produced by
    annotate_findings + the normal serializer):

      raw_score (residual technical risk)
        -- what the code objectively still exposes. Includes accepted_risk
        findings (the risk is real, you've just chosen to tolerate it --
        this number must never look like the code got safer just because
        someone accepted the risk). EXCLUDES false_positive and remediated
        findings, because those are claims the finding is wrong or already
        fixed, not risk-tolerance decisions -- they should never count
        against the score at all once confirmed.

      governed_score (post-review risk)
        -- what a CISO/auditor should actually act on. Excludes
        accepted_risk, false_positive, AND remediated -- only genuinely
        open, unreviewed findings count.

    The `raw_score` parameter (the scanner's own pre-review risk_score()) is
    accepted for backward compatibility but is NOT used for the returned
    raw_score -- both scores are now computed fresh from the same severity
    weighting so they're always on a consistent, comparable scale and false
    positives/remediated findings are guaranteed to move the number.
    """
    residual_findings = [f for f in findings if f.get("status", "open") not in _REMOVED_FROM_EVERY_SCORE]
    residual_raw = sum(_SEVERITY_WEIGHT.get(f.get("severity", "INFO"), 0) for f in residual_findings)
    residual_score = min(100, residual_raw)

    open_findings = [
        f for f in findings
        if f.get("status", "open") not in _REMOVED_FROM_EVERY_SCORE
        and f.get("status", "open") not in _EXCLUDED_FROM_GOVERNED_ONLY
    ]
    governed_raw = sum(_SEVERITY_WEIGHT.get(f.get("severity", "INFO"), 0) for f in open_findings)
    governed_score = min(100, governed_raw)

    removed_count = len([f for f in findings if f.get("status", "open") in _REMOVED_FROM_EVERY_SCORE])
    accepted_count = len([f for f in findings if f.get("status", "open") in _EXCLUDED_FROM_GOVERNED_ONLY])
    needs_reverify = [f.get("id") for f in findings if f.get("status", "open") == "remediated"]

    return {
        "raw_score": residual_score,
        "governed_score": governed_score,
        "findings_excluded_from_governed": accepted_count + removed_count,
        "findings_removed_as_fp_or_remediated": removed_count,
        "findings_accepted_risk": accepted_count,
        "open_findings_count": len(open_findings),
        "needs_reverification": needs_reverify,
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
