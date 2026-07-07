# -*- coding: utf-8 -*-
"""
Drift Detection
================
Compares two scans of the same target and classifies every finding into:
  - new           : appeared in the current scan, wasn't in the baseline
  - resolved      : was in the baseline, no longer present
  - escalated     : same finding, severity got worse
  - de-escalated  : same finding, severity improved
  - unchanged     : same finding, same severity

Findings are correlated by a stable fingerprint rather than exact title
match, so re-wording a finding's description or a line-number shift doesn't
make it look like a brand new issue. This is the same pattern mcp-audit
uses for its `diff` command (rule + server/tool + matched value).

Baselines are stored as JSON snapshots on disk, keyed by target, so a user
can capture "today's" scan and compare against it after making fixes --
this is what "0.2.4 vs 0.2.6, did anything actually change?" should have
been able to answer with one click instead of a manual side-by-side read.
"""
from __future__ import annotations
import json
import time
from pathlib import Path

_BASELINE_DIR = Path.home() / ".agentscan" / "baselines"


def _fingerprint(finding: dict) -> str:
    """
    A stable identity for a finding that survives minor re-wording.
    Uses the finding's own id (already stable, e.g. "AGT-CAP-SHELL_EXEC-TOOL")
    plus its tags, which encode capability + tool name -- the actual
    "what and where" of the finding, not the prose description.
    """
    fid = finding.get("id", "")
    tags = tuple(sorted(finding.get("tags", []) or []))
    return fid + "|" + ",".join(tags)


def save_baseline(target: str, findings: list) -> dict:
    """Snapshot the current findings as the baseline for future diffs."""
    _BASELINE_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = "".join(c if c.isalnum() else "_" for c in target)[:120]
    path = _BASELINE_DIR / (safe_name + ".json")
    snapshot = {
        "target": target,
        "captured_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "findings": [
            {"id": f.get("id", ""), "title": f.get("title", ""),
             "severity": f.get("severity", ""), "tags": f.get("tags", [])}
            for f in findings
        ],
    }
    path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    return snapshot


def load_baseline(target: str) -> dict | None:
    safe_name = "".join(c if c.isalnum() else "_" for c in target)[:120]
    path = _BASELINE_DIR / (safe_name + ".json")
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


_SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def compute_drift(target: str, current_findings: list) -> dict:
    """
    Compare current_findings against the saved baseline for target.
    Returns a dict with new/resolved/escalated/de_escalated/unchanged lists,
    or has_baseline=False if no baseline exists yet.
    """
    baseline = load_baseline(target)
    if baseline is None:
        return {"has_baseline": False}

    baseline_by_fp = {_fingerprint(f): f for f in baseline["findings"]}
    current_by_fp = {_fingerprint(f): f for f in current_findings}

    new = []
    resolved = []
    escalated = []
    de_escalated = []
    unchanged = []

    for fp, cur in current_by_fp.items():
        if fp not in baseline_by_fp:
            new.append(cur)
        else:
            old = baseline_by_fp[fp]
            old_rank = _SEVERITY_RANK.get(old.get("severity", ""), 0)
            cur_rank = _SEVERITY_RANK.get(cur.get("severity", ""), 0)
            if cur_rank > old_rank:
                escalated.append({"finding": cur, "from": old.get("severity"), "to": cur.get("severity")})
            elif cur_rank < old_rank:
                de_escalated.append({"finding": cur, "from": old.get("severity"), "to": cur.get("severity")})
            else:
                unchanged.append(cur)

    for fp, old in baseline_by_fp.items():
        if fp not in current_by_fp:
            resolved.append(old)

    return {
        "has_baseline": True,
        "baseline_captured_at": baseline.get("captured_at", ""),
        "new": new,
        "resolved": resolved,
        "escalated": escalated,
        "de_escalated": de_escalated,
        "unchanged": unchanged,
        "summary": {
            "new_count": len(new),
            "resolved_count": len(resolved),
            "escalated_count": len(escalated),
            "de_escalated_count": len(de_escalated),
            "unchanged_count": len(unchanged),
        },
    }
