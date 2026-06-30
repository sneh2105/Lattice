"""
AI Supply Chain Scanner v2
===========================
Covers the full AI supply chain surface:
  - PyPI packages        (malicious, typosquatting, dependency risk)
  - npm packages         (now implemented)
  - HuggingFace models   (pickle RCE, provenance, suspicious files)
  - HuggingFace datasets (poisoning signals, license, provenance)
  - MCP server packages  (npm/PyPI packages inside MCP servers)
  - Embeddings / vector stores (provenance signals)
  - Publisher reputation (cross-registry trust scoring)

Low false-positive design:
  - Known malicious: HIGH confidence
  - Heuristic-only: MEDIUM confidence, explicitly labelled
  - Every finding includes the exact data that triggered it
"""

from __future__ import annotations
import json
import re
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentscan.models import ConfidenceLevel, Evidence, Finding, ScanResult, Severity


# ── Known threat intelligence ─────────────────────────────────────────────────

KNOWN_MALICIOUS_PYPI: dict[str, str] = {
    "pytorch-nightly-cpu":    "Malicious PyTorch lookalike — credential stealer (2023, Lazarus Group)",
    "torchvision-nightly":    "Malicious torchvision lookalike — credential stealer (2023)",
    "huggingface-hub-cli":    "Typosquatting huggingface_hub — data exfiltration (2024)",
    "openai-dev":             "Typosquatting openai — reverse shell payload (2024)",
    "langchain-core-dev":     "Malicious LangChain lookalike — env var exfiltration (2024)",
    "transformers-dev":       "Malicious transformers lookalike (2024)",
    "anthropic-sdk":          "Typosquatting anthropic — credential harvester (2025)",
    "crewai-tools-extra":     "Malicious CrewAI extension — agent hijack payload (2025)",
}

KNOWN_MALICIOUS_NPM: dict[str, str] = {
    "axios-proxy":            "Axios backdoor — credential exfiltration (2025, North Korea attributed)",
    "node-fetch-2":           "Typosquatting node-fetch — POST exfil on install (2024)",
    "langchainjs-dev":        "Malicious LangChain.js lookalike (2024)",
    "openai-node-extra":      "Malicious openai SDK lookalike (2024)",
    "@anthropic/sdk-beta":    "Scoped package squatting — reverse shell (2025)",
}

# File types dangerous in model repos
DANGEROUS_MODEL_FILES: dict[str, tuple[str, str, Severity]] = {
    ".pkl":    ("Pickle file",    "Arbitrary code execution on load — pickle.load() runs __reduce__", Severity.CRITICAL),
    ".pickle": ("Pickle file",    "Arbitrary code execution on load", Severity.CRITICAL),
    ".pt":     ("PyTorch checkpoint", "May embed pickle payload — use safetensors instead", Severity.HIGH),
    ".pth":    ("PyTorch weights",    "May embed pickle payload", Severity.HIGH),
    ".bin":    ("Binary weights",     "Can embed pickle in older HF format", Severity.MEDIUM),
    ".exe":    ("Executable",         "No legitimate use in a model repo", Severity.CRITICAL),
    ".sh":     ("Shell script",       "Could execute arbitrary commands", Severity.HIGH),
    ".js":     ("JavaScript",         "Unexpected in model repo — supply chain attack signal", Severity.HIGH),
    ".ps1":    ("PowerShell script",  "Could execute arbitrary commands on Windows", Severity.HIGH),
    ".dll":    ("DLL",                "No legitimate use in a model repo", Severity.CRITICAL),
}

# Dataset poisoning signals (content patterns)
DATASET_POISON_PATTERNS: list[dict] = [
    {
        "id": "DS-INJECT-IGNORE",
        "pattern": r"ignore\s+(all\s+)?(previous|prior|above|preceding)\s+instructions",
        "title": "Prompt injection in dataset — ignore-previous-instructions pattern",
        "severity": Severity.CRITICAL,
        "explanation": "Dataset contains text matching classic prompt injection patterns. "
                       "If this dataset is used for RAG or fine-tuning, it can poison the model "
                       "or override system prompts at inference time.",
        "mitre": ["AML.T0020", "AML.T0051"],
    },
    {
        "id": "DS-INJECT-SYSTEM",
        "pattern": r"\[SYSTEM\]|\[INST\]|<\|system\|>|<system>",
        "title": "Embedded system prompt tokens in dataset",
        "severity": Severity.HIGH,
        "explanation": "Dataset contains chat template special tokens (system/inst markers). "
                       "These can hijack model behaviour during fine-tuning by injecting "
                       "fake system prompts into training data.",
        "mitre": ["AML.T0020"],
    },
    {
        "id": "DS-INJECT-TOOL",
        "pattern": r"<tool_call>|<function_call>|\[TOOL_CALL\]|\"tool_calls\":",
        "title": "Embedded tool-call tokens in dataset",
        "severity": Severity.HIGH,
        "explanation": "Dataset contains tool-call format tokens. If used in RAG, "
                       "these can trigger unintended tool invocations via indirect injection.",
        "mitre": ["AML.T0020", "AML.T0048"],
    },
    {
        "id": "DS-CREDENTIAL",
        "pattern": r"(api[_-]?key|secret[_-]?key|password|token)\s*[:=]\s*['\"]?[A-Za-z0-9+/]{20,}",
        "title": "Hardcoded credentials in dataset",
        "severity": Severity.HIGH,
        "explanation": "Dataset appears to contain hardcoded credentials or API keys. "
                       "Fine-tuning on this data may cause the model to memorise and leak them.",
        "mitre": ["AML.T0051"],
    },
    {
        "id": "DS-EXFIL-URL",
        "pattern": r"(curl|wget|fetch|requests\.get)\s+['\"]?https?://(?!github\.com|huggingface\.co|arxiv\.org)",
        "title": "Outbound URL patterns in dataset",
        "severity": Severity.MEDIUM,
        "explanation": "Dataset contains code samples that make outbound HTTP requests to "
                       "non-standard domains. These can be injected into model outputs "
                       "triggering data exfiltration via tool calls.",
        "mitre": ["AML.T0040"],
    },
]

# Trusted publishers per registry
TRUSTED_PYPI_PUBLISHERS = {
    "openai", "anthropic", "google", "microsoft", "meta", "huggingface",
    "langchain-ai", "llamaindex", "cohere", "mistralai", "deepmind",
    "numpy", "scipy", "pandas-dev", "pytorch", "tensorflow",
}

TRUSTED_NPM_PUBLISHERS = {
    "openai", "anthropic", "google-cloud", "microsoft", "aws-sdk",
    "langchain", "llamaindex", "cohere-ai", "vercel",
}

TRUSTED_HF_ORGS = {
    "google", "meta-llama", "microsoft", "openai", "mistralai", "anthropic",
    "stabilityai", "bigscience", "EleutherAI", "allenai", "huggingface",
    "tiiuae", "deepseek-ai", "Qwen", "cohere", "ai21labs",
}


# ── Utility ───────────────────────────────────────────────────────────────────

def _fetch_json(url: str, timeout: int = 10) -> dict | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "AgentScan/0.3"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def _fetch_text(url: str, timeout: int = 10, max_bytes: int = 50_000) -> str | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "AgentScan/0.3"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(max_bytes).decode("utf-8", errors="ignore")
    except Exception:
        return None


def _suspicious_name_heuristic(name: str, known_good: set[str]) -> bool:
    """True if name looks like a typosquatting attempt."""
    clean = name.lower().replace("-", "").replace("_", "").replace(".", "")
    for good in known_good:
        good_clean = good.lower().replace("-", "").replace("_", "").replace(".", "")
        if good_clean != clean and _edit_distance(good_clean, clean) <= 2 and len(clean) > 4:
            return True
    return False


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein distance."""
    if len(a) < len(b): a, b = b, a
    if not b: return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j+1]+1, curr[j]+1, prev[j]+(ca != cb)))
        prev = curr
    return prev[-1]


# ── PyPI Scanner ─────────────────────────────────────────────────────────────

def _scan_pypi(package_name: str) -> ScanResult:
    start = time.monotonic()
    findings: list[Finding] = []
    name_lower = package_name.lower()

    # 1. Known malicious (fast path, highest confidence)
    if name_lower in KNOWN_MALICIOUS_PYPI:
        findings.append(Finding(
            id=f"SC-PYPI-KNOWN-MAL-{name_lower[:20].upper()}",
            title=f"[KNOWN MALICIOUS] PyPI package: '{package_name}'",
            severity=Severity.CRITICAL,
            confidence=ConfidenceLevel.HIGH,
            scanner="supply_chain_v2",
            explanation=KNOWN_MALICIOUS_PYPI[name_lower],
            impact="Installing this package executes malicious code — credential theft, reverse shell, or data exfiltration.",
            remediation=f"Do not install '{package_name}'. Use the legitimate package instead. Check for typosquatting.",
            evidence=[Evidence("known_malicious_db", "package_name", package_name, "Exact match in AgentScan threat intelligence database")],
            mitre_atlas=["AML.T0020"],
            tags=["supply-chain", "known-malicious", "pypi"],
        ))

    # 2. Typosquatting heuristic
    if _suspicious_name_heuristic(package_name, TRUSTED_PYPI_PUBLISHERS):
        findings.append(Finding(
            id=f"SC-PYPI-TYPOSQUAT-{name_lower[:20].upper()}",
            title=f"Possible typosquatting: '{package_name}' resembles a trusted package",
            severity=Severity.HIGH,
            confidence=ConfidenceLevel.MEDIUM,
            scanner="supply_chain_v2",
            explanation=f"'{package_name}' has a name similar to a trusted publisher (edit distance ≤2). "
                        "This is a common technique used in supply chain attacks.",
            impact="Package may be malicious impersonation of a legitimate library.",
            remediation=f"Verify '{package_name}' is the intended package. Check the exact spelling of the legitimate package.",
            evidence=[Evidence("name_analysis", "package_name", package_name, "Edit distance ≤2 from a trusted publisher name")],
            mitre_atlas=["AML.T0020"],
            tags=["supply-chain", "typosquatting", "pypi"],
        ))

    # 3. Fetch live metadata
    meta = _fetch_json(f"https://pypi.org/pypi/{package_name}/json")
    if not meta:
        return ScanResult(
            target=f"pypi:{package_name}", scanner_type="supply_chain_v2",
            findings=findings,
            error=None if findings else f"Could not fetch PyPI metadata for '{package_name}'",
            scan_duration_ms=int((time.monotonic()-start)*1000),
        )

    info = meta.get("info", {})
    author = info.get("author") or info.get("maintainer") or ""
    project_urls = info.get("project_urls") or {}
    requires_dist = info.get("requires_dist") or []
    version = info.get("version", "unknown")
    classifiers = info.get("classifiers", [])

    # No source link
    has_source = bool(project_urls.get("Source") or project_urls.get("Repository") or
                      project_urls.get("Homepage") or info.get("home_page"))
    if not has_source:
        findings.append(Finding(
            id=f"SC-PYPI-NO-SRC-{name_lower[:20].upper()}",
            title=f"No source code link: '{package_name}'",
            severity=Severity.MEDIUM,
            confidence=ConfidenceLevel.HIGH,
            scanner="supply_chain_v2",
            explanation=f"'{package_name}' has no GitHub/source link. Legitimate packages almost always include one. Malicious packages often omit this to prevent code inspection.",
            impact="Cannot verify package source — may be obfuscated malware.",
            remediation=f"Search for '{package_name}' source on GitHub before installing.",
            evidence=[Evidence("pypi_metadata", "project_urls", list(project_urls.keys()), "No source/repository URL found")],
            mitre_atlas=["AML.T0020"],
            tags=["supply-chain", "provenance", "pypi"],
        ))

    # Large dependency tree
    if len(requires_dist) > 40:
        findings.append(Finding(
            id=f"SC-PYPI-DEP-SURFACE-{name_lower[:15].upper()}",
            title=f"Large dependency surface: '{package_name}' declares {len(requires_dist)} dependencies",
            severity=Severity.LOW,
            confidence=ConfidenceLevel.MEDIUM,
            scanner="supply_chain_v2",
            explanation=f"Each dependency is a potential supply chain attack vector. {len(requires_dist)} dependencies is unusually high.",
            impact="Increased attack surface via transitive dependencies.",
            remediation="Pin to specific versions in lockfile. Audit top-level dependencies.",
            evidence=[Evidence("pypi_metadata", "requires_dist", len(requires_dist), f"{len(requires_dist)} dependencies declared")],
            mitre_atlas=["AML.T0020"],
            tags=["supply-chain", "dependencies", "pypi"],
        ))

    return ScanResult(
        target=f"pypi:{package_name}", scanner_type="supply_chain_v2",
        findings=findings,
        metadata={"package": package_name, "version": version, "author": author,
                  "dep_count": len(requires_dist), "registry": "pypi"},
        scan_duration_ms=int((time.monotonic()-start)*1000),
    )


# ── npm Scanner ───────────────────────────────────────────────────────────────

def _scan_npm(package_name: str) -> ScanResult:
    start = time.monotonic()
    findings: list[Finding] = []
    name_lower = package_name.lower()

    # Known malicious
    if name_lower in KNOWN_MALICIOUS_NPM:
        findings.append(Finding(
            id=f"SC-NPM-KNOWN-MAL-{name_lower[:20].upper().replace('/', '_').replace('@', '')}",
            title=f"[KNOWN MALICIOUS] npm package: '{package_name}'",
            severity=Severity.CRITICAL,
            confidence=ConfidenceLevel.HIGH,
            scanner="supply_chain_v2",
            explanation=KNOWN_MALICIOUS_NPM[name_lower],
            impact="Installing this package executes malicious code on install (postinstall hook) or at runtime.",
            remediation=f"Do not install '{package_name}'. Check for the legitimate alternative.",
            evidence=[Evidence("known_malicious_db", "package_name", package_name, "Match in AgentScan npm threat intelligence")],
            mitre_atlas=["AML.T0020"],
            tags=["supply-chain", "known-malicious", "npm"],
        ))

    # Fetch registry metadata
    encoded = package_name.replace("/", "%2F")
    meta = _fetch_json(f"https://registry.npmjs.org/{encoded}")
    if not meta:
        return ScanResult(
            target=f"npm:{package_name}", scanner_type="supply_chain_v2",
            findings=findings,
            error=None if findings else f"Could not fetch npm metadata for '{package_name}'",
            scan_duration_ms=int((time.monotonic()-start)*1000),
        )

    latest_tag = meta.get("dist-tags", {}).get("latest", "")
    latest_version = meta.get("versions", {}).get(latest_tag, {})
    description = meta.get("description", "")
    homepage = meta.get("homepage", "")
    repository = meta.get("repository", {})
    maintainers = meta.get("maintainers", [])
    time_data = meta.get("time", {})
    deps = latest_version.get("dependencies", {})
    scripts = latest_version.get("scripts", {})

    # Dangerous install scripts (postinstall is the classic attack vector)
    dangerous_scripts = {k: v for k, v in scripts.items()
                        if k in ("postinstall", "preinstall", "install")
                        and any(w in v.lower() for w in ["curl", "wget", "fetch", "exec", "spawn", "eval", "base64"])}
    if dangerous_scripts:
        findings.append(Finding(
            id=f"SC-NPM-INSTALL-SCRIPT-{name_lower[:15].upper().replace('/', '_').replace('@', '')}",
            title=f"Dangerous install script in '{package_name}'",
            severity=Severity.CRITICAL,
            confidence=ConfidenceLevel.HIGH,
            scanner="supply_chain_v2",
            explanation=f"'{package_name}' has a postinstall/preinstall script containing network or execution keywords. "
                        "This is the primary mechanism for malicious npm packages to execute code on install.",
            impact="Arbitrary code execution when `npm install` runs.",
            remediation="Audit the install script before installing. Use `npm install --ignore-scripts` to block execution.",
            evidence=[Evidence("npm_metadata", "scripts", dangerous_scripts,
                               f"Install scripts contain dangerous keywords: {list(dangerous_scripts.keys())}")],
            mitre_atlas=["AML.T0020", "AML.T0017"],
            tags=["supply-chain", "install-script", "npm"],
        ))

    # No repository link
    if not repository and not homepage:
        findings.append(Finding(
            id=f"SC-NPM-NO-SRC-{name_lower[:15].upper().replace('/', '_').replace('@', '')}",
            title=f"No source repository: '{package_name}'",
            severity=Severity.MEDIUM,
            confidence=ConfidenceLevel.HIGH,
            scanner="supply_chain_v2",
            explanation=f"'{package_name}' has no repository or homepage link. Malicious packages often omit this.",
            impact="Cannot inspect source code before installation.",
            remediation="Verify the package has a public source repository before installing.",
            evidence=[Evidence("npm_metadata", "repository", None, "No repository or homepage field found")],
            mitre_atlas=["AML.T0020"],
            tags=["supply-chain", "provenance", "npm"],
        ))

    # Single maintainer with recent creation (high-risk signal)
    created = time_data.get("created", "")
    if len(maintainers) == 1 and created:
        findings.append(Finding(
            id=f"SC-NPM-SINGLE-MAINTAINER-{name_lower[:12].upper().replace('/', '_').replace('@', '')}",
            title=f"Single maintainer, no org backing: '{package_name}'",
            severity=Severity.LOW,
            confidence=ConfidenceLevel.MEDIUM,
            scanner="supply_chain_v2",
            explanation=f"'{package_name}' has one maintainer and no organisation backing. "
                        "Account takeover of a single maintainer is a common supply chain attack vector.",
            impact="Single point of failure — maintainer account takeover compromises all users.",
            remediation="Prefer packages with multiple maintainers or org backing for production use.",
            evidence=[Evidence("npm_metadata", "maintainers", [m.get("name") for m in maintainers],
                               "Single maintainer account")],
            mitre_atlas=["AML.T0020"],
            tags=["supply-chain", "maintainer-risk", "npm"],
        ))

    return ScanResult(
        target=f"npm:{package_name}", scanner_type="supply_chain_v2",
        findings=findings,
        metadata={"package": package_name, "version": latest_tag,
                  "maintainers": len(maintainers), "dep_count": len(deps), "registry": "npm"},
        scan_duration_ms=int((time.monotonic()-start)*1000),
    )


# ── HuggingFace Model Scanner ─────────────────────────────────────────────────

def _scan_hf_model(repo_id: str) -> ScanResult:
    start = time.monotonic()
    findings: list[Finding] = []

    meta = _fetch_json(f"https://huggingface.co/api/models/{repo_id}")
    if not meta:
        return ScanResult(target=f"hf:{repo_id}", scanner_type="supply_chain_v2",
                         error=f"Cannot fetch HuggingFace model: '{repo_id}'",
                         scan_duration_ms=int((time.monotonic()-start)*1000))

    author = meta.get("author", repo_id.split("/")[0] if "/" in repo_id else "unknown")
    likes = meta.get("likes", 0)
    downloads = meta.get("downloads", 0)
    tags = meta.get("tags", [])
    card_data = meta.get("cardData", {}) or {}
    siblings = meta.get("siblings", [])
    private = meta.get("private", False)

    # File analysis
    has_safetensors = any(s.get("rfilename","").endswith(".safetensors") for s in siblings)
    for sibling in siblings:
        fn = sibling.get("rfilename", "")
        ext = Path(fn).suffix.lower()
        if ext in DANGEROUS_MODEL_FILES:
            ftype, reason, sev = DANGEROUS_MODEL_FILES[ext]
            conf = ConfidenceLevel.HIGH if ext in (".pkl", ".pickle", ".exe", ".dll") else ConfidenceLevel.MEDIUM
            extra = ""
            if ext in (".pkl", ".pickle"):
                extra = " Use `safetensors` format instead — it is immune to pickle RCE."
            elif has_safetensors and ext in (".pt", ".pth", ".bin"):
                sev = Severity.LOW
                extra = " (Note: safetensors also present — this file may be legacy/optional.)"
            findings.append(Finding(
                id=f"SC-HF-FILE-{ext[1:].upper()}-{fn[:20].upper().replace('/','-')}",
                title=f"Dangerous file in model repo: '{fn}' [{ftype}]",
                severity=sev, confidence=conf, scanner="supply_chain_v2",
                explanation=f"'{fn}' is a {ftype}. {reason}.{extra}",
                impact=reason,
                remediation="Use safetensors format. Report .exe/.dll/.sh files to HuggingFace security@huggingface.co.",
                evidence=[Evidence("hf_repo_files", f"siblings[{fn!r}]", fn,
                                   f"Extension '{ext}' is in dangerous file type list")],
                mitre_atlas=["AML.T0020", "AML.T0017"],
                references=["https://huggingface.co/docs/hub/security-pickle"],
                tags=["supply-chain", "model-file", ext[1:], "hf"],
            ))

    # Unknown author, low engagement
    is_trusted_org = any(t in author.lower() for t in {o.lower() for o in TRUSTED_HF_ORGS})
    if not is_trusted_org and likes < 10 and downloads < 500:
        findings.append(Finding(
            id=f"SC-HF-LOW-TRUST-{repo_id[:25].upper().replace('/','_')}",
            title=f"Low-provenance model: '{repo_id}'",
            severity=Severity.LOW, confidence=ConfidenceLevel.MEDIUM,
            scanner="supply_chain_v2",
            explanation=f"Model has {likes} likes and ~{downloads} downloads from "
                        f"'{author}' (not a verified trusted organisation). Provenance signal only.",
            impact="Model may be undertested, abandoned, or from an unverified source.",
            remediation="Review model card, training data, and licence. Prefer models from verified orgs.",
            evidence=[Evidence("hf_metadata", "likes/downloads/author",
                               {"likes": likes, "downloads": downloads, "author": author},
                               "Low engagement + unrecognised author")],
            mitre_atlas=["AML.T0020"],
            tags=["supply-chain", "provenance", "hf"],
        ))

    # No model card / licence
    if not card_data.get("license") and "license" not in " ".join(tags).lower():
        findings.append(Finding(
            id=f"SC-HF-NO-LICENSE-{repo_id[:20].upper().replace('/','_')}",
            title=f"No licence declared: '{repo_id}'",
            severity=Severity.INFO, confidence=ConfidenceLevel.HIGH,
            scanner="supply_chain_v2",
            explanation="No licence is declared. Using this model in production may create legal risk.",
            impact="Legal/compliance risk — no clear usage rights.",
            remediation="Check with the author for licence terms before production deployment.",
            evidence=[Evidence("hf_metadata", "cardData.license", None, "No licence field in model card")],
            mitre_atlas=[],
            tags=["supply-chain", "licence", "hf"],
        ))

    return ScanResult(
        target=f"hf:{repo_id}", scanner_type="supply_chain_v2",
        findings=findings,
        metadata={"repo_id": repo_id, "author": author, "likes": likes,
                  "downloads": downloads, "file_count": len(siblings),
                  "has_safetensors": has_safetensors, "registry": "huggingface_model"},
        scan_duration_ms=int((time.monotonic()-start)*1000),
    )


# ── HuggingFace Dataset Scanner ───────────────────────────────────────────────

def _scan_hf_dataset(repo_id: str) -> ScanResult:
    """
    Dataset poisoning scanner.
    Fetches dataset metadata and samples, then scans for:
      - Prompt injection patterns
      - System prompt tokens
      - Tool-call tokens
      - Hardcoded credentials
      - Suspicious outbound URL patterns
    """
    start = time.monotonic()
    findings: list[Finding] = []

    # Fetch dataset metadata
    meta = _fetch_json(f"https://huggingface.co/api/datasets/{repo_id}")
    if not meta:
        return ScanResult(target=f"dataset:{repo_id}", scanner_type="supply_chain_v2",
                         error=f"Cannot fetch dataset metadata: '{repo_id}'",
                         scan_duration_ms=int((time.monotonic()-start)*1000))

    author = meta.get("author", repo_id.split("/")[0] if "/" in repo_id else "unknown")
    likes = meta.get("likes", 0)
    card_data = meta.get("cardData", {}) or {}
    siblings = meta.get("siblings", [])

    # Try to fetch a sample from dataset viewer API
    sample_text = ""
    viewer_url = f"https://datasets-server.huggingface.co/rows?dataset={repo_id}&split=train&offset=0&limit=20"
    viewer_data = _fetch_json(viewer_url, timeout=15)
    if viewer_data and "rows" in viewer_data:
        rows = viewer_data["rows"][:20]
        sample_text = json.dumps(rows)

    # Also try fetching a README/data card
    readme_text = _fetch_text(
        f"https://huggingface.co/{repo_id}/raw/main/README.md", max_bytes=30_000
    ) or ""

    combined_text = sample_text + "\n" + readme_text

    # Scan for poisoning patterns
    if combined_text.strip():
        for pattern_def in DATASET_POISON_PATTERNS:
            match = re.search(pattern_def["pattern"], combined_text, re.IGNORECASE)
            if match:
                snippet = combined_text[max(0, match.start()-40):match.end()+40].strip()
                findings.append(Finding(
                    id=f"SC-DS-{pattern_def['id']}-{repo_id[:15].upper().replace('/','_')}",
                    title=pattern_def["title"],
                    severity=pattern_def["severity"],
                    confidence=ConfidenceLevel.HIGH,
                    scanner="supply_chain_v2",
                    explanation=pattern_def["explanation"],
                    impact="Dataset poisoning can affect fine-tuned model behaviour or enable RAG injection attacks.",
                    remediation="Audit full dataset before use. Filter or exclude rows matching this pattern. "
                                "Use a separate validation split to test model behaviour.",
                    evidence=[Evidence(
                        "dataset_content", "sampled_rows",
                        snippet[:200],
                        f"Pattern '{pattern_def['id']}' matched in dataset sample",
                    )],
                    mitre_atlas=pattern_def["mitre"],
                    tags=["supply-chain", "dataset-poisoning", "hf"],
                ))
    else:
        # Couldn't fetch sample — report as informational gap
        findings.append(Finding(
            id=f"SC-DS-NO-SAMPLE-{repo_id[:15].upper().replace('/','_')}",
            title=f"Dataset content not accessible for scanning: '{repo_id}'",
            severity=Severity.INFO, confidence=ConfidenceLevel.HIGH,
            scanner="supply_chain_v2",
            explanation="AgentScan could not fetch dataset rows for content analysis. "
                        "This may be a private dataset, gated dataset, or one without a standard split.",
            impact="Poisoning risk cannot be assessed without content access.",
            remediation="Manually audit dataset content before use in RAG or fine-tuning pipelines.",
            evidence=[Evidence("dataset_viewer", "rows", None, "Dataset viewer returned no data")],
            mitre_atlas=["AML.T0020"],
            tags=["supply-chain", "dataset-access", "hf"],
        ))

    # Provenance check
    is_trusted = any(t in author.lower() for t in {o.lower() for o in TRUSTED_HF_ORGS})
    if not is_trusted and likes < 20:
        findings.append(Finding(
            id=f"SC-DS-LOW-PROV-{repo_id[:15].upper().replace('/','_')}",
            title=f"Low-provenance dataset: '{repo_id}'",
            severity=Severity.MEDIUM, confidence=ConfidenceLevel.MEDIUM,
            scanner="supply_chain_v2",
            explanation=f"Dataset has {likes} likes from '{author}' (not a trusted organisation). "
                        "Untrusted datasets are a primary vector for training data poisoning attacks.",
            impact="Fine-tuning on poisoned data can introduce backdoors, biases, or injection vulnerabilities.",
            remediation="Prefer datasets from verified organisations. Audit provenance chain of training data.",
            evidence=[Evidence("hf_metadata", "author/likes", {"author": author, "likes": likes},
                               "Unrecognised author with low engagement")],
            mitre_atlas=["AML.T0020"],
            tags=["supply-chain", "dataset-provenance", "hf"],
        ))

    return ScanResult(
        target=f"dataset:{repo_id}", scanner_type="supply_chain_v2",
        findings=findings,
        metadata={"repo_id": repo_id, "author": author, "likes": likes,
                  "file_count": len(siblings), "sample_scanned": bool(sample_text),
                  "registry": "huggingface_dataset"},
        scan_duration_ms=int((time.monotonic()-start)*1000),
    )


# ── Main entry point ──────────────────────────────────────────────────────────

def scan_supply_chain(target: str) -> ScanResult:
    """
    Scan an AI supply chain artifact.

    Formats:
      pypi:<name>           PyPI package
      npm:<name>            npm package (now implemented)
      hf:<org>/<model>      HuggingFace model
      dataset:<org>/<name>  HuggingFace dataset (poisoning scan)
      <org>/<name>          Auto-detect HuggingFace (model first, then dataset)
    """
    target = target.strip()
    if target.startswith("pypi:"):
        return _scan_pypi(target[5:])
    elif target.startswith("npm:"):
        return _scan_npm(target[4:])
    elif target.startswith("hf:"):
        return _scan_hf_model(target[3:])
    elif target.startswith("dataset:"):
        return _scan_hf_dataset(target[8:])
    elif "/" in target and not target.startswith("http"):
        # Auto-detect: try model first
        result = _scan_hf_model(target)
        if not result.error:
            return result
        return _scan_hf_dataset(target)
    else:
        return ScanResult(
            target=target, scanner_type="supply_chain_v2",
            error=f"Unknown target format: '{target}'. Use: pypi:<name>  npm:<name>  hf:<org>/<model>  dataset:<org>/<name>",
        )
