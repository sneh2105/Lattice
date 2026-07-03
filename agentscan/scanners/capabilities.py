# -*- coding: ascii -*-
"""
Canonical capability taxonomy and detection logic.

THIS IS THE SINGLE SOURCE OF TRUTH for:
  - CAPABILITY_MAP        (capability classes, keywords, severity, impact)
  - DANGEROUS_COMBINATIONS (capability pairs that form attack chains)
  - detect_capabilities() / detect_capabilities_with_reasons()

Every scanner (agent_scanner, source_scanner, mcp_scanner, mcp_scanner_v2)
and every graph/trust path MUST import detection from this module.

History: rounds 1-3 of adversarial QA kept re-discovering the same keyword
bugs because the taxonomy was duplicated in three files and fixes only
landed in one copy at a time (e.g. the bare-"run" false positive on
query_prod_db was fixed in mcp_scanner.py in round 1 and re-found in
mcp_scanner_v2.py in round 3). Do NOT re-introduce per-scanner keyword
lists. Add scanner-specific presentation metadata (titles, remediation
text, graph edges) in the scanner, keyed by the capability name returned
from here -- never scanner-specific matching logic.
"""

from __future__ import annotations

import re
import unicodedata

from agentscan.models import Severity

# Common Cyrillic/Greek lookalike characters mapped to their Latin
# equivalents, so a homoglyph-obfuscated docstring/name ("runs a
# diagnostic" with Cyrillic 'a', U+0430) still matches lexically.
# This is a defence-in-depth measure alongside NFKC normalisation --
# NFKC alone does not fold Cyrillic into Latin since they are
# legitimately distinct scripts, not compatibility variants.
_CONFUSABLES = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0445": "x", "\u0455": "s", "\u0456": "i",
    "\u0410": "A", "\u0415": "E", "\u041e": "O", "\u0420": "P",
    "\u0421": "C", "\u0425": "X",
}
_CONFUSABLE_TABLE = str.maketrans(_CONFUSABLES)

# ---------------------------------------------------------------------------
# Capability taxonomy
# Capabilities are grouped by the access class they grant.
# Keywords are matched as substrings against the normalised
# name+description+permissions text (see detect_capabilities below).
#
# Rules learned from QA rounds 1-3 (do not undo):
#   - NO bare "run"/"execute" in shell_exec (round 1: query_prod_db FP).
#     Compound forms + the token co-occurrence stage cover the real cases.
#   - NO bare "refund" in financial_transaction (round 1:
#     calculate_refund_estimate FP).
#   - NO bare "repl" or "code" in code_execution (round 3: "repl" matched
#     inside "replica", flagging standard DB terminology as CRITICAL).
#   - NO bare "eval" (matches "retrieval"/"evaluate"), NO bare "token"
#     (matches "tokenize"), NO bare "auth" (matches "author").
# ---------------------------------------------------------------------------

CAPABILITY_MAP: dict[str, dict] = {
    "shell_exec": {
        "keywords": ["shell_exec", "run_shell", "run_command", "bash", "subprocess", "os.system", "exec_host", "exec_command", "shell_command", "terminal", "execute_shell", "execute_command", "execute_script", "run_code", "exec_code", "run_script"],
        "severity": Severity.CRITICAL,
        "description": "Can execute arbitrary operating system commands",
        "impact": "Full host compromise: data exfiltration, persistence, lateral movement",
        "mitre": ["AML.T0017", "AML.T0048"],
        "cwe": ["CWE-78"],
    },
    "file_write": {
        "keywords": ["file_write", "write_file", "create_file", "delete_file", "move_file", "filesystem", "disk_write", "save_file"],
        "severity": Severity.HIGH,
        "description": "Can write to the filesystem",
        "impact": "Malicious file creation, config tampering, persistence",
        "mitre": ["AML.T0048"],
        "cwe": ["CWE-73"],
    },
    "file_read": {
        "keywords": ["file_read", "read_file", "filesystem", "disk_read", "open_file", "cat"],
        "severity": Severity.MEDIUM,
        "description": "Can read arbitrary files from the filesystem",
        "impact": "Credential theft, source code exfiltration, config exposure",
        "mitre": ["AML.T0051"],
        "cwe": ["CWE-22"],
    },
    "network_egress": {
        "keywords": ["http", "request", "fetch", "web", "browser", "browse", "curl", "network", "internet", "url"],
        "severity": Severity.MEDIUM,
        "description": "Can make outbound network requests",
        "impact": "Data exfiltration, C2 communication, SSRF",
        "mitre": ["AML.T0040"],
        "cwe": ["CWE-918"],
    },
    "secret_access": {
        "keywords": ["secret", "vault", "credential", "api_key", "env", "ssm", "aws_secrets", "keychain", "password"],
        "severity": Severity.CRITICAL,
        "description": "Can access secrets, credentials, or API keys",
        "impact": "Credential theft enabling further account compromise",
        "mitre": ["AML.T0051"],
        "cwe": ["CWE-522"],
    },
    "database": {
        "keywords": ["database", "db", "sql", "query", "postgres", "mysql", "mongo", "redis", "dynamo", "sqlite"],
        "severity": Severity.HIGH,
        "description": "Can query or modify databases",
        "impact": "Data exfiltration, data manipulation, injection attacks",
        "mitre": ["AML.T0048"],
        "cwe": ["CWE-89"],
    },
    "email_send": {
        "keywords": ["email", "send_mail", "smtp", "sendgrid", "ses", "mail", "gmail"],
        "severity": Severity.MEDIUM,
        "description": "Can send emails",
        "impact": "Phishing, social engineering, data exfiltration via email",
        "mitre": ["AML.T0040"],
        "cwe": [],
    },
    "financial_transaction": {
        "keywords": ["wire_transfer", "wire transfer", "transfer_funds",
                      "initiate_transfer", "initiate_payment", "process_payment",
                      "issue_refund", "process_refund", "refund_payment",
                      "charge_card", "charge_customer", "stripe", "ach_transfer",
                      "disburse", "payout", "send_money", "move_money"],
        "severity": Severity.CRITICAL,
        "description": "Can initiate financial transactions or move money",
        "impact": "Direct financial loss via unauthorised or injected transactions",
        "mitre": ["AML.T0048"],
        "cwe": ["CWE-840"],
    },
    "code_execution": {
        "keywords": ["python_repl", "code_interpreter", "eval_code", "execute_code", "jupyter", "notebook", "ipython", "interpreter"],
        "severity": Severity.CRITICAL,
        "description": "Can execute arbitrary code in a runtime",
        "impact": "Full arbitrary code execution within agent context",
        "mitre": ["AML.T0017"],
        "cwe": ["CWE-95"],
    },
    "cloud_api": {
        "keywords": ["aws", "gcp", "azure", "s3", "ec2", "iam", "lambda", "cloud", "bucket"],
        "severity": Severity.HIGH,
        "description": "Can call cloud provider APIs",
        "impact": "Cloud resource manipulation, data access, privilege escalation",
        "mitre": ["AML.T0048"],
        "cwe": [],
    },
    "process_spawn": {
        "keywords": ["spawn_process", "create_process", "spawn_agent", "fork_process", "spawn", "fork"],
        "severity": Severity.CRITICAL,
        "description": "Can spawn child processes or sub-agents",
        "impact": "Sandbox escape, resource exhaustion, delegated attack execution",
        "mitre": ["AML.T0017", "AML.T0048"],
        "cwe": ["CWE-78"],
    },
}

# ---------------------------------------------------------------------------
# Dangerous capability combinations that together form attack paths.
# ---------------------------------------------------------------------------

DANGEROUS_COMBINATIONS: list[dict] = [
    {
        "caps": {"secret_access", "network_egress"},
        "title": "Credential exfiltration path",
        "severity": Severity.CRITICAL,
        "description": (
            "The agent can read secrets AND make outbound network requests. "
            "This is a complete exfiltration path: an attacker who controls the agent's "
            "prompt (via prompt injection or malicious tool output) can instruct it to "
            "read credentials and POST them to an attacker-controlled server."
        ),
        "entry": "Prompt injection via user input or malicious tool output",
        "impact": "AWS/cloud credentials, API keys, or secrets exfiltrated to attacker",
        "mitre": ["AML.T0051", "AML.T0040"],
    },
    {
        "caps": {"shell_exec", "network_egress"},
        "title": "Remote code execution + exfiltration path",
        "severity": Severity.CRITICAL,
        "description": (
            "The agent can execute shell commands AND make network requests. "
            "Combined, this enables full reverse shell, C2 beaconing, or data exfiltration."
        ),
        "entry": "Prompt injection or malicious MCP tool response",
        "impact": "Host compromise with persistent attacker foothold",
        "mitre": ["AML.T0017", "AML.T0040"],
    },
    {
        "caps": {"shell_exec", "secret_access"},
        "title": "Credential theft via shell execution",
        "severity": Severity.CRITICAL,
        "description": (
            "The agent can execute shell commands AND access secrets. "
            "Shell access is itself an exfiltration channel (curl, wget, DNS): "
            "an attacker can instruct the agent to read credentials via its "
            "secret-access tool and send them out through the shell, so no "
            "separate network tool is required to complete the chain."
        ),
        "entry": "Prompt injection via user input or malicious tool output",
        "impact": "Credentials read and exfiltrated through shell-native network utilities",
        "mitre": ["AML.T0051", "AML.T0017", "AML.T0040"],
    },
    {
        "caps": {"shell_exec", "database"},
        "title": "Database exfiltration via shell execution",
        "severity": Severity.HIGH,
        "description": (
            "The agent can query databases AND execute shell commands. "
            "Shell access provides the outbound channel (curl, wget, DNS), so an "
            "attacker can dump sensitive tables via the database tool and "
            "exfiltrate the results through the shell without any dedicated "
            "network tool."
        ),
        "entry": "Prompt injection via user-supplied query",
        "impact": "Database contents exfiltrated through shell-native network utilities",
        "mitre": ["AML.T0051", "AML.T0017", "AML.T0040"],
    },
    {
        "caps": {"file_write", "code_execution"},
        "title": "Persistent malware drop path",
        "severity": Severity.CRITICAL,
        "description": (
            "The agent can write files AND execute code. An attacker can instruct it to "
            "write malicious scripts and then execute them, achieving persistent compromise."
        ),
        "entry": "Malicious prompt or tool output",
        "impact": "Persistent backdoor or malware dropped on host",
        "mitre": ["AML.T0017", "AML.T0048"],
    },
    {
        "caps": {"cloud_api", "secret_access"},
        "title": "Cloud privilege escalation path",
        "severity": Severity.CRITICAL,
        "description": (
            "The agent can access cloud APIs AND read secrets. This enables privilege "
            "escalation: steal IAM credentials, then use them to access other cloud resources."
        ),
        "entry": "Prompt injection via user message",
        "impact": "Cloud account takeover via stolen IAM credentials",
        "mitre": ["AML.T0051", "AML.T0048"],
    },
    {
        "caps": {"database", "network_egress"},
        "title": "Database exfiltration path",
        "severity": Severity.HIGH,
        "description": (
            "The agent can query databases AND make outbound requests. "
            "An attacker can instruct it to dump sensitive tables and exfiltrate the data."
        ),
        "entry": "Prompt injection via user-supplied query",
        "impact": "Full database contents exfiltrated to attacker",
        "mitre": ["AML.T0051", "AML.T0040"],
    },
    {
        "caps": {"financial_transaction", "database"},
        "title": "Fraudulent transaction path",
        "severity": Severity.CRITICAL,
        "description": (
            "The agent can both query records AND initiate financial transactions. "
            "An attacker can instruct it to look up account/payment details from the "
            "database and then trigger an unauthorised transfer using injected values."
        ),
        "entry": "Prompt injection via user message or malicious tool output",
        "impact": "Direct financial loss via fraudulent or unauthorised transactions",
        "mitre": ["AML.T0051", "AML.T0048"],
    },
]


def normalise(name: str) -> str:
    folded = unicodedata.normalize("NFKC", name).translate(_CONFUSABLE_TABLE)
    return folded.lower().replace("-", "_").replace(" ", "_")


# ---------------------------------------------------------------------------
# Stage 2: shell_exec token analysis.
#
# Design (rounds 2-3):
#   - Verb/target co-occurrence catches run_remediation_script,
#     execute_patch_script etc. without re-introducing the bare-"run"
#     false positive on query_prod_db ("Run a read query...").
#   - The verb and target sets are DISJOINT. Round 3 found that having
#     "shell"/"bash" in both sets let a single word satisfy the "pair"
#     by itself, so detect_shell_companies (AML/finance tooling) was
#     flagged CRITICAL. A pair now requires two different words.
#   - "shell"/"bash" instead act as standalone triggers, but ONLY in
#     the tool NAME (a deliberate naming choice), never in description
#     prose, where "no shell access" or "shell company" appear
#     legitimately. A collocation guard additionally skips the finance
#     sense ("shell company/companies/corp...").
#   - Bare "process" was removed from the target set (round 3:
#     run_batch_process, a nightly analytics job, was flagged CRITICAL).
#     "subprocess" remains, and compound keywords in CAPABILITY_MAP
#     cover the unambiguous OS forms.
# ---------------------------------------------------------------------------

_SHELL_VERB_TOKENS = {"run", "exec", "execute", "invoke"}
_SHELL_TARGET_TOKENS = {"script", "command", "commands", "cmd", "terminal", "subprocess"}
_SHELL_STANDALONE_TOKENS = {"shell", "bash"}
# "shell" immediately followed by one of these is finance/legal
# terminology, not an OS shell.
_SHELL_BENIGN_FOLLOWERS = {"company", "companies", "corp", "corps",
                           "corporation", "corporations", "entity",
                           "entities", "firm", "firms"}


def _tokenise(text: str) -> list[str]:
    """Split text into ordered lowercase word tokens, stripping punctuation."""
    cleaned = re.sub(r"[^\w\s-]", " ", text.lower())
    cleaned = cleaned.replace("-", " ").replace("_", " ")
    return cleaned.split()


def shell_token_reason(tool_name: str, description: str = "") -> str | None:
    """
    Return a human-readable reason if the name/description indicates
    shell execution via token analysis, else None.
    """
    combined_tokens = _tokenise(tool_name + " " + description)
    token_set = set(combined_tokens)

    verb_hits = token_set & _SHELL_VERB_TOKENS
    target_hits = token_set & _SHELL_TARGET_TOKENS
    if verb_hits and target_hits:
        return ("shell-verb token '" + sorted(verb_hits)[0]
                + "' and shell-target token '" + sorted(target_hits)[0]
                + "' co-occur in the tool name/description")

    # Standalone shell/bash: tool NAME only, with finance-collocation guard.
    name_tokens = _tokenise(tool_name)
    for i, tok in enumerate(name_tokens):
        if tok in _SHELL_STANDALONE_TOKENS:
            nxt = name_tokens[i + 1] if i + 1 < len(name_tokens) else ""
            if nxt in _SHELL_BENIGN_FOLLOWERS:
                continue
            return ("tool name contains the standalone token '" + tok
                    + "', which refers to an OS shell")
    return None


def _has_shell_token_pair(text: str) -> bool:
    """
    Backward-compatible boolean wrapper. The text is treated as a
    combined name+description; standalone-token analysis is applied to
    the whole text's first-token context conservatively via
    shell_token_reason with the text as the name.
    Prefer shell_token_reason(name, description) in new code.
    """
    return shell_token_reason(text) is not None


def detect_capabilities_with_reasons(
    tool_name: str,
    tool_def: dict | None = None,
    extra_text: str = "",
) -> dict[str, str]:
    """
    Map a tool definition to {capability_name: reason_string}.

    The reason explains exactly which keyword(s) or token pair fired,
    so findings can show reviewers WHY a capability was assigned.
    """
    reasons: dict[str, str] = {}
    haystack = normalise(tool_name)
    description = ""
    if isinstance(tool_def, dict):
        description = tool_def.get("description", "") or ""
        haystack += " " + normalise(description)
        haystack += " " + normalise(str(tool_def.get("permissions", "")))
        haystack += " " + normalise(str(tool_def.get("type", "")))
    if extra_text:
        haystack += " " + normalise(extra_text)

    # Very short keywords (<= 3 chars, e.g. "db", "aws", "ses", "cat")
    # are matched as whole tokens only. As bare substrings they embed in
    # ordinary words ("db" in "feedback", "ses" in "assess", "cat" in
    # "category") -- the same false-positive class QA rounds 1-3 kept
    # finding with "run", "repl", and "refund".
    haystack_tokens = set(haystack.replace("_", " ").split())

    def _kw_hit(kw: str) -> bool:
        if len(kw) <= 3:
            return kw in haystack_tokens
        return kw in haystack

    for cap_name, cap in CAPABILITY_MAP.items():
        hits = [kw for kw in cap["keywords"] if _kw_hit(kw)]
        if hits:
            reasons[cap_name] = "matched keyword(s): " + ", ".join(
                "'" + h + "'" for h in hits[:3]
            )

    # Stage 2: token analysis for shell_exec, only when the direct
    # keyword list did not already match.
    if "shell_exec" not in reasons:
        token_reason = shell_token_reason(tool_name, description)
        if token_reason:
            reasons["shell_exec"] = token_reason

    return reasons


def detect_capabilities(tool_name: str, tool_def: dict | None = None,
                        extra_text: str = "") -> set[str]:
    """Map a tool definition to a set of capability class names."""
    return set(detect_capabilities_with_reasons(tool_name, tool_def, extra_text))


# ---------------------------------------------------------------------------
# Behavioral (AST call-site) detection layer.
#
# Everything above this line matches on the tool's declared NAME and
# DESCRIPTION. A round-4 red-team review demonstrated that this is
# trivially evadable: a function named "utility_helper" with the
# docstring "A generic utility helper for the agent" that contains a
# real `subprocess.run(cmd, shell=True)` call in its body scores
# 0/100 with zero findings, because nothing ever inspects what the
# function actually calls. Three variants were demonstrated:
#   1. Boring name + boring docstring, dangerous call in the body.
#   2. No docstring at all (real behavior only in a `#` comment).
#   3. A fake "docstring" (an f-string literal, which Python does not
#      recognise as a docstring -- ast.get_docstring() returns None).
# This is a fundamentally different risk than a keyword miss: it's a
# clean report on code that is not clean, which is worse than no
# report because a team reading "risk 0/100" will not think to look
# further.
#
# This layer is intentionally independent of and additive to the
# lexical layer above: it inspects the actual AST of a function body
# for calls to known-dangerous stdlib/SDK functions, regardless of
# what the function's name or docstring claim. It cannot be evaded by
# renaming, omitting, or lying in the docstring, because it never
# reads the docstring at all -- only real Call nodes in the body.
#
# Scope/limitations (documented, not silently claimed as complete):
#   - Only catches direct, unresolved-alias calls (subprocess.run(...),
#     os.system(...)). It does not do inter-procedural analysis, does
#     not resolve `f = subprocess.run; f(...)`, and does not evaluate
#     the split-string evasion (`"sh" + "ell_ex" + "ec"`) as a STRING
#     VALUE -- it matches the actual function *called*, which is a
#     stronger signal than the string, so that evasion is caught for
#     a different reason (the real call is still `subprocess.run(...,
#     shell=True)`, however the *variable* naming it is obfuscated).
#   - Does not execute or symbolically evaluate code -- pure static
#     AST pattern matching on call targets.
# ---------------------------------------------------------------------------

# dotted call path -> (capability, reason fragment)
# Matched against the joined dotted name of the call target, e.g.
# "subprocess.run", "os.system", "boto3.client".
BODY_CALL_SIGNALS: dict[str, tuple[str, str]] = {
    "subprocess.run": ("shell_exec", "calls subprocess.run(...)"),
    "subprocess.call": ("shell_exec", "calls subprocess.call(...)"),
    "subprocess.check_call": ("shell_exec", "calls subprocess.check_call(...)"),
    "subprocess.check_output": ("shell_exec", "calls subprocess.check_output(...)"),
    "subprocess.popen": ("shell_exec", "calls subprocess.Popen(...)"),
    "os.system": ("shell_exec", "calls os.system(...)"),
    "os.popen": ("shell_exec", "calls os.popen(...)"),
    "os.execv": ("shell_exec", "calls os.execv(...)"),
    "os.execve": ("shell_exec", "calls os.execve(...)"),
    "os.spawnl": ("process_spawn", "calls os.spawnl(...)"),
    "os.spawnv": ("process_spawn", "calls os.spawnv(...)"),
    "pty.spawn": ("shell_exec", "calls pty.spawn(...)"),
    "eval": ("code_execution", "calls eval(...) on runtime data"),
    "exec": ("code_execution", "calls exec(...) on runtime data"),
    "compile": ("code_execution", "calls compile(...) to build executable code"),
    "boto3.client": ("cloud_api", "calls boto3.client(...) (AWS SDK)"),
    "hvac.client": ("secret_access", "calls hvac.Client(...) (HashiCorp Vault SDK)"),
    "requests.get": ("network_egress", "calls requests.get(...)"),
    "requests.post": ("network_egress", "calls requests.post(...)"),
    "requests.put": ("network_egress", "calls requests.put(...)"),
    "requests.request": ("network_egress", "calls requests.request(...)"),
    "httpx.get": ("network_egress", "calls httpx.get(...)"),
    "httpx.post": ("network_egress", "calls httpx.post(...)"),
    "urllib.request.urlopen": ("network_egress", "calls urllib.request.urlopen(...)"),
}

# Second-argument-string signal: some AWS/secret-manager calls only
# indicate secret_access based on their argument, not the call target
# alone (boto3.client("s3") is cloud_api but not secret_access;
# boto3.client("secretsmanager") is both).
_BOTO_SECRET_SERVICES = {"secretsmanager", "ssm"}


def _dotted_call_name(func_node) -> str:
    """Best-effort dotted name of a Call node's func, e.g. 'subprocess.run'."""
    import ast
    parts: list[str] = []
    node = func_node
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def detect_capabilities_from_body(func_node) -> dict[str, str]:
    """
    Walk a function's AST body for calls to known-dangerous stdlib/SDK
    functions. Independent of and additive to name/description
    matching -- see module docstring above for why this layer exists.

    func_node: an ast.FunctionDef or ast.AsyncFunctionDef.
    Returns {capability_name: reason_string}.
    """
    import ast

    reasons: dict[str, str] = {}
    for node in ast.walk(func_node):
        if not isinstance(node, ast.Call):
            continue
        dotted = _dotted_call_name(node.func).lower()
        if not dotted:
            continue

        if dotted in BODY_CALL_SIGNALS:
            cap, reason = BODY_CALL_SIGNALS[dotted]
            reasons.setdefault(cap, "AST evidence: " + reason)
            if dotted == "boto3.client" and node.args:
                first = node.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    if first.value.lower() in _BOTO_SECRET_SERVICES:
                        reasons.setdefault(
                            "secret_access",
                            "AST evidence: calls boto3.client(" + repr(first.value) + ")"
                        )
            continue

        # bare eval/exec/compile: dotted name is just "eval" etc (no dots)
        if dotted in ("eval", "exec", "compile"):
            cap, reason = BODY_CALL_SIGNALS[dotted]
            reasons.setdefault(cap, "AST evidence: " + reason)
            continue

    return reasons
