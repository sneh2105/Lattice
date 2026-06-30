"""
Agent Identity Graph
====================
Builds a complete picture of what an agent can actually access —
not just "it has shell" but:

  Identity → Permissions → Secrets → Memory → Vector DB
  → LLM → Tools → Network → Filesystem → Cloud APIs

Answers: "What can this agent actually do?"

Sources:
  - Agent config (static)
  - MCP server manifests
  - Runtime events (dynamic, if available)
  - IAM / permission declarations
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

from agentscan.models import ScanResult, Finding, Evidence, Severity, ConfidenceLevel


@dataclass
class IdentityNode:
    """A resource or capability accessible by the agent."""
    id: str
    category: str        # "identity" | "permission" | "secret" | "memory" | "vectordb"
                         # "llm" | "tool" | "network" | "filesystem" | "cloud" | "database"
    label: str
    access_level: str    # "read" | "write" | "admin" | "execute" | "none"
    scoped: bool         # is access properly scoped/minimal?
    details: dict[str, Any] = field(default_factory=dict)
    risk_notes: list[str] = field(default_factory=list)


@dataclass
class AccessRelationship:
    src: str            # identity/agent node
    dst: str            # resource node
    access_type: str
    via: str            # "tool" | "config" | "runtime" | "implicit"
    conditional: bool   # requires auth/approval?


@dataclass
class AgentIdentityGraph:
    """Complete access graph for an agent."""
    agent_id: str
    agent_name: str
    nodes: list[IdentityNode]
    relationships: list[AccessRelationship]
    findings: list[Finding]
    # Summary answers
    can_access_internet: bool
    can_access_secrets: bool
    can_execute_code: bool
    can_write_filesystem: bool
    can_access_cloud: bool
    can_access_database: bool
    can_access_email: bool
    has_persistent_memory: bool
    identity_defined: bool
    permissions_scoped: bool
    effective_permissions: list[str]     # flat list of what the agent can do
    risk_score: int                      # 0-100

    def answer(self, question: str) -> str:
        """Answer natural-language questions about agent access."""
        q = question.lower()
        if "internet" in q or "network" in q or "web" in q:
            return "YES" if self.can_access_internet else "NO"
        if "secret" in q or "credential" in q or "key" in q:
            return "YES" if self.can_access_secrets else "NO"
        if "code" in q or "shell" in q or "exec" in q:
            return "YES" if self.can_execute_code else "NO"
        if "file" in q or "filesystem" in q or "disk" in q:
            return "YES" if self.can_write_filesystem else "NO"
        if "cloud" in q or "aws" in q or "gcp" in q:
            return "YES" if self.can_access_cloud else "NO"
        if "database" in q or "db" in q or "sql" in q:
            return "YES" if self.can_access_database else "NO"
        if "email" in q or "mail" in q:
            return "YES" if self.can_access_email else "NO"
        if "memory" in q or "remember" in q:
            return "YES" if self.has_persistent_memory else "NO"
        return "Unknown — ask about a specific capability"


# ── Capability taxonomy ───────────────────────────────────────────────────────

CAPABILITY_CATEGORIES = {
    # identity
    "api_key":          ("identity", "API Key / Service Account", "read", False),
    "oauth_token":      ("identity", "OAuth Token", "read", True),
    "service_account":  ("identity", "Service Account", "admin", False),

    # permissions
    "shell_exec":       ("tool", "OS Shell / Command Execution", "execute", False),
    "code_execution":   ("tool", "Code Interpreter", "execute", False),
    "file_read":        ("filesystem", "Filesystem (Read)", "read", False),
    "file_write":       ("filesystem", "Filesystem (Write)", "write", False),
    "network_egress":   ("network", "Internet / External Network", "write", False),
    "database":         ("database", "Database", "read", False),
    "email_send":       ("network", "Email / SMTP", "write", False),
    "financial_transaction": ("network", "Financial Transaction / Payment", "write", False),
    "cloud_api":        ("cloud", "Cloud Provider APIs (AWS/GCP/Azure)", "admin", False),
    "secret_access":    ("secret", "Secret Manager / Vault", "read", False),
    "memory_read":      ("memory", "Agent Memory (Read)", "read", True),
    "memory_write":     ("memory", "Agent Memory (Write)", "write", False),
    "vector_db":        ("vectordb", "Vector Database / RAG", "read", True),
}

# Risk weights per capability
CAPABILITY_RISK = {
    "shell_exec": 40, "code_execution": 40, "secret_access": 35,
    "cloud_api": 30, "database": 25, "file_write": 20, "network_egress": 15,
    "file_read": 10, "email_send": 10, "memory_write": 8,
    "financial_transaction": 38,
    "memory_read": 3, "vector_db": 3,
}


def build_identity_graph(
    agent_name: str,
    capabilities: list[str],
    tools: list[dict] = None,
    identity: dict = None,
    memory_config: dict = None,
    cloud_config: dict = None,
    network_policy: dict = None,
) -> AgentIdentityGraph:
    """
    Build a complete agent identity graph from configuration.

    Parameters:
        agent_name: display name for the agent
        capabilities: list of capability strings (from agent_scanner)
        tools: raw tool definitions
        identity: dict with keys: name, type (api_key/oauth/service_account), scoped
        memory_config: dict with: type, provider, persistent
        cloud_config: dict with: provider, iam_role, scoped
        network_policy: dict with: allowlist, block_private_ips
    """
    nodes: list[IdentityNode] = []
    relationships: list[AccessRelationship] = []
    findings: list[Finding] = []

    agent_node_id = f"agent_{agent_name.lower().replace(' ','_')}"

    # ── Identity node ─────────────────────────────────────────────────────────
    ident = identity or {}
    ident_type = ident.get("type", "unknown")
    ident_scoped = ident.get("scoped", False)
    ident_name = ident.get("name", "Unknown identity")

    identity_defined = bool(identity and ident.get("name"))
    nodes.append(IdentityNode(
        id="identity",
        category="identity",
        label=f"Identity: {ident_name} [{ident_type}]",
        access_level="admin" if ident_type in ("service_account", "root") else "read",
        scoped=ident_scoped,
        details=ident,
        risk_notes=([] if identity_defined else ["No identity configured — agent runs without explicit identity"]),
    ))
    relationships.append(AccessRelationship("identity", agent_node_id, "authenticates_as", "config", False))

    if not identity_defined:
        findings.append(Finding(
            id="ID-NO-IDENTITY",
            title="Agent has no explicit identity configured",
            severity=Severity.HIGH, confidence=ConfidenceLevel.MEDIUM,
            scanner="identity_graph",
            explanation="No identity (service account, API key, OAuth token) is explicitly configured. "
                        "The agent likely inherits ambient credentials from the host environment, "
                        "which are often over-privileged.",
            impact="Agent may have unintended permissions inherited from the deployment environment.",
            remediation="Create a dedicated, minimal-permission service account or API key for this agent. "
                        "Never rely on ambient environment credentials.",
            evidence=[Evidence("agent_config", "identity", None, "No identity section found")],
            mitre_atlas=["AML.T0048"],
        ))

    # ── Capability nodes ──────────────────────────────────────────────────────
    for cap in capabilities:
        if cap not in CAPABILITY_CATEGORIES:
            continue
        cat, label, access, scoped_by_default = CAPABILITY_CATEGORIES[cap]
        risk_notes = []
        if not scoped_by_default:
            risk_notes.append(f"No inherent scoping — requires explicit restriction")

        node = IdentityNode(
            id=f"cap_{cap}",
            category=cat,
            label=label,
            access_level=access,
            scoped=False,   # assume unscoped unless config says otherwise
            details={"capability": cap},
            risk_notes=risk_notes,
        )
        nodes.append(node)
        relationships.append(AccessRelationship(
            agent_node_id, f"cap_{cap}", access, "tool", False
        ))

    # ── Memory node ───────────────────────────────────────────────────────────
    mem = memory_config or {}
    if mem or "memory_read" in capabilities or "memory_write" in capabilities:
        persistent = mem.get("persistent", True)
        mem_type = mem.get("type", "unknown")
        nodes.append(IdentityNode(
            id="memory",
            category="memory",
            label=f"Agent Memory [{mem_type}] ({'persistent' if persistent else 'session'})",
            access_level="write" if "memory_write" in capabilities else "read",
            scoped=bool(mem.get("namespace") or mem.get("scope")),
            details=mem,
            risk_notes=(["Persistent memory can accumulate sensitive data across sessions"] if persistent else []),
        ))
        relationships.append(AccessRelationship(agent_node_id, "memory", "read/write", "config", False))

    # ── Vector DB / RAG node ──────────────────────────────────────────────────
    if "vector_db" in capabilities or mem.get("type") in ("vectorstore", "pinecone", "weaviate", "chromadb"):
        nodes.append(IdentityNode(
            id="vectordb",
            category="vectordb",
            label=f"Vector DB / RAG [{mem.get('provider','unknown')}]",
            access_level="read",
            scoped=bool(mem.get("allowed_collections")),
            details={"provider": mem.get("provider", "unknown"),
                     "collections": mem.get("allowed_collections", ["*"])},
            risk_notes=(
                [] if mem.get("allowed_collections")
                else ["No collection scoping — agent can read entire vector store"]
            ),
        ))
        relationships.append(AccessRelationship(agent_node_id, "vectordb", "read", "config", False))

    # ── LLM node ─────────────────────────────────────────────────────────────
    nodes.append(IdentityNode(
        id="llm",
        category="llm",
        label="Large Language Model",
        access_level="write",
        scoped=False,
        details={},
        risk_notes=["LLM is the core reasoning component — all prompt injections target this"],
    ))
    relationships.append(AccessRelationship(agent_node_id, "llm", "invokes", "config", False))

    # ── Cloud node ────────────────────────────────────────────────────────────
    cloud = cloud_config or {}
    if cloud or "cloud_api" in capabilities:
        provider = cloud.get("provider", "unknown")
        iam_scoped = bool(cloud.get("iam_role") and cloud.get("scoped"))
        nodes.append(IdentityNode(
            id="cloud",
            category="cloud",
            label=f"Cloud APIs [{provider}]",
            access_level="admin" if not iam_scoped else "read",
            scoped=iam_scoped,
            details=cloud,
            risk_notes=([] if iam_scoped else [f"No IAM scoping for {provider} access — may have broad permissions"]),
        ))
        relationships.append(AccessRelationship(agent_node_id, "cloud", "calls", "tool", False))

        if not iam_scoped:
            findings.append(Finding(
                id="ID-CLOUD-UNSCOPED",
                title=f"Cloud API access is not IAM-scoped",
                severity=Severity.HIGH, confidence=ConfidenceLevel.MEDIUM,
                scanner="identity_graph",
                explanation=f"The agent has access to {provider} cloud APIs without explicit IAM role scoping. "
                            "This means the agent inherits the full permissions of its deployment environment.",
                impact="Agent may perform privileged cloud operations beyond its task scope.",
                remediation=f"Create a dedicated {provider} IAM role for this agent with only the permissions "
                            "it actually needs. Apply least-privilege principles.",
                evidence=[Evidence("cloud_config", "iam_role", cloud.get("iam_role"), "No scoped IAM role")],
                mitre_atlas=["AML.T0048"],
            ))

    # ── Network policy node ───────────────────────────────────────────────────
    net = network_policy or {}
    if "network_egress" in capabilities or "email_send" in capabilities:
        has_allowlist = bool(net.get("allowlist"))
        blocks_private = net.get("block_private_ips", False)
        nodes.append(IdentityNode(
            id="network",
            category="network",
            label="External Network / Internet",
            access_level="write",
            scoped=has_allowlist,
            details=net,
            risk_notes=(
                [] if has_allowlist else ["No domain allowlist — can reach any internet destination"]
            ) + (
                [] if blocks_private else ["Private IP ranges not blocked — SSRF possible"]
            ),
        ))
        relationships.append(AccessRelationship(agent_node_id, "network", "egress", "tool", False))

        if not has_allowlist:
            findings.append(Finding(
                id="ID-NET-NO-ALLOWLIST",
                title="No network egress allowlist — agent can reach any internet host",
                severity=Severity.HIGH, confidence=ConfidenceLevel.HIGH,
                scanner="identity_graph",
                explanation="The agent has outbound network access with no domain allowlist. "
                            "This enables data exfiltration to any internet destination.",
                impact="Unrestricted exfiltration path available to attacker-injected instructions.",
                remediation="Implement a network egress allowlist. Block all destinations not "
                            "explicitly required. Block private IP ranges (SSRF prevention).",
                evidence=[Evidence("network_policy", "allowlist", None, "No allowlist configured")],
                mitre_atlas=["AML.T0040"],
            ))

    # ── Compute effective permissions ─────────────────────────────────────────
    effective_perms = []
    cap_to_human = {
        "shell_exec": "Execute OS commands", "code_execution": "Execute arbitrary code",
        "secret_access": "Read secrets/credentials", "cloud_api": "Call cloud APIs",
        "database": "Query/modify databases", "file_write": "Write files",
        "file_read": "Read files", "network_egress": "Make internet requests",
        "email_send": "Send emails", "memory_write": "Write to persistent memory",
        "memory_read": "Read agent memory", "vector_db": "Read vector store/RAG",
    }
    for cap in capabilities:
        effective_perms.append(cap_to_human.get(cap, cap))

    # ── Risk score ────────────────────────────────────────────────────────────
    risk_score = min(sum(CAPABILITY_RISK.get(c, 2) for c in capabilities), 100)

    # ── Over-privilege finding ────────────────────────────────────────────────
    high_risk_caps = [c for c in capabilities if CAPABILITY_RISK.get(c, 0) >= 25]
    if len(high_risk_caps) >= 3:
        findings.append(Finding(
            id="ID-OVER-PRIVILEGED",
            title=f"Agent is over-privileged: {len(high_risk_caps)} high-risk capabilities",
            severity=Severity.HIGH, confidence=ConfidenceLevel.HIGH,
            scanner="identity_graph",
            explanation=(
                f"This agent has {len(high_risk_caps)} high-risk capabilities simultaneously: "
                f"{', '.join(high_risk_caps)}. Each capability is potentially justifiable alone, "
                "but together they form a complete attack surface — any compromise gives an attacker "
                "multiple avenues to cause damage."
            ),
            impact="Complete host and data compromise possible from a single prompt injection.",
            remediation=(
                "Apply principle of least privilege: separate high-risk capabilities into "
                "dedicated agents with narrow scopes. A search agent should not have shell access."
            ),
            evidence=[Evidence("capabilities", "high_risk", high_risk_caps,
                               f"{len(high_risk_caps)} capabilities each scoring ≥25 risk points")],
            mitre_atlas=["AML.T0048"],
        ))

    return AgentIdentityGraph(
        agent_id=agent_node_id,
        agent_name=agent_name,
        nodes=nodes,
        relationships=relationships,
        findings=findings,
        can_access_internet="network_egress" in capabilities or "email_send" in capabilities,
        can_access_secrets="secret_access" in capabilities,
        can_execute_code="shell_exec" in capabilities or "code_execution" in capabilities,
        can_write_filesystem="file_write" in capabilities,
        can_access_cloud="cloud_api" in capabilities,
        can_access_database="database" in capabilities,
        can_access_email="email_send" in capabilities,
        has_persistent_memory=bool(mem.get("persistent") or "memory_write" in capabilities),
        identity_defined=identity_defined,
        permissions_scoped=bool(net.get("allowlist") and cloud.get("iam_role")),
        effective_permissions=effective_perms,
        risk_score=risk_score,
    )


def identity_graph_from_scan(result: ScanResult, agent_name: str = "") -> AgentIdentityGraph:
    """Build identity graph directly from a ScanResult."""
    caps = result.metadata.get("capabilities_detected", [])
    name = agent_name or result.target.split("/")[-1].replace(".yaml","").replace(".json","")
    return build_identity_graph(agent_name=name, capabilities=caps)
