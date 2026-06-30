"""
Graph Node and Edge definitions for the AI Attack Graph Engine.

Every entity in the agent ecosystem is a node.
Every relationship or data flow is a directed edge.

Node types:
  ENTRY_POINT   — attacker-controlled inputs (user prompt, tool response, env var)
  TOOL          — agent tool / MCP tool
  RESOURCE      — data stores, secrets, files, databases
  NETWORK       — external network destinations
  AGENT         — the agent itself (trust boundary)
  MCP_SERVER    — an MCP server (trust boundary)
  PROCESS       — OS process / code execution context
  CROWN_JEWEL   — high-value targets (credentials, PII, financial data)

Edge types:
  EXECUTES      — tool can execute code/commands
  READS         — tool can read from resource
  WRITES        — tool can write to resource
  CALLS         — agent calls tool / tool calls API
  EXFILTRATES   — data can leave the trust boundary
  ESCALATES     — enables privilege escalation
  INJECTS       — prompt injection path
  DEPENDS_ON    — supply chain dependency
  TRUSTS        — explicit trust relationship
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class NodeType(str, Enum):
    ENTRY_POINT = "entry_point"
    TOOL        = "tool"
    RESOURCE    = "resource"
    NETWORK     = "network"
    AGENT       = "agent"
    MCP_SERVER  = "mcp_server"
    PROCESS     = "process"
    CROWN_JEWEL = "crown_jewel"


class EdgeType(str, Enum):
    EXECUTES   = "executes"
    READS      = "reads"
    WRITES     = "writes"
    CALLS      = "calls"
    EXFILTRATES = "exfiltrates"
    ESCALATES  = "escalates"
    INJECTS    = "injects"
    DEPENDS_ON = "depends_on"
    TRUSTS     = "trusts"


# Crown jewel value weights — used for blast radius scoring
CROWN_JEWEL_VALUE = {
    "aws_credentials":      100,
    "cloud_credentials":    100,
    "api_keys":             90,
    "database_contents":    85,
    "pii_data":             85,
    "financial_data":       90,
    "source_code":          70,
    "config_files":         65,
    "log_files":            40,
    "filesystem":           50,
    "external_network":     60,
    "shell_access":         95,
}


@dataclass
class Node:
    id: str
    type: NodeType
    label: str
    properties: dict[str, Any] = field(default_factory=dict)
    # Risk signals
    attacker_controlled: bool = False   # can attacker influence this node's value?
    is_crown_jewel: bool = False        # is this a high-value target?
    crown_jewel_value: int = 0          # 0-100, used for blast radius
    trust_boundary: bool = False        # does this node define a trust boundary?

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        return isinstance(other, Node) and self.id == other.id


@dataclass
class Edge:
    src: str    # Node ID
    dst: str    # Node ID
    type: EdgeType
    label: str = ""
    properties: dict[str, Any] = field(default_factory=dict)
    # Confidence that this edge exists
    confidence: float = 1.0   # 0.0 – 1.0
    # MITRE ATLAS technique this edge represents
    mitre: list[str] = field(default_factory=list)

    def __hash__(self):
        return hash((self.src, self.dst, self.type))


# ── Predefined nodes that always exist in the graph ─────────────────────────

ATTACKER_ENTRY_NODES: dict[str, Node] = {
    "user_prompt": Node(
        id="user_prompt",
        type=NodeType.ENTRY_POINT,
        label="User Prompt",
        attacker_controlled=True,
        properties={"description": "User-supplied text input to the agent"},
    ),
    "tool_response": Node(
        id="tool_response",
        type=NodeType.ENTRY_POINT,
        label="Tool Response (Indirect Injection)",
        attacker_controlled=True,
        properties={"description": "Content returned by a tool — attacker may control via MITM or malicious data"},
    ),
    "rag_context": Node(
        id="rag_context",
        type=NodeType.ENTRY_POINT,
        label="RAG Context / Retrieved Documents",
        attacker_controlled=True,
        properties={"description": "Documents retrieved from vector store — may contain injected instructions"},
    ),
    "env_vars": Node(
        id="env_vars",
        type=NodeType.ENTRY_POINT,
        label="Environment Variables",
        attacker_controlled=False,
        properties={"description": "Process environment — may contain secrets"},
    ),
}

CROWN_JEWEL_NODES: dict[str, Node] = {
    "aws_credentials": Node(
        id="aws_credentials", type=NodeType.CROWN_JEWEL,
        label="AWS / Cloud Credentials", is_crown_jewel=True,
        crown_jewel_value=CROWN_JEWEL_VALUE["aws_credentials"],
        properties={"impact": "Full cloud account takeover"},
    ),
    "api_keys": Node(
        id="api_keys", type=NodeType.CROWN_JEWEL,
        label="API Keys / Tokens", is_crown_jewel=True,
        crown_jewel_value=CROWN_JEWEL_VALUE["api_keys"],
        properties={"impact": "Service account compromise"},
    ),
    "database_contents": Node(
        id="database_contents", type=NodeType.CROWN_JEWEL,
        label="Database Contents (PII / Financial)", is_crown_jewel=True,
        crown_jewel_value=CROWN_JEWEL_VALUE["database_contents"],
        properties={"impact": "Mass data exfiltration"},
    ),
    "external_network": Node(
        id="external_network", type=NodeType.NETWORK,
        label="External Network / Internet", is_crown_jewel=True,
        crown_jewel_value=CROWN_JEWEL_VALUE["external_network"],
        properties={"impact": "Data exfiltration, C2 communication"},
    ),
    "shell_process": Node(
        id="shell_process", type=NodeType.PROCESS,
        label="OS Shell / Command Execution", is_crown_jewel=True,
        crown_jewel_value=CROWN_JEWEL_VALUE["shell_access"],
        properties={"impact": "Arbitrary code execution, persistence, lateral movement"},
    ),
    "filesystem": Node(
        id="filesystem", type=NodeType.RESOURCE,
        label="Host Filesystem", is_crown_jewel=False,
        crown_jewel_value=CROWN_JEWEL_VALUE["filesystem"],
        properties={"impact": "File read/write, config tampering"},
    ),
    "pii_store": Node(
        id="pii_store", type=NodeType.CROWN_JEWEL,
        label="PII Data Store", is_crown_jewel=True,
        crown_jewel_value=CROWN_JEWEL_VALUE["pii_data"],
        properties={"impact": "DPDP / GDPR breach, regulatory penalty"},
    ),
}
