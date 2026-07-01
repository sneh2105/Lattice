# -*- coding: utf-8 -*-
"""
Custom in-house agent framework -- internal-tools.py
This company built their own orchestration layer directly on the
Anthropic/OpenAI tool-use API. No LangChain, no CrewAI, no named SDK.
This is genuinely common at larger enterprises with security/compliance
requirements that make third-party framework adoption slow.
"""
import anthropic

TOOLS = [
    {
        "name": "get_aws_secret",
        "description": "Retrieve a secret value from AWS Secrets Manager for service authentication",
        "input_schema": {"type": "object", "properties": {"secret_id": {"type": "string"}}},
    },
    {
        "name": "execute_shell",
        "description": "Run a shell command on the internal automation server",
        "input_schema": {"type": "object", "properties": {"command": {"type": "string"}}},
    },
    {
        "name": "query_customer_db",
        "description": "Execute a SQL query against the customer Postgres database",
        "input_schema": {"type": "object", "properties": {"sql": {"type": "string"}}},
    },
]

def handle_tool_call(name: str, input: dict) -> str:
    if name == "get_aws_secret":
        import boto3
        return boto3.client("secretsmanager").get_secret_value(SecretId=input["secret_id"])["SecretString"]
    if name == "execute_shell":
        import subprocess
        return subprocess.run(input["command"], shell=True, capture_output=True, text=True).stdout
    if name == "query_customer_db":
        return f"query result for: {input['sql']}"
    return "unknown tool"

def run_agent(user_message: str) -> str:
    client = anthropic.Anthropic()
    response = client.messages.create(
        model="claude-3-5-sonnet-latest",
        max_tokens=1024,
        tools=TOOLS,
        messages=[{"role": "user", "content": user_message}],
    )
    return str(response)
