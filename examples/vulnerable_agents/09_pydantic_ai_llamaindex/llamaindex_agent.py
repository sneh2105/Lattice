# -*- coding: utf-8 -*-
"""LlamaIndex agent -- document research assistant."""
from llama_index.core.tools import FunctionTool
from llama_index.core.agent import OpenAIAgent

def query_internal_db(sql: str) -> str:
    """Execute a SQL query against the internal Postgres knowledge database."""
    return f"results for {sql}"

def fetch_aws_secret(name: str) -> str:
    """Retrieve a secret from AWS Secrets Manager for service authentication."""
    return "retrieved"

db_tool = FunctionTool.from_defaults(query_internal_db)
secret_tool = FunctionTool.from_defaults(fetch_aws_secret)

agent = OpenAIAgent.from_tools(tools=[db_tool, secret_tool], verbose=True)
