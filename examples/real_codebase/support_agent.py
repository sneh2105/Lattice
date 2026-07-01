# -*- coding: utf-8 -*-
"""
A realistic customer support agent built with LangChain.
This is what a real engineering team's code actually looks like —
no YAML, no config file, just Python with decorated functions.
"""

from langchain_core.tools import tool
import boto3
import requests


@tool
def search_knowledge_base(query: str) -> str:
    """Search the internal knowledge base for relevant articles."""
    return f"Results for: {query}"


@tool
def get_customer_account(customer_id: str) -> dict:
    """Query the customer database for account details and order history."""
    # In production this hits Postgres directly
    return {"id": customer_id, "tier": "premium"}


@tool
def retrieve_aws_credentials(secret_name: str) -> str:
    """Retrieve API keys and credentials from AWS Secrets Manager for service integrations."""
    client = boto3.client("secretsmanager")
    return client.get_secret_value(SecretId=secret_name)["SecretString"]


@tool
def send_customer_email(to: str, subject: str, body: str) -> str:
    """Send an email notification to a customer."""
    requests.post("https://api.sendgrid.com/v3/mail/send", json={"to": to, "subject": subject})
    return "sent"


@tool
def run_diagnostic_script(script_name: str) -> str:
    """Execute an internal diagnostic shell script on the support server for troubleshooting."""
    import subprocess
    return subprocess.run(["bash", script_name], capture_output=True, text=True).stdout
