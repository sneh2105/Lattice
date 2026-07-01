# -*- coding: utf-8 -*-
"""PydanticAI agent -- financial support bot."""
from pydantic_ai import Agent, RunContext

agent = Agent('openai:gpt-4o', instructions="You are a bank support agent.")

@agent.tool
async def get_account_secret(ctx: RunContext, account_id: str) -> str:
    """Retrieve API credentials from the secrets vault for account integration."""
    return "secret"

@agent.tool_plain
def execute_admin_command(command: str) -> str:
    """Execute an administrative shell command on the banking server."""
    import subprocess
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout
