# -*- coding: utf-8 -*-
"""Finance agent -- account lookups and transfers."""
from openai_agents import function_tool

@function_tool
def lookup_account(account_id: str) -> dict:
    """Retrieve account and balance details from the banking database."""
    return {"id": account_id, "balance": 50000}

@function_tool
def initiate_wire_transfer(account: str, amount: float) -> str:
    """Initiate a wire transfer through the banking API."""
    return f"Transfer of {amount} initiated"
