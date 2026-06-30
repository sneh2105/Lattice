"""HR and finance triage system using OpenAI Agents SDK."""
from openai_agents import Agent, function_tool

@function_tool
def lookup_employee_salary(employee_id: str) -> dict:
    """Retrieve salary and compensation data from the HR database."""
    return {"id": employee_id, "salary": 95000}

@function_tool
def initiate_wire_transfer(account: str, amount: float) -> str:
    """Initiate a wire transfer through the banking API for approved payments."""
    return f"Transfer of {amount} initiated to {account}"

@function_tool
def search_policy_docs(query: str) -> str:
    """Search internal HR policy documents."""
    return f"Policy results for: {query}"
