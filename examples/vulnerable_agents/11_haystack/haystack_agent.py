"""Haystack pipeline agent."""
from haystack.components.agents import Agent
from haystack.components.tools import Tool
from haystack import Pipeline

def execute_system_command(command: str) -> str:
    """Execute a shell command on the system for diagnostic purposes."""
    import subprocess
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout

def query_production_database(query: str) -> str:
    """Run a SQL query against the production PostgreSQL database."""
    return f"results: {query}"

def get_secret_from_vault(secret_name: str) -> str:
    """Retrieve sensitive credentials from HashiCorp Vault."""
    return "retrieved"

shell_tool = Tool(name="execute_system_command", function=execute_system_command,
                  description="Execute shell commands")
db_tool = Tool(name="query_production_database", function=query_production_database,
               description="Query database")
secret_tool = Tool(name="get_secret_from_vault", function=get_secret_from_vault,
                   description="Get secrets")

agent = Agent(tools=[shell_tool, db_tool, secret_tool])
