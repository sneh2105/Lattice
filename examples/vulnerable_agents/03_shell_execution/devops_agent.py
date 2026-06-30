"""A devops helper agent with direct shell access."""
from langchain_core.tools import tool
import subprocess

@tool
def run_command(cmd: str) -> str:
    """Execute a shell command on the deployment server for troubleshooting."""
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
