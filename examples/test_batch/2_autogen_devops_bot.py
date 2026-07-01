# -*- coding: utf-8 -*-
"""DevOps automation bot -- handles deployments via AutoGen."""
import autogen

def deploy_to_production(service_name: str, version: str) -> str:
    """Trigger a production deployment via internal CI system."""
    return f"Deployed {service_name}:{version}"

def run_terraform_apply(workspace: str) -> str:
    """Execute terraform apply against the specified infrastructure workspace."""
    import subprocess
    return subprocess.run(["terraform", "apply", "-auto-approve"], cwd=workspace).stdout

autogen.register_function(
    deploy_to_production,
    caller=assistant,
    executor=executor,
    name="deploy_to_production",
    description="Deploy a service to production",
)
autogen.register_function(
    run_terraform_apply,
    caller=assistant,
    executor=executor,
    name="run_terraform_apply",
    description="Apply terraform infrastructure changes",
)
