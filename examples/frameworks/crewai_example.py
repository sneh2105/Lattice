"""
AgentScan + CrewAI
==================
Monitors a multi-agent CrewAI crew for security events in real time.

Install:
    pip install crewai agentscan

Run:
    python crewai_example.py
"""

from crewai import Agent, Task, Crew, Process
from crewai.tools import BaseTool
from agentscan.runtime.integrations import AgentScanCrewCallback
from agentscan.runtime.integrations.monitor import agentscan_trace

# ── Example tools ──────────────────────────────────────────────────────────────

class WebSearchTool(BaseTool):
    name: str = "web_search"
    description: str = "Search the web for information"

    def _run(self, query: str) -> str:
        # In production: real web search
        return f"Search results for: {query}"


class ReportWriterTool(BaseTool):
    name: str = "write_report"
    description: str = "Write a formatted research report"

    def _run(self, content: str) -> str:
        return f"Report written: {content[:100]}..."


# ── Agents ─────────────────────────────────────────────────────────────────────

researcher = Agent(
    role="Senior Research Analyst",
    goal="Find accurate, up-to-date information on the given topic",
    backstory="Expert researcher with 10 years of experience in market analysis",
    tools=[WebSearchTool()],
    verbose=True,
)

writer = Agent(
    role="Technical Writer",
    goal="Produce clear, concise reports from research findings",
    backstory="Professional writer specialising in technical and business content",
    tools=[ReportWriterTool()],
    verbose=True,
)

# ── AgentScan integration ──────────────────────────────────────────────────────

def run_with_monitoring(topic: str) -> str:
    """Run a CrewAI research crew with full AgentScan monitoring."""

    # Option 1: callback (recommended for CrewAI)
    callback = AgentScanCrewCallback(
        agent_name="research-crew",
        console_alerts=True,                    # print alerts immediately
        report_path="crewai_security_report.json",  # write JSON report on completion
    )

    # Define tasks
    research_task = Task(
        description=f"Research the following topic thoroughly: {topic}",
        agent=researcher,
        expected_output="A comprehensive research summary with key findings",
    )

    write_task = Task(
        description="Write a professional report based on the research findings",
        agent=writer,
        expected_output="A structured report with executive summary, findings, and recommendations",
    )

    # Assemble crew with AgentScan callback
    crew = Crew(
        agents=[researcher, writer],
        tasks=[research_task, write_task],
        process=Process.sequential,
        callbacks=[callback],
        verbose=True,
    )

    # Run the crew
    result = crew.kickoff()

    # Get security report
    report = callback.flush()

    print(f"\n{'='*60}")
    print(f"AgentScan Security Summary")
    print(f"{'='*60}")
    print(f"Events monitored : {report.event_count}")
    print(f"Critical findings: {sum(1 for f in report.findings if f.severity.value == 'CRITICAL')}")
    print(f"Attack paths     : {len(report.attack_paths)}")

    if report.findings:
        print(f"\nFindings:")
        for f in report.findings:
            print(f"  [{f.severity.value}] {f.title}")

    return str(result)


# ── Option 2: context manager (cleaner for scripts) ────────────────────────────

def run_with_trace(topic: str) -> str:
    """Alternative: use agentscan_trace context manager."""
    with agentscan_trace(
        agent_name="research-crew",
        console_alerts=True,
        report_path="crewai_trace_report.json",
    ) as monitor:
        callback = AgentScanCrewCallback(monitor=monitor)

        task = Task(
            description=f"Research: {topic}",
            agent=researcher,
            expected_output="Research summary",
        )
        crew = Crew(agents=[researcher], tasks=[task], callbacks=[callback])
        result = crew.kickoff()

    return str(result)


if __name__ == "__main__":
    result = run_with_monitoring("AI security risks in financial services 2025")
    print(f"\nResult: {result[:200]}...")
