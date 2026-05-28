#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# OnionClaw v2.3.0 — CrewAI Integration Example
# ============================================
# Demonstrates using SICRY as a dark web research tool for CrewAI multi-agent workflows.

"""
Example: Multi-agent dark web investigation using SICRY + CrewAI.

Agents:
  - Researcher: Executes dark web searches via SICRY
  - Analyzer: Interprets results, extracts intelligence
  - Reporter: Compiles findings into structured output

Usage:
  pip install crewai requests beautifulsoup4 python-dotenv stem
  export OPENAI_API_KEY=...
  python examples_crewai.py
"""

from crewai import Agent, Task, Crew
import sicry

# ─────────────────────────────────────────────────────────────────
# AGENTS
# ─────────────────────────────────────────────────────────────────

researcher_agent = Agent(
    role="Dark Web Researcher",
    goal="Search the Tor network for relevant information using SICRY",
    backstory="You are a cybercrime threat intelligence expert. You find relevant\
 dark web marketplaces, leaked data sources, and threat actor forums.",
    tools=[
        # SICRY tools (wrapped as CrewAI tools)
    ],
    allow_code_execution=True,
)

analyzer_agent = Agent(
    role="Intelligence Analyst",
    goal="Analyze dark web search results and extract actionable intelligence",
    backstory="You excel at identifying patterns, extracting IOCs (indicators of compromise),\
 and ranking threats by severity. You think critically about data quality.",
    tools=[],
    allow_code_execution=True,
)

reporter_agent = Agent(
    role="Intelligence Report Generator",
    goal="Compile findings into a structured, executive-ready threat intel report",
    backstory="You write clear, concise threat intelligence reports suitable for CISO\
 and SOC contexts. You use MITRE ATT&CK frameworks and evidence-based analysis.",
    tools=[],
    allow_code_execution=True,
)

# ─────────────────────────────────────────────────────────────────
# TASKS
# ─────────────────────────────────────────────────────────────────

def create_research_task(query: str) -> Task:
    """Create a research task that executes a SICRY dark web search."""
    return Task(
        description=f"Search the Tor network for: {query}\n\n\
Use SICRY to locate 15-20 relevant results from dark web search engines.\
 Return raw results including title, URL, engine source, and confidence score.",
        agent=researcher_agent,
        expected_output="List of 15-20 dark web search results with metadata",
    )


def create_analysis_task() -> Task:
    """Create an analysis task that interprets search results."""
    return Task(
        description="Analyze the search results from the previous researcher task.\n\n\
1. Identify the most relevant and high-confidence results\n\
2. Extract intelligence artifacts (IOCs, actor names, techniques, etc.)\n\
3. Cross-reference with known threat actor profiles\n\
4. Rate the findings by severity (critical, high, medium, low)\n\
5. Flag any immediate actionable intelligence",
        agent=analyzer_agent,
        expected_output="Categorized intelligence findings with severity ratings",
    )


def create_report_task() -> Task:
    """Create a report generation task."""
    return Task(
        description="Compile the intelligence analysis into a professional threat intel report.\n\n\
Format:\n\
1. Executive Summary (3-5 sentences)\n\
2. Search Query & Scope\n\
3. Key Findings (ordered by severity)\n\
4. Indicators of Compromise (IOCs)\n\
5. Threat Actor Profile (if applicable)\n\
6. Recommended Actions\n\
7. Sources & Links\n\n\
Keep language clear and evidence-based.",
        agent=reporter_agent,
        expected_output="Professional threat intelligence report (markdown or structured format)",
    )


# ─────────────────────────────────────────────────────────────────
# MAIN WORKFLOW
# ─────────────────────────────────────────────────────────────────

def run_dark_web_investigation(query: str) -> str:
    """Execute a full dark web investigation workflow.
    
    Args:
        query: Investigation topic (e.g., "leaked AWS credentials")
    
    Returns:
        Structured threat intelligence report
    """
    # Verify Tor connectivity
    if not sicry.check_tor():
        return "ERROR: Tor is not running or unreachable. Start Tor and try again."
    
    # Create tasks for this investigation
    research_task = create_research_task(query)
    analysis_task = create_analysis_task()
    report_task = create_report_task()
    
    # Create crew
    crew = Crew(
        agents=[researcher_agent, analyzer_agent, reporter_agent],
        tasks=[research_task, analysis_task, report_task],
        verbose=True,
    )
    
    # Execute workflow
    result = crew.kickoff()
    return result


if __name__ == "__main__":
    # Example: Investigate leaked enterprise credentials
    investigation_query = "enterprise credentials leaked marketplace"
    
    print("=" * 70)
    print("SICRY + CrewAI Dark Web Investigation")
    print("=" * 70)
    print(f"\nQuery: {investigation_query}\n")
    
    report = run_dark_web_investigation(investigation_query)
    print("\n" + "=" * 70)
    print("INVESTIGATION REPORT")
    print("=" * 70)
    print(report)
