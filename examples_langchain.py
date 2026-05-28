#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# OnionClaw v2.3.0 — LangChain Integration Example
# ================================================
# Demonstrates using SICRY as a LangChain tool for dark web research.

"""
Example: LangChain agent with SICRY for dark web OSINT.

LangChain Integrations:
  - Tool: SICRY search() wrapper
  - Memory: Conversation history from investigations
  - Chain: ReAct (Reasoning + Action) loop for multi-step investigations

Usage:
  pip install langchain langchain-openai requests beautifulsoup4 python-dotenv stem
  export OPENAI_API_KEY=...
  python examples_langchain.py
"""

from langchain.tools import Tool
from langchain.agents import initialize_agent, AgentType
from langchain_openai import ChatOpenAI
from langchain.memory import ConversationBufferMemory
import sicry
import json


# ─────────────────────────────────────────────────────────────────
# LANGCHAIN TOOLS (wrapping SICRY)
# ─────────────────────────────────────────────────────────────────

def search_dark_web(query: str, max_results: int = 10, mode: str = "threat_intel") -> str:
    """Search the Tor network using SICRY.
    
    Args:
        query: Search query (natural language)
        max_results: Max results to return (1-50)
        mode: Investigation mode (threat_intel | ransomware | personal_identity | corporate)
    
    Returns:
        JSON string of search results
    """
    results = sicry.search(
        query=query,
        max_results=min(max_results, 50),
        mode=mode if mode in ["threat_intel", "ransomware", "personal_identity", "corporate"] else None
    )
    
    # Format for LLM
    formatted = []
    for r in results:
        formatted.append({
            "title": r.get("title", "N/A")[:80],
            "url": r.get("url", "N/A"),
            "engine": r.get("engine", "unknown"),
            "confidence": round(r.get("confidence", 0.0), 2),
        })
    
    return json.dumps(formatted, indent=2)


def analyze_results(query: str, results_json: str) -> str:
    """Analyze dark web search results using SICRY's LLM analysis.
    
    Args:
        query: Original search query
        results_json: JSON string of results from search_dark_web()
    
    Returns:
        LLM-powered analysis and insights
    """
    try:
        results = json.loads(results_json)
    except json.JSONDecodeError:
        return "ERROR: Could not parse results. Ensure results_json is valid JSON."
    
    if not results:
        return "No results to analyze."
    
    # Format for SICRY LLM analysis
    result_text = "\n".join(
        f"- {r['title']} ({r['engine']}) - {r['url']}"
        for r in results[:10]
    )
    
    system_prompt = "You are a dark web threat intelligence expert.\
 Analyze these search results and extract:\n\
1. Key findings\n\
2. Threat actors or groups mentioned\n\
3. Recommended next steps"
    
    prompt = f"Query: {query}\n\nResults:\n{result_text}"
    
    analysis = sicry._call_llm("openai", system_prompt, prompt)
    return analysis


def check_engine_health() -> str:
    """Check the health/latency of all dark web search engines."""
    health = sicry.check_search_engines()
    
    online = [e for e in health if e.get("status") == "up"]
    offline = [e for e in health if e.get("status") != "up"]
    
    summary = f"Search Engines Online: {len(online)}/{len(health)}\n\n"
    summary += "Online Engines:\n"
    for e in online:
        summary += f"  - {e['name']}: {e.get('latency_ms', '?')}ms\n"
    
    if offline:
        summary += f"\nOffline Engines ({len(offline)}):\n"
        for e in offline:
            summary += f"  - {e['name']}: {e.get('error', 'unknown error')}\n"
    
    return summary


# ─────────────────────────────────────────────────────────────────
# LANGCHAIN AGENT
# ─────────────────────────────────────────────────────────────────

def create_dark_web_agent():
    """Create a LangChain ReAct agent for dark web investigations."""
    
    # Verify Tor is running
    if not sicry.check_tor():
        raise RuntimeError("Tor is not running. Start Tor and try again.")
    
    # Initialize LLM
    llm = ChatOpenAI(
        model="gpt-4",
        temperature=0.0,  # Deterministic for OSINT
        max_tokens=2048,
    )
    
    # Define tools
    tools = [
        Tool(
            name="search_dark_web",
            func=search_dark_web,
            description="Search the Tor network for information.\
 Useful for finding dark web marketplaces, leaked data, threat actors, etc.\
 Input: search query (string). Example: 'stolen credit cards marketplace'",
        ),
        Tool(
            name="analyze_results",
            func=analyze_results,
            description="Analyze dark web search results using AI.\
 Extracts IOCs, threat actors, and actionable intelligence.\
 Input: original query (string) and JSON results from search_dark_web.",
        ),
        Tool(
            name="check_engine_health",
            func=check_engine_health,
            description="Check which dark web search engines are online.\
 Useful before running searches to understand coverage.",
        ),
    ]
    
    # Create memory for conversation
    memory = ConversationBufferMemory(
        memory_key="chat_history",
        return_messages=True,
    )
    
    # Initialize agent
    agent = initialize_agent(
        tools=tools,
        llm=llm,
        agent=AgentType.OPENAI_FUNCTIONS,  # ReAct with tool use
        memory=memory,
        verbose=True,
        max_iterations=10,
        early_stopping_method="generate",
    )
    
    return agent


# ─────────────────────────────────────────────────────────────────
# EXAMPLE INVESTIGATIONS
# ─────────────────────────────────────────────────────────────────

def multi_step_investigation():
    """Example: Multi-step investigation using ReAct reasoning."""
    agent = create_dark_web_agent()
    
    # Example input that triggers multiple tools
    investigation_prompt = """
    I'm investigating a reported data breach of a financial services company.
    
    Please:
    1. Check that dark web search engines are online
    2. Search for recent leaks related to this sector
    3. Identify any threat actors claiming credit
    4. Recommend security actions
    """
    
    result = agent.run(investigation_prompt)
    return result


def threat_hunting_workflow():
    """Example: Threat hunting workflow using SICRY + LangChain."""
    agent = create_dark_web_agent()
    
    iocs_to_hunt = [
        "Conti ransomware C2",
        "LockBit affiliate forums",
        "BlackCat malware samples",
    ]
    
    for ioc in iocs_to_hunt:
        print(f"\n{'='*60}")
        print(f"Hunting: {ioc}")
        print('='*60)
        result = agent.run(f"Find information about {ioc} on the dark web.")
        print(result)


if __name__ == "__main__":
    print("OnionClaw + LangChain Dark Web Investigation Agent")
    print("=" * 60)
    
    # Run multi-step investigation
    result = multi_step_investigation()
    print("\n" + "=" * 60)
    print("INVESTIGATION RESULT:")
    print("=" * 60)
    print(result)
