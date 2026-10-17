"""Agent registry: maps agent names to classes and provides run_agent().

All 7 agents are registered:
  onboarding, optimizer, discovery, tuning, triage, log_alert, remediation (stub)
"""
from __future__ import annotations

from ..db import Database
from .base import Agent, AgentResult

# Lazy imports to avoid circular dependencies at module load time
AGENTS: dict[str, type[Agent]] = {}


def _register_all() -> None:
    """Lazily populate the registry. Called once on first access."""
    if AGENTS:
        return

    from .discovery import RuleDiscoveryAgent
    from .log_alert import LogAlertAgent
    from .onboarding import OnboardingAgent
    from .optimizer import IngestionOptimizerAgent
    from .triage import TriageAgent
    from .tuning import TuningAgent

    AGENTS["triage"] = TriageAgent
    AGENTS["log_alert"] = LogAlertAgent
    AGENTS["onboarding"] = OnboardingAgent
    AGENTS["optimizer"] = IngestionOptimizerAgent
    AGENTS["discovery"] = RuleDiscoveryAgent
    AGENTS["tuning"] = TuningAgent


def run_agent(db: Database, name: str, **kw) -> AgentResult:
    """Create an agent instance and run it with the given keyword arguments.

    Args:
        db: Database instance
        name: agent name (key in AGENTS dict)
        **kw: passed to Agent.run() and Agent.execute()

    Returns:
        AgentResult with status, summary, output

    Raises:
        ValueError: unknown agent name
    """
    _register_all()
    cls = AGENTS.get(name)
    if cls is None:
        raise ValueError(f"Unknown agent: {name}. Available: {sorted(AGENTS)}")

    agent = cls(db)
    return agent.run(**kw)


def list_agents() -> list[str]:
    """Return sorted list of registered agent names."""
    _register_all()
    return sorted(AGENTS.keys())
