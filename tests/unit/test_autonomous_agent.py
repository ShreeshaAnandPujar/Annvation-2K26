"""
Unit Tests for Autonomous AI Threat Sentinel (Pygenic Arc / Team Rudranix)
"""

import pytest
from app.services.autonomous_agent import AutonomousAIAgent, SentinelMode, ThreatLevel
from app.services.threat_engine import (
    BehavioralThreatEngine,
    BehaviourCategory,
    EnforcementAction,
    ThreatVerdict,
)


def test_autonomous_agent_initial_state():
    agent = AutonomousAIAgent(enabled=True)
    assert agent.is_enabled() is True
    status = agent.get_status()
    assert status["mode"] == SentinelMode.ACTIVE.value
    assert status["enabled"] is True
    assert status["threat_level"] in ("NOMINAL", "ELEVATED", "CRITICAL")


def test_autonomous_agent_toggle():
    agent = AutonomousAIAgent(enabled=True)
    
    # Toggle OFF
    new_state = agent.toggle()
    assert new_state is False
    assert agent.is_enabled() is False
    assert agent.get_status()["mode"] == SentinelMode.STANDBY.value

    # Toggle ON explicitly
    new_state = agent.toggle(True)
    assert new_state is True
    assert agent.is_enabled() is True
    assert agent.get_status()["mode"] == SentinelMode.ACTIVE.value


def test_autonomous_agent_attack_auto_blocking():
    engine = BehavioralThreatEngine()
    agent = AutonomousAIAgent(enabled=True)
    agent.set_dependencies(threat_engine=engine)

    # Simulate Credential Stuffing Threat Verdict
    verdict = ThreatVerdict(
        risk_score=0.92,
        behaviour_category=BehaviourCategory.CREDENTIAL_STUFFING,
        action=EnforcementAction.SOFT_BLOCK,
        explanation="Dual-axis credential stuffing detected.",
        evidence={"reasons": ["Multiple auth failures"]},
    )

    # Process telemetry
    record = agent.process_telemetry(
        ip="192.168.64.99",
        client_id="kali_bot",
        path="/gateway/auth/login",
        verdict=verdict,
    )

    assert record is not None
    assert record.target_ip == "192.168.64.99"
    assert record.action_taken == "AUTONOMOUS_IP_BAN"
    assert "CRITICAL THREAT CONFIRMED" in record.verdict
    assert agent.total_autonomous_bans == 1

    # Verify IP is actively banned in threat engine
    is_blocked, cat, ttl = engine.local_store.is_blocked("192.168.64.99")
    assert is_blocked is True
    assert cat == BehaviourCategory.CREDENTIAL_STUFFING


def test_autonomous_agent_standby_mode_suppresses_auto_blocking():
    engine = BehavioralThreatEngine()
    agent = AutonomousAIAgent(enabled=False)  # STANDBY MODE
    agent.set_dependencies(threat_engine=engine)

    verdict = ThreatVerdict(
        risk_score=0.95,
        behaviour_category=BehaviourCategory.SCRAPING,
        action=EnforcementAction.SOFT_BLOCK,
        explanation="Timing entropy bot scraping.",
        evidence={"reasons": ["Low variance"]},
    )

    record = agent.process_telemetry(
        ip="192.168.64.100",
        client_id="kali_scraper",
        path="/gateway/products",
        verdict=verdict,
    )

    assert record is not None
    assert record.action_taken == "PASSIVE_ALERT"
    assert agent.total_autonomous_bans == 0

    # In standby mode, threat engine block was not autonomously triggered by agent
    is_blocked, _, _ = engine.local_store.is_blocked("192.168.64.100")
    assert is_blocked is False
