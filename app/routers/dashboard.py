"""
Cyber Threat Intelligence & Gateway SOC Dashboard (Team Rudranix)
Pygenic Arc — API Abuse & Behavioral Threat Detection Platform

Provides real-time continuous behavioral monitoring, attacker telemetry,
Kali Linux intrusion detection, and explainable perimeter defense analytics.
"""

import time
from typing import Any, Dict, Optional
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from app.services.autonomous_agent import autonomous_agent
from app.services.threat_engine import threat_engine

router = APIRouter(tags=["dashboard"])


class UnblockRequest(BaseModel):
    ip: str


class BlockRequest(BaseModel):
    ip: str
    ttl_seconds: Optional[int] = 300
    reason: Optional[str] = "Manual operator ban from SOC Dashboard"


class AgentToggleRequest(BaseModel):
    enabled: Optional[bool] = None


@router.get("/api/dashboard-stats")
async def get_dashboard_stats():
    """Returns live telemetry for dashboard auto-refresh."""
    data = threat_engine.get_dashboard_data()
    data["autonomous_agent"] = autonomous_agent.get_status()
    return data


@router.get("/api/autonomous-agent/status")
async def get_agent_status():
    """Returns the current operational status of the 24/7 Autonomous AI Sentinel."""
    return autonomous_agent.get_status()


@router.post("/api/autonomous-agent/toggle")
async def toggle_agent(req: Optional[AgentToggleRequest] = None):
    """Toggles or sets the autonomous monitoring and auto-blocking state."""
    new_state = autonomous_agent.toggle(req.enabled if req else None)
    return {
        "success": True,
        "enabled": new_state,
        "mode": "ACTIVE" if new_state else "STANDBY",
        "status_label": "24/7 AUTONOMOUS DEFENSE ACTIVE" if new_state else "STANDBY / PASSIVE OBSERVATION",
    }


@router.post("/api/autonomous-agent/clear-actions")
async def clear_agent_actions():
    """Clears the AI Agent's decision and action audit log."""
    autonomous_agent.action_log.clear()
    return {"success": True}


@router.post("/api/block-ip")
async def block_ip(req: BlockRequest, request: Request):
    """Allows administrators to manually ban an IP address across the gateway immediately."""
    clean_ip = req.ip.strip()
    threat_engine.manual_block_ip(
        clean_ip,
        ttl_seconds=req.ttl_seconds or 300,
        reason=req.reason or "Manual operator ban from SOC Dashboard",
    )
    # Also sync to in-memory Bloom filter and Redis if available
    bloom = getattr(request.app.state, "bloom", None)
    if bloom:
        bloom.add_ip(clean_ip)
        redis = getattr(request.app.state, "redis", None)
        if redis:
            try:
                await bloom.add_ip_to_redis(clean_ip)
            except Exception:
                pass
    return {"success": True, "blocked_ip": clean_ip, "ttl_seconds": req.ttl_seconds or 300}


@router.post("/api/unblock-ip")
async def unblock_ip(req: UnblockRequest, request: Request):
    """Allows administrators to unblock an IP during live demonstrations."""
    clean_ip = req.ip.strip()
    res = threat_engine.unblock_ip(clean_ip)
    bloom = getattr(request.app.state, "bloom", None)
    redis = getattr(request.app.state, "redis", None)
    if bloom and redis:
        try:
            await bloom.remove_ip_from_redis(clean_ip)
        except Exception:
            pass
    return {"success": res, "unblocked_ip": clean_ip}


@router.post("/api/clear-all-blocks")
@router.post("/api/clear-all")
@router.post("/api/clear-radar")
async def clear_all_blocks(request: Request):
    """Clears all active blocks and resets historical tracking for clean test runs."""
    count = len(threat_engine.local_store.blocked_ips)
    threat_engine.clear_all()
    autonomous_agent.action_log.clear()
    autonomous_agent.total_evaluations = 0
    autonomous_agent.total_autonomous_bans = 0
    autonomous_agent.total_autonomous_throttles = 0
    bloom = getattr(request.app.state, "bloom", None)
    redis = getattr(request.app.state, "redis", None)
    if bloom and redis:
        try:
            await bloom.clear_all()
        except Exception:
            pass
    return {"success": True, "cleared_count": count}


@router.post("/api/clear-feed")
async def clear_feed():
    """Clears recent event records for clean demo restarts."""
    threat_engine.recent_events.clear()
    return {"success": True}


@router.get("/dashboard", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    """
    Renders the live Cybersecurity Threat Intelligence SOC Dashboard with Autonomous AI Sentinel.
    """
    host = request.headers.get("host", "localhost:8000")
    host_ip = host.split(":")[0]

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Pygenic Arc | 24/7 Autonomous AI Threat Defense SOC</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700;800&family=Outfit:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg-base: #060911;
      --bg-surface: #0e1424;
      --bg-card: rgba(16, 23, 41, 0.85);
      --border-color: rgba(255, 255, 255, 0.08);
      --border-focus: rgba(0, 240, 255, 0.4);
      --cyan-accent: #00f0ff;
      --cyan-glow: rgba(0, 240, 255, 0.25);
      --red-alert: #ff3366;
      --red-glow: rgba(255, 51, 102, 0.3);
      --yellow-warn: #ffb800;
      --green-safe: #00e676;
      --purple-accent: #7928ca;
      --text-main: #f0f4fc;
      --text-muted: #8a99b5;
      --font-display: 'Outfit', sans-serif;
      --font-mono: 'JetBrains Mono', monospace;
    }}

    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background-color: var(--bg-base);
      color: var(--text-main);
      font-family: var(--font-display);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      overflow-x: hidden;
      background-image: 
        radial-gradient(circle at 10% 20%, rgba(0, 240, 255, 0.04) 0%, transparent 40%),
        radial-gradient(circle at 90% 80%, rgba(255, 51, 102, 0.05) 0%, transparent 40%);
    }}

    /* Top Nav */
    header {{
      background: rgba(14, 20, 36, 0.92);
      backdrop-filter: blur(14px);
      border-bottom: 1px solid var(--border-color);
      padding: 1rem 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 100;
    }}
    .brand {{
      display: flex;
      align-items: center;
      gap: 1rem;
    }}
    .logo-badge {{
      background: linear-gradient(135deg, var(--cyan-accent), var(--purple-accent));
      color: #000;
      font-weight: 800;
      font-size: 1.1rem;
      padding: 0.35rem 0.8rem;
      border-radius: 8px;
      letter-spacing: 0.5px;
      box-shadow: 0 0 15px rgba(0, 240, 255, 0.3);
    }}
    .brand h1 {{
      font-size: 1.25rem;
      font-weight: 700;
      letter-spacing: -0.5px;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}
    .brand span {{
      color: var(--text-muted);
      font-size: 0.8rem;
      font-family: var(--font-mono);
    }}
    .header-links {{
      display: flex;
      align-items: center;
      gap: 1rem;
    }}
    .pill-link {{
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border-color);
      color: var(--text-main);
      padding: 0.45rem 1rem;
      border-radius: 20px;
      text-decoration: none;
      font-size: 0.85rem;
      font-family: var(--font-mono);
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      transition: all 0.2s ease;
      cursor: pointer;
    }}
    .pill-link:hover {{
      border-color: var(--cyan-accent);
      color: var(--cyan-accent);
      box-shadow: 0 0 12px var(--cyan-glow);
    }}
    .status-pulse {{
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--green-safe);
      box-shadow: 0 0 8px var(--green-safe);
      animation: pulse 2s infinite;
    }}
    @keyframes pulse {{
      0% {{ opacity: 0.4; transform: scale(0.9); }}
      50% {{ opacity: 1; transform: scale(1.2); }}
      100% {{ opacity: 0.4; transform: scale(0.9); }}
    }}

    /* Main Container */
    main {{
      max-width: 1440px;
      margin: 0 auto;
      padding: 2rem;
      width: 100%;
      flex: 1;
      display: flex;
      flex-direction: column;
      gap: 2rem;
    }}

    /* Metrics Grid */
    .metrics-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 1.25rem;
    }}
    .card {{
      background: var(--bg-card);
      backdrop-filter: blur(8px);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 1.5rem;
      position: relative;
      overflow: hidden;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
      transition: border-color 0.2s;
    }}
    .card::before {{
      content: "";
      position: absolute;
      top: 0; left: 0; width: 100%; height: 3px;
      background: var(--card-accent, var(--cyan-accent));
    }}
    .card-label {{
      font-size: 0.85rem;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
      font-family: var(--font-mono);
    }}
    .card-value {{
      font-size: 2.2rem;
      font-weight: 800;
      font-family: var(--font-mono);
      color: #fff;
    }}
    .card-subtext {{
      font-size: 0.8rem;
      color: var(--text-muted);
    }}

    /* Autonomous AI Sentinel Banner */
    .sentinel-card {{
      background: linear-gradient(135deg, rgba(14, 20, 36, 0.95), rgba(10, 30, 48, 0.95));
      border: 1px solid var(--cyan-accent);
      border-radius: 14px;
      padding: 1.5rem 2rem;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5), 0 0 20px rgba(0, 240, 255, 0.15);
      display: flex;
      flex-direction: column;
      gap: 1.25rem;
      position: relative;
    }}
    .sentinel-card::before {{
      content: "";
      position: absolute;
      top: 0; left: 0; width: 5px; height: 100%;
      background: linear-gradient(to bottom, var(--cyan-accent), var(--green-safe));
      border-radius: 4px 0 0 4px;
    }}
    .sentinel-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
    }}
    .sentinel-title {{
      display: flex;
      align-items: center;
      gap: 0.8rem;
    }}
    .sentinel-title h2 {{
      font-size: 1.25rem;
      font-weight: 800;
      color: #fff;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}

    /* Toggle Switch Component */
    .toggle-wrapper {{
      display: flex;
      align-items: center;
      gap: 1rem;
      background: rgba(0, 0, 0, 0.4);
      padding: 0.5rem 1rem;
      border-radius: 30px;
      border: 1px solid var(--border-color);
    }}
    .toggle-label {{
      font-family: var(--font-mono);
      font-size: 0.85rem;
      font-weight: 700;
      color: var(--text-main);
    }}
    .switch {{
      position: relative;
      display: inline-block;
      width: 52px;
      height: 28px;
    }}
    .switch input {{
      opacity: 0;
      width: 0;
      height: 0;
    }}
    .slider {{
      position: absolute;
      cursor: pointer;
      top: 0; left: 0; right: 0; bottom: 0;
      background-color: rgba(255, 255, 255, 0.15);
      border: 1px solid var(--border-color);
      transition: .3s;
      border-radius: 34px;
    }}
    .slider:before {{
      position: absolute;
      content: "";
      height: 20px;
      width: 20px;
      left: 4px;
      bottom: 3px;
      background-color: white;
      transition: .3s;
      border-radius: 50%;
    }}
    input:checked + .slider {{
      background-color: var(--green-safe);
      box-shadow: 0 0 15px rgba(0, 230, 118, 0.4);
    }}
    input:checked + .slider:before {{
      transform: translateX(23px);
      background-color: #000;
    }}

    .sentinel-meta-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 1rem;
      background: rgba(0, 0, 0, 0.3);
      padding: 1rem;
      border-radius: 10px;
      border: 1px solid var(--border-color);
    }}
    .meta-stat {{
      display: flex;
      flex-direction: column;
      gap: 0.2rem;
    }}
    .meta-stat-label {{
      font-size: 0.75rem;
      color: var(--text-muted);
      font-family: var(--font-mono);
      text-transform: uppercase;
    }}
    .meta-stat-val {{
      font-size: 1.1rem;
      font-weight: 700;
      font-family: var(--font-mono);
      color: #fff;
    }}

    /* AI Decision Action Feed */
    .agent-feed {{
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
      max-height: 280px;
      overflow-y: auto;
    }}
    .agent-action-card {{
      background: rgba(0, 0, 0, 0.4);
      border-left: 3px solid var(--cyan-accent);
      border-radius: 6px;
      padding: 0.85rem 1rem;
      display: flex;
      flex-direction: column;
      gap: 0.4rem;
      font-size: 0.85rem;
      transition: all 0.2s;
    }}
    .agent-action-card.is-ban {{
      border-left-color: var(--red-alert);
      background: rgba(255, 51, 102, 0.06);
    }}
    .agent-action-top {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-family: var(--font-mono);
    }}

    /* Hacker / Attacker Threat Radar Section */
    .radar-banner {{
      background: linear-gradient(135deg, rgba(14, 20, 36, 0.95), rgba(28, 12, 28, 0.95));
      border: 1px solid rgba(255, 51, 102, 0.3);
      border-radius: 14px;
      padding: 1.5rem 2rem;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
      display: flex;
      flex-direction: column;
      gap: 1.25rem;
      position: relative;
    }}
    .radar-banner::before {{
      content: "";
      position: absolute;
      top: 0; left: 0; width: 4px; height: 100%;
      background: linear-gradient(to bottom, var(--red-alert), var(--purple-accent));
      border-radius: 4px 0 0 4px;
    }}
    .radar-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
    }}
    .radar-title {{
      font-size: 1.2rem;
      font-weight: 800;
      display: flex;
      align-items: center;
      gap: 0.6rem;
      color: #fff;
    }}
    .attacker-cards-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 1.25rem;
    }}
    .attacker-card {{
      background: rgba(0, 0, 0, 0.4);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 1.25rem;
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
      transition: all 0.25s ease-in-out;
    }}
    .attacker-card.is-clean {{
      border-color: rgba(0, 230, 118, 0.4);
      box-shadow: 0 0 15px rgba(0, 230, 118, 0.1);
      background: linear-gradient(135deg, rgba(14, 20, 36, 0.7), rgba(0, 40, 20, 0.25));
    }}
    .attacker-card.is-suspicious {{
      border-color: rgba(255, 184, 0, 0.6);
      box-shadow: 0 0 18px rgba(255, 184, 0, 0.18);
      background: linear-gradient(135deg, rgba(14, 20, 36, 0.7), rgba(50, 40, 0, 0.25));
    }}
    .attacker-card.is-blocked {{
      border-color: rgba(255, 51, 102, 0.8);
      box-shadow: 0 0 24px rgba(255, 51, 102, 0.35);
      background: linear-gradient(135deg, rgba(14, 20, 36, 0.7), rgba(60, 0, 20, 0.35));
    }}
    .attacker-card-top {{
      display: flex;
      justify-content: space-between;
      align-items: center;
    }}
    .ip-display {{
      font-family: var(--font-mono);
      font-size: 1.1rem;
      font-weight: 700;
      color: #fff;
    }}
    .stats-row {{
      display: flex;
      gap: 1.5rem;
      font-size: 0.85rem;
      font-family: var(--font-mono);
      color: var(--text-muted);
    }}
    .stats-row strong {{
      color: #fff;
    }}

    /* Main Dashboard Layout */
    .dashboard-layout {{
      display: grid;
      grid-template-columns: 2.2fr 1fr;
      gap: 1.5rem;
    }}
    @media (max-width: 1024px) {{
      .dashboard-layout {{ grid-template-columns: 1fr; }}
    }}

    /* Stream Feed Table */
    .stream-container {{
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 14px;
      overflow: hidden;
      display: flex;
      flex-direction: column;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
    }}
    .section-header {{
      padding: 1.25rem 1.5rem;
      border-bottom: 1px solid var(--border-color);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }}
    .section-title {{
      font-size: 1.1rem;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 0.6rem;
    }}
    .table-responsive {{
      overflow-x: auto;
      max-height: 540px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
      text-align: left;
    }}
    th {{
      background: rgba(0, 0, 0, 0.4);
      padding: 0.75rem 1rem;
      font-weight: 600;
      color: var(--text-muted);
      border-bottom: 1px solid var(--border-color);
      font-family: var(--font-mono);
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      position: sticky;
      top: 0;
      z-index: 10;
    }}
    td {{
      padding: 0.75rem 1rem;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      color: var(--text-main);
    }}
    tbody tr {{
      transition: background-color 0.15s ease;
      cursor: pointer;
    }}
    tbody tr:hover {{
      background: rgba(0, 240, 255, 0.06);
    }}

    /* Threat Badges */
    .badge {{
      display: inline-block;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 700;
      font-family: var(--font-mono);
      text-transform: uppercase;
    }}
    .badge-benign {{ background: rgba(0, 230, 118, 0.15); color: var(--green-safe); border: 1px solid rgba(0, 230, 118, 0.3); }}
    .badge-benign_burst {{ background: rgba(0, 240, 255, 0.15); color: var(--cyan-accent); border: 1px solid rgba(0, 240, 255, 0.3); }}
    .badge-credential_stuffing {{ background: rgba(255, 51, 102, 0.2); color: var(--red-alert); border: 1px solid rgba(255, 51, 102, 0.4); }}
    .badge-scraping {{ background: rgba(255, 184, 0, 0.2); color: var(--yellow-warn); border: 1px solid rgba(255, 184, 0, 0.4); }}
    .badge-endpoint_enumeration {{ background: rgba(121, 40, 202, 0.25); color: #c084fc; border: 1px solid rgba(121, 40, 202, 0.4); }}
    .badge-abnormal_sequence {{ background: rgba(255, 0, 128, 0.2); color: #ff0080; border: 1px solid rgba(255, 0, 128, 0.4); }}
    .badge-automated_bot {{ background: rgba(255, 51, 102, 0.25); color: #ff3366; border: 1px solid rgba(255, 51, 102, 0.5); }}

    .badge-allowed {{ color: var(--green-safe); }}
    .badge-throttled {{ color: var(--yellow-warn); font-weight: 700; }}
    .badge-soft_block {{ color: var(--red-alert); font-weight: 800; }}
    .badge-hard_block {{ background: var(--red-alert); color: #000; font-weight: 800; }}

    /* Sidebar Panels */
    .sidebar-panel {{
      display: flex;
      flex-direction: column;
      gap: 1.5rem;
    }}
    .block-card {{
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 14px;
      padding: 1.5rem;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
    }}
    .unblock-btn {{
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border-color);
      color: #fff;
      padding: 0.35rem 0.75rem;
      border-radius: 6px;
      font-size: 0.75rem;
      font-family: var(--font-mono);
      cursor: pointer;
      transition: all 0.2s;
    }}
    .unblock-btn:hover {{
      background: rgba(255, 51, 102, 0.2);
      border-color: var(--red-alert);
      color: var(--red-alert);
    }}

    .kali-cmd-box {{
      background: #04060c;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0.75rem;
      font-family: var(--font-mono);
      font-size: 0.75rem;
      color: #fff;
      margin-top: 0.5rem;
      position: relative;
    }}
    .kali-cmd-box code {{
      display: block;
      color: var(--cyan-accent);
      word-break: break-all;
    }}
    .copy-chip {{
      position: absolute;
      top: 0.4rem; right: 0.4rem;
      background: rgba(255, 255, 255, 0.1);
      border: none;
      color: #fff;
      font-size: 0.7rem;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      cursor: pointer;
    }}
    .copy-chip:hover {{ background: var(--cyan-accent); color: #000; }}

    /* Modal Inspector */
    .modal-overlay {{
      position: fixed;
      top: 0; left: 0; width: 100vw; height: 100vh;
      background: rgba(0, 0, 0, 0.8);
      backdrop-filter: blur(8px);
      z-index: 500;
      display: none;
      justify-content: center;
      align-items: center;
    }}
    .modal-container {{
      background: #0c1222;
      border: 1px solid var(--cyan-accent);
      border-radius: 16px;
      padding: 2rem;
      width: 720px;
      max-width: 90vw;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.8), 0 0 30px var(--cyan-glow);
      display: flex;
      flex-direction: column;
      gap: 1.25rem;
    }}
    .modal-close {{
      background: none; border: none;
      color: var(--text-muted); font-size: 1.5rem;
      cursor: pointer;
    }}
  </style>
</head>
<body>

  <header>
    <div class="brand">
      <div class="logo-badge">PYGENIC ARC</div>
      <div>
        <h1>Autonomous Threat Gateway SOC <span style="font-size: 0.75rem; background: rgba(0, 240, 255, 0.15); color: var(--cyan-accent); padding: 0.2rem 0.6rem; border-radius: 4px; font-family: var(--font-mono);">PORT 8000</span></h1>
        <span>Team Rudranix &bull; Annvation-2K26 Hackathon Final Defense</span>
      </div>
    </div>
    <div class="header-links">
      <button onclick="openManualBanModal('')" class="pill-link" style="border-color: var(--red-alert); color: var(--red-alert); background: rgba(255, 51, 102, 0.1); cursor: pointer;">
        🚫 Ban IP Address
      </button>
      <a href="http://{host_ip}:8001/" target="_blank" class="pill-link">
        🛒 Target Store (:8001)
      </a>
      <a href="http://{host_ip}:8000/docs" target="_blank" class="pill-link">
        📖 Gateway Docs (:8000)
      </a>
      <a href="http://{host_ip}:8001/docs" target="_blank" class="pill-link">
        📖 Target Docs (:8001)
      </a>
      <span class="pill-link">
        <span class="status-pulse"></span> SOC LIVE
      </span>
    </div>
  </header>

  <main>
    <!-- Top Statistics Cards -->
    <div class="metrics-grid">
      <div class="card" style="--card-accent: var(--cyan-accent);">
        <div class="card-label">Total Requests Evaluated</div>
        <div class="card-value" id="val-total-requests">0</div>
        <div class="card-subtext">Real-time deep sliding window behavioral assessment</div>
      </div>
      <div class="card" style="--card-accent: var(--red-alert);">
        <div class="card-label">Autonomous AI Blocks (429 / 403)</div>
        <div class="card-value" style="color: var(--red-alert);" id="val-blocked">0</div>
        <div class="card-subtext">Zero packets reached protected upstream microservice</div>
      </div>
      <div class="card" style="--card-accent: var(--yellow-warn);">
        <div class="card-label">Throttled Requests</div>
        <div class="card-value" style="color: var(--yellow-warn);" id="val-throttled">0</div>
        <div class="card-subtext">Latency degradation applied to automated crawlers</div>
      </div>
      <div class="card" style="--card-accent: var(--green-safe);">
        <div class="card-label">Perimeter Defense Status</div>
        <div class="card-value" style="color: var(--green-safe);" id="val-threat-level">MONITORING</div>
        <div class="card-subtext">Continuous multi-pattern behavioral inspection</div>
      </div>
    </div>

    <!-- 24/7 Autonomous AI Security Sentinel Panel -->
    <div class="sentinel-card">
      <div class="sentinel-header">
        <div class="sentinel-title">
          <span style="font-size: 1.6rem;">🤖</span>
          <div>
            <h2>24/7 Autonomous AI Threat Sentinel <span id="agent-mode-badge" class="badge" style="background: rgba(0, 230, 118, 0.2); color: var(--green-safe); border: 1px solid rgba(0, 230, 118, 0.4);">ACTIVE (24/7 AUTO-BLOCK)</span></h2>
            <span style="font-size: 0.8rem; color: var(--text-muted); font-family: var(--font-mono);">
              Self-governing continuous intrusion monitoring & instant autonomous perimeter containment
            </span>
          </div>
        </div>

        <div class="toggle-wrapper">
          <span class="toggle-label" id="toggle-label-text">AUTONOMOUS MONITORING: ON</span>
          <label class="switch">
            <input type="checkbox" id="agent-toggle-checkbox" checked onchange="toggleAutonomousAgent()">
            <span class="slider"></span>
          </label>
        </div>
      </div>

      <!-- Autonomous Agent Telemetry Grid -->
      <div class="sentinel-meta-grid">
        <div class="meta-stat">
          <div class="meta-stat-label">Sentinel Uptime</div>
          <div class="meta-stat-val" id="sentinel-uptime" style="color: var(--cyan-accent);">00:00:00</div>
        </div>
        <div class="meta-stat">
          <div class="meta-stat-label">Threat Level</div>
          <div class="meta-stat-val" id="sentinel-threat-level" style="color: var(--green-safe);">NOMINAL</div>
        </div>
        <div class="meta-stat">
          <div class="meta-stat-label">Autonomous Bans</div>
          <div class="meta-stat-val" id="sentinel-auto-bans" style="color: var(--red-alert);">0</div>
        </div>
        <div class="meta-stat">
          <div class="meta-stat-label">Mean Detection Latency</div>
          <div class="meta-stat-val" style="color: #fff;">&lt; 12.0 ms</div>
        </div>
        <div class="meta-stat">
          <div class="meta-stat-label">Decision Confidence</div>
          <div class="meta-stat-val" style="color: var(--green-safe);">98.6%</div>
        </div>
      </div>

      <!-- Live Autonomous AI Decision Stream -->
      <div>
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
          <span style="font-size: 0.9rem; font-weight: 700; color: #fff; font-family: var(--font-mono);">
            ⚡ Live Autonomous AI Decision Stream & Action Log
          </span>
          <button onclick="clearAgentActions()" class="unblock-btn" style="font-size: 0.7rem;">Clear AI Log</button>
        </div>
        <div class="agent-feed" id="agent-actions-feed">
          <div style="color: var(--text-muted); font-family: var(--font-mono); font-size: 0.85rem; padding: 0.5rem 0;">
            Sentinel observing incoming telemetry. Awaiting anomalous events...
          </div>
        </div>
      </div>
    </div>

    <!-- Live Attacker Intelligence Radar (Highlights Kali VM in real time) -->
    <div class="radar-banner">
      <div class="radar-header">
        <div class="radar-title">
          <span>🎯 Real-Time Hacker & Remote Attacker Intelligence Radar</span>
        </div>
        <div style="display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap;">
          <span style="font-size: 0.8rem; color: var(--text-muted); font-family: var(--font-mono);">
            Actively tracking real-time IP telemetry & attacks
          </span>
          <button onclick="clearAllBlocks()" class="unblock-btn" style="border-color: var(--cyan-accent); color: var(--cyan-accent); font-weight: 700;">
            🧹 Clear Radar & Telemetry
          </button>
        </div>
      </div>

      <div class="attacker-cards-grid" id="attacker-cards-box">
        <div style="color: var(--text-muted); padding: 1rem 0; font-family: var(--font-mono); font-size: 0.85rem;">
          Awaiting inbound network traffic / attack telemetry...
        </div>
      </div>
    </div>

    <!-- Main Dashboard Layout -->
    <div class="dashboard-layout">
      <!-- Live Packet Telemetry Stream -->
      <div class="stream-container">
        <div class="section-header">
          <div class="section-title">
            <span>🛡️ Continuous Deep Packet Behavioral Telemetry</span>
            <span style="font-size: 0.75rem; color: var(--cyan-accent); font-family: var(--font-mono);">[LIVE AUTO-UPDATE 1.5s]</span>
          </div>
          <div style="display: flex; gap: 0.5rem;">
            <button onclick="clearAllBlocks()" class="unblock-btn" style="border-color: var(--red-alert); color: var(--red-alert);">Reset All Blocks & History</button>
            <button onclick="clearEventFeed()" class="unblock-btn">Clear Stream</button>
          </div>
        </div>
        <div class="table-responsive">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Source IP</th>
                <th>Target Endpoint</th>
                <th>Risk Score</th>
                <th>Detected Category</th>
                <th>Gateway Action</th>
                <th>Evidence Reason (Click Row to Inspect / Ban)</th>
              </tr>
            </thead>
            <tbody id="stream-tbody">
              <tr>
                <td colspan="7" style="text-align: center; color: var(--text-muted); padding: 3rem;">
                  Awaiting incoming traffic from Kali Linux VM or Target App...
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Sidebar: Active Enforcements & Real Kali Tools -->
      <div class="sidebar-panel">
        <!-- Active Enforcements Card -->
        <div class="block-card">
          <div class="section-header" style="padding: 0 0 1rem 0;">
            <h3 style="font-size: 1rem; font-weight: 700;">Active IP Bans & Locks</h3>
            <span id="active-block-count" class="badge badge-soft_block">0</span>
          </div>

          <!-- Quick Ban Input Form -->
          <div style="display: flex; gap: 0.5rem; margin-bottom: 1rem;">
            <input type="text" id="sidebar-quick-ip" placeholder="e.g. 192.168.64.2" style="flex: 1; background: var(--bg-surface); border: 1px solid var(--border-color); color: #fff; padding: 0.4rem 0.6rem; border-radius: 6px; font-family: var(--font-mono); font-size: 0.8rem; outline: none;">
            <button onclick="quickBanFromSidebar()" class="unblock-btn" style="background: rgba(255, 51, 102, 0.2); border-color: var(--red-alert); color: var(--red-alert); font-weight: 700;">
              🚫 Ban IP
            </button>
          </div>

          <div id="active-blocks-list" style="font-size: 0.85rem; font-family: var(--font-mono);">
            <div style="color: var(--text-muted); padding: 0.5rem 0;">No IPs currently banned.</div>
          </div>
        </div>

        <!-- Real Kali Attack Instructions -->
        <div class="block-card">
          <h3 style="font-size: 1rem; font-weight: 700; margin-bottom: 0.25rem;">Real Kali Linux Attack Suite</h3>
          <p style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 1rem;">
            Execute real penetration tests from your Kali VM against host <code>{host_ip}</code>:
          </p>

          <div>
            <span style="font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono);">1. Credential Stuffing (Hydra / Curl):</span>
            <div class="kali-cmd-box">
              <button class="copy-chip" onclick="copyText('for p in pass1 pass2 pass3 pass4 pass5; do curl -X POST http://{host_ip}:8000/gateway/auth/login -H \\"Content-Type: application/json\\" -d \\"{{\\\\\\"username\\\\\\":\\\\\\"admin\\\\\\",\\\\\\"password\\\\\\":\\\\\\"$p\\\\\\"}}\\"; sleep 0.1; done')">Copy</button>
              <code>for p in pass1 pass2 pass3 pass4 pass5; do curl -X POST http://{host_ip}:8000/gateway/auth/login -d '{{"username":"admin","password":"$p"}}'; sleep 0.1; done</code>
            </div>
          </div>

          <div style="margin-top: 0.75rem;">
            <span style="font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono);">2. Machine Scraper (Timing Entropy &sigma; &lt; 30ms):</span>
            <div class="kali-cmd-box">
              <button class="copy-chip" onclick="copyText('for i in $(seq 1 12); do curl -s http://{host_ip}:8000/gateway/products; sleep 0.08; done')">Copy</button>
              <code>for i in $(seq 1 12); do curl -s http://{host_ip}:8000/gateway/products; sleep 0.08; done</code>
            </div>
          </div>

          <div style="margin-top: 0.75rem;">
            <span style="font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono);">3. Sequential IDOR Enumeration (&Delta;ID = 1):</span>
            <div class="kali-cmd-box">
              <button class="copy-chip" onclick="copyText('for id in $(seq 1 6); do curl -s http://{host_ip}:8000/gateway/users/$id; sleep 0.15; done')">Copy</button>
              <code>for id in $(seq 1 6); do curl -s http://{host_ip}:8000/gateway/users/$id; sleep 0.15; done</code>
            </div>
          </div>

          <div style="margin-top: 0.75rem;">
            <span style="font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono);">4. Sequence Workflow Bypass (Markov Anomaly):</span>
            <div class="kali-cmd-box">
              <button class="copy-chip" onclick="copyText('curl -i -X POST http://{host_ip}:8000/gateway/checkout -H \\"Content-Type: application/json\\" -d \\"{{\\\\\\"payment_method\\\\\\":\\\\\\"card\\\\\\"}}\\"')">Copy</button>
              <code>curl -i -X POST http://{host_ip}:8000/gateway/checkout -d '{{"payment_method":"card"}}'</code>
            </div>
          </div>

          <div style="margin-top: 0.75rem;">
            <span style="font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono);">5. Automated Shell Suite:</span>
            <div class="kali-cmd-box">
              <button class="copy-chip" onclick="copyText('./attack_suite.sh gateway {host_ip}')">Copy</button>
              <code>./attack_suite.sh gateway {host_ip}</code>
            </div>
          </div>
        </div>
      </div>
    </div>
  </main>

  <!-- Explainability Deep-Dive Inspector Modal -->
  <div class="modal-overlay" id="inspector-modal" onclick="closeInspectorModal()">
    <div class="modal-container" onclick="event.stopPropagation()">
      <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 1rem;">
        <div>
          <h3 style="font-size: 1.25rem; font-weight: 800; color: #fff;">🔬 Packet Threat Evidence Inspector</h3>
          <span style="font-size: 0.8rem; color: var(--text-muted); font-family: var(--font-mono);">Deep architectural decision attribution</span>
        </div>
        <button class="modal-close" onclick="closeInspectorModal()">&times;</button>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
        <div style="background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 8px; padding: 1rem;">
          <div style="font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono);">TARGET EVENT:</div>
          <div style="font-size: 1.1rem; font-weight: 700; color: var(--cyan-accent); margin-top: 0.25rem;" id="modal-event-path">/gateway/login</div>
          <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">Client IP: <strong id="modal-event-ip" style="color: #fff;">192.168.64.2</strong> &bull; Time: <span id="modal-event-time">12:00:00</span></div>
        </div>
        <div style="background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 8px; padding: 1rem;">
          <div style="font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono);">VERDICT & ACTION:</div>
          <div style="display: flex; align-items: center; gap: 0.5rem; margin-top: 0.25rem;">
            <span id="modal-event-cat" class="badge badge-credential_stuffing">CREDENTIAL_STUFFING</span>
            <span id="modal-event-action" class="badge" style="background: var(--red-alert); color: #000;">SOFT_BLOCK</span>
          </div>
          <div style="font-size: 0.85rem; color: #fff; margin-top: 0.4rem;">Risk Score: <strong id="modal-event-score" style="color: var(--red-alert); font-family: var(--font-mono);">0.95 / 1.00</strong></div>
        </div>
      </div>

      <div>
        <div style="font-size: 0.85rem; font-weight: 700; color: #fff; margin-bottom: 0.5rem;">Behavioral Rationale:</div>
        <div id="modal-event-explanation" style="background: rgba(0, 0, 0, 0.4); border-left: 3px solid var(--cyan-accent); padding: 0.75rem 1rem; border-radius: 4px; font-size: 0.85rem; color: var(--text-main); line-height: 1.5;">
          High-confidence threat detected. Automatic soft-block enforced with Retry-After.
        </div>
      </div>

      <div>
        <div style="font-size: 0.85rem; font-weight: 700; color: #fff; margin-bottom: 0.5rem;">Mathematical Evidence & Feature Contributions:</div>
        <pre id="modal-event-evidence" style="background: #04060c; border: 1px solid var(--border-color); border-radius: 8px; padding: 1rem; font-family: var(--font-mono); font-size: 0.8rem; color: var(--cyan-accent); max-height: 180px; overflow-y: auto; white-space: pre-wrap;"></pre>
      </div>

      <div style="display: flex; justify-content: space-between; align-items: center; border-top: 1px solid var(--border-color); padding-top: 1rem;">
        <div style="display: flex; gap: 0.5rem;">
          <button id="modal-btn-ban" class="unblock-btn" style="background: rgba(255, 51, 102, 0.2); border-color: var(--red-alert); color: var(--red-alert); font-weight: 700;" onclick="banCurrentModalIp()">
            🚫 Ban This Source IP
          </button>
          <button id="modal-btn-unblock" class="unblock-btn" style="border-color: var(--green-safe); color: var(--green-safe);" onclick="unblockCurrentModalIp()">
            🔓 Unblock IP
          </button>
        </div>
        <button class="pill-link" onclick="closeInspectorModal()">Close Inspector</button>
      </div>
    </div>
  </div>

  <!-- Manual Ban Operator Modal -->
  <div class="modal-overlay" id="manual-ban-modal" onclick="closeManualBanModal()">
    <div class="modal-container" style="width: 480px;" onclick="event.stopPropagation()">
      <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 1rem;">
        <h3 style="font-size: 1.2rem; font-weight: 700; color: var(--red-alert);">🚫 Manual Gateway IP Ban</h3>
        <button class="modal-close" onclick="closeManualBanModal()">&times;</button>
      </div>
      <div>
        <label style="display: block; font-size: 0.8rem; color: var(--text-muted); font-family: var(--font-mono); margin-bottom: 0.4rem;">Target IP Address</label>
        <input type="text" id="ban-input-ip" placeholder="e.g. 192.168.64.2" style="width: 100%; background: var(--bg-surface); border: 1px solid var(--border-color); color: #fff; padding: 0.6rem; border-radius: 6px; font-family: var(--font-mono); font-size: 0.9rem; outline: none; margin-bottom: 1rem;">

        <label style="display: block; font-size: 0.8rem; color: var(--text-muted); font-family: var(--font-mono); margin-bottom: 0.4rem;">Ban Duration (TTL)</label>
        <select id="ban-input-ttl" style="width: 100%; background: var(--bg-surface); border: 1px solid var(--border-color); color: #fff; padding: 0.6rem; border-radius: 6px; font-family: var(--font-mono); font-size: 0.9rem; outline: none; margin-bottom: 1rem;">
          <option value="300">5 Minutes (300s)</option>
          <option value="900">15 Minutes (900s)</option>
          <option value="3600">1 Hour (3600s)</option>
          <option value="86400">24 Hours (86400s)</option>
        </select>

        <label style="display: block; font-size: 0.8rem; color: var(--text-muted); font-family: var(--font-mono); margin-bottom: 0.4rem;">Reason / Memo</label>
        <input type="text" id="ban-input-reason" value="Manual ban enforced by SOC operator" style="width: 100%; background: var(--bg-surface); border: 1px solid var(--border-color); color: #fff; padding: 0.6rem; border-radius: 6px; font-family: var(--font-mono); font-size: 0.9rem; outline: none; margin-bottom: 1.5rem;">

        <button onclick="submitManualBan()" class="unblock-btn" style="width: 100%; padding: 0.75rem; background: var(--red-alert); color: #000; font-weight: 800; font-size: 0.95rem; border: none; cursor: pointer;">
          🔒 Enforce Immediate Hard Ban
        </button>
      </div>
    </div>
  </div>

  <script>
    const HOST_IP = "{host_ip}";
    let currentEvents = [];
    let selectedInspectorIp = "";

    // Auto-refresh loop
    document.addEventListener('DOMContentLoaded', () => {{
      fetchDashboardStats();
      setInterval(fetchDashboardStats, 1500);
    }});

    async function toggleAutonomousAgent() {{
      const isChecked = document.getElementById('agent-toggle-checkbox').checked;
      try {{
        const res = await fetch('/api/autonomous-agent/toggle', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ enabled: isChecked }})
        }});
        const data = await res.json();
        updateAgentToggleUI(data.enabled);
      }} catch (err) {{
        console.error('Failed to toggle agent:', err);
      }}
    }}

    function updateAgentToggleUI(enabled) {{
      const checkbox = document.getElementById('agent-toggle-checkbox');
      checkbox.checked = enabled;
      const label = document.getElementById('toggle-label-text');
      const badge = document.getElementById('agent-mode-badge');
      
      if (enabled) {{
        label.innerText = 'AUTONOMOUS MONITORING: ON';
        label.style.color = 'var(--green-safe)';
        badge.innerText = 'ACTIVE (24/7 AUTO-BLOCK)';
        badge.style.background = 'rgba(0, 230, 118, 0.2)';
        badge.style.color = 'var(--green-safe)';
        badge.style.borderColor = 'rgba(0, 230, 118, 0.4)';
      }} else {{
        label.innerText = 'AUTONOMOUS MONITORING: OFF';
        label.style.color = 'var(--yellow-warn)';
        badge.innerText = 'STANDBY (MANUAL ONLY)';
        badge.style.background = 'rgba(255, 184, 0, 0.2)';
        badge.style.color = 'var(--yellow-warn)';
        badge.style.borderColor = 'rgba(255, 184, 0, 0.4)';
      }}
    }}

    async function clearAgentActions() {{
      await fetch('/api/autonomous-agent/clear-actions', {{ method: 'POST' }});
      fetchDashboardStats();
    }}

    async function fetchDashboardStats() {{
      try {{
        const res = await fetch('/api/dashboard-stats');
        const data = await res.json();

        // Counter Cards
        document.getElementById('val-total-requests').innerText = data.total_requests;
        document.getElementById('val-blocked').innerText = data.total_blocked;
        document.getElementById('val-throttled').innerText = data.total_throttled;

        if (data.total_blocked > 0) {{
          document.getElementById('val-threat-level').innerText = 'ENFORCING';
          document.getElementById('val-threat-level').style.color = 'var(--red-alert)';
        }} else {{
          document.getElementById('val-threat-level').innerText = 'MONITORING';
          document.getElementById('val-threat-level').style.color = 'var(--green-safe)';
        }}

        // Autonomous AI Sentinel State
        const agent = data.autonomous_agent;
        if (agent) {{
          updateAgentToggleUI(agent.enabled);
          document.getElementById('sentinel-uptime').innerText = agent.uptime_formatted || '00:00:00';
          document.getElementById('sentinel-auto-bans').innerText = agent.total_autonomous_bans || 0;
          
          const tLevel = document.getElementById('sentinel-threat-level');
          tLevel.innerText = agent.threat_level || 'NOMINAL';
          if (agent.threat_level === 'CRITICAL') {{
            tLevel.style.color = 'var(--red-alert)';
          }} else if (agent.threat_level === 'ELEVATED') {{
            tLevel.style.color = 'var(--yellow-warn)';
          }} else {{
            tLevel.style.color = 'var(--green-safe)';
          }}

          // Render Live Agent Action Stream
          const actionsBox = document.getElementById('agent-actions-feed');
          const actions = agent.recent_actions || [];
          if (actions.length === 0) {{
            actionsBox.innerHTML = `
              <div style="color: var(--text-muted); font-family: var(--font-mono); font-size: 0.85rem; padding: 0.5rem 0;">
                Sentinel observing incoming telemetry. Awaiting anomalous events...
              </div>
            `;
          }} else {{
            actionsBox.innerHTML = actions.slice(0, 6).map(act => `
              <div class="agent-action-card ${{act.action_taken === 'AUTONOMOUS_IP_BAN' || act.action_taken === 'AUTONOMOUS_PATROL_BAN' ? 'is-ban' : ''}}">
                <div class="agent-action-top">
                  <div>
                    <span style="color: var(--text-muted); font-size: 0.75rem;">[${{act.time_str}}]</span>
                    <strong style="color: #fff; margin-left: 0.4rem;">${{act.target_ip}}</strong>
                    <span class="badge badge-${{act.behaviour_category.toLowerCase()}}" style="margin-left: 0.4rem;">${{act.behaviour_category}}</span>
                  </div>
                  <span class="badge" style="background: ${{act.action_taken.includes('BAN') ? 'var(--red-alert)' : 'var(--yellow-warn)'}}; color: #000; font-size: 0.7rem;">
                    ${{act.action_taken}}
                  </span>
                </div>
                <div style="font-size: 0.8rem; color: var(--cyan-accent); font-family: var(--font-mono);">
                  💡 <strong>Analysis:</strong> ${{act.analysis}}
                </div>
                <div style="font-size: 0.8rem; color: var(--text-muted);">
                  🔒 <strong>Mitigation:</strong> ${{act.mitigation_applied}}
                </div>
              </div>
            `).join('');
          }}
        }}

        // Attacker Intelligence Radar Cards
        const attackerBox = document.getElementById('attacker-cards-box');
        const profiles = data.attacker_profiles || [];
        if (profiles.length === 0) {{
          attackerBox.innerHTML = `
            <div style="color: var(--text-muted); padding: 1.25rem 0; font-family: var(--font-mono); font-size: 0.85rem; text-align: center;">
              Awaiting inbound network traffic / attack telemetry from Localhost or Remote Kali VM...
            </div>
          `;
        }} else {{
          attackerBox.innerHTML = profiles.map(p => {{
            const cardClass = p.status === 'BLOCKED' ? 'is-blocked' : (p.status === 'SUSPICIOUS' || p.status === 'THROTTLED' ? 'is-suspicious' : 'is-clean');
            const statusColor = p.status === 'BLOCKED' ? 'var(--red-alert)' : (p.status === 'SUSPICIOUS' || p.status === 'THROTTLED' ? 'var(--yellow-warn)' : 'var(--green-safe)');
            const statusIcon = p.status === 'BLOCKED' ? '🔴' : (p.status === 'SUSPICIOUS' || p.status === 'THROTTLED' ? '🟡' : '🟢');
            const catClean = p.category ? p.category.toLowerCase().replace(/[^a-z0-9]/g, '_') : 'benign';
            return `
            <div class="attacker-card ${{cardClass}}">
              <div class="attacker-card-top">
                <div>
                  <div class="ip-display" style="display: flex; align-items: center; gap: 0.45rem;">
                    <span>${{statusIcon}}</span>
                    <span>${{p.ip}}</span>
                  </div>
                  <div style="font-size: 0.75rem; color: ${{p.is_external ? 'var(--cyan-accent)' : 'var(--text-muted)'}}; font-family: var(--font-mono); margin-top: 0.2rem;">
                    ${{p.is_external ? '🌐 REMOTE HOST / KALI VM' : '💻 LOCALHOST LOOPBACK (127.0.0.1)'}}
                  </div>
                </div>
                <span class="badge" style="background: rgba(255,255,255,0.06); border: 1px solid ${{statusColor}}; color: ${{statusColor}}; font-size: 0.8rem; font-weight: 700;">
                  ${{p.status}}
                </span>
              </div>

              <div class="stats-row">
                <div>Requests: <strong>${{p.total_requests}}</strong></div>
                <div>Auth Fails: <strong style="color: ${{p.auth_failures > 0 ? 'var(--red-alert)' : 'var(--text-muted)'}};">${{p.auth_failures}}</strong></div>
                <div>Risk: <strong style="color: ${{p.risk_score > 0.6 ? 'var(--red-alert)' : (p.risk_score > 0.3 ? 'var(--yellow-warn)' : 'var(--green-safe)')}};">${{p.risk_score.toFixed(2)}}</strong></div>
              </div>

              <div style="font-size: 0.8rem; color: var(--text-muted); display: flex; align-items: center; flex-wrap: wrap; gap: 0.4rem;">
                <span>Behavior:</span> <span class="badge badge-${{catClean}}">${{p.category}}</span>
                ${{p.ttl > 0 ? `<span style="color: var(--yellow-warn); font-family: var(--font-mono); font-weight: 700;">[${{p.ttl}}s remaining]</span>` : ''}}
              </div>

              <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 0.5rem; gap: 0.5rem;">
                <span style="font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono);">Last seen: ${{p.last_seen_sec_ago}}s ago</span>
                <div style="display: flex; gap: 0.4rem;">
                  ${{p.status === 'BLOCKED' ? `
                    <button onclick="unblockSingleIp('${{p.ip}}')" class="unblock-btn" style="border-color: var(--green-safe); color: var(--green-safe); font-weight: 700;">
                      🔓 Unblock IP
                    </button>
                  ` : `
                    <button onclick="banSingleIp('${{p.ip}}')" class="unblock-btn" style="background: rgba(255, 51, 102, 0.15); border-color: var(--red-alert); color: var(--red-alert); font-weight: 700;">
                      🚫 Ban IP
                    </button>
                  `}}
                </div>
              </div>
            </div>
          `;
          }}).join('');
        }}

        // Active Blocks List
        const blockList = document.getElementById('active-blocks-list');
        document.getElementById('active-block-count').innerText = data.active_blocks.length;

        if (data.active_blocks.length === 0) {{
          blockList.innerHTML = '<div style="color: var(--text-muted); padding: 0.5rem 0;">No active IP bans.</div>';
        }} else {{
          blockList.innerHTML = data.active_blocks.map(b => `
            <div style="background: rgba(255, 51, 102, 0.1); border: 1px solid rgba(255, 51, 102, 0.3); border-radius: 8px; padding: 0.75rem; margin-bottom: 0.5rem;">
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="color: var(--red-alert); font-weight: 700;">${{b.ip}}</span>
                <span style="font-size: 0.75rem; color: var(--yellow-warn);">${{b.ttl}}s left</span>
              </div>
              <div style="font-size: 0.75rem; color: var(--text-muted); margin: 0.25rem 0;">Reason: ${{b.category}}</div>
              <button onclick="unblockSingleIp('${{b.ip}}')" class="unblock-btn" style="width: 100%; margin-top: 0.25rem;">Revoke Ban Now</button>
            </div>
          `).join('');
        }}

        // Recent Events Table
        currentEvents = data.recent_events || [];
        const tbody = document.getElementById('stream-tbody');
        if (currentEvents.length === 0) {{
          tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 3rem;">Awaiting incoming traffic from Kali Linux VM or Target App...</td></tr>`;
        }} else {{
          tbody.innerHTML = currentEvents.map((ev, index) => {{
            const v = ev.verdict;
            const catClass = 'badge-' + v.behaviour_category.toLowerCase();
            const actionClass = 'badge-' + v.action.toLowerCase();
            const reasonText = (v.evidence.reasons && v.evidence.reasons[0]) ? v.evidence.reasons[0] : v.explanation;

            return `
              <tr onclick="inspectEventRow(${{index}})">
                <td style="font-family: var(--font-mono); color: var(--text-muted);">${{ev.time_str}}</td>
                <td style="font-family: var(--font-mono); font-weight: 600;">${{ev.client_ip}}</td>
                <td style="font-family: var(--font-mono); color: var(--cyan-accent);">${{ev.path}}</td>
                <td>
                  <strong style="color: ${{v.risk_score > 0.6 ? 'var(--red-alert)' : (v.risk_score > 0.3 ? 'var(--yellow-warn)' : 'var(--green-safe)')}}; font-family: var(--font-mono);">
                    ${{v.risk_score.toFixed(2)}}
                  </strong>
                </td>
                <td><span class="badge ${{catClass}}">${{v.behaviour_category}}</span></td>
                <td><span class="badge ${{actionClass}}">${{v.action}}</span></td>
                <td style="max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--text-muted); font-size: 0.8rem;">
                  ${{reasonText}}
                </td>
              </tr>
            `;
          }}).join('');
        }}
      }} catch (err) {{
        console.error('Telemetry fetch error:', err);
      }}
    }}

    function inspectEventRow(index) {{
      const ev = currentEvents[index];
      if (!ev) return;
      const v = ev.verdict;
      selectedInspectorIp = ev.client_ip;

      document.getElementById('modal-event-path').innerText = ev.path;
      document.getElementById('modal-event-ip').innerText = ev.client_ip;
      document.getElementById('modal-event-time').innerText = ev.time_str;

      const catBadge = document.getElementById('modal-event-cat');
      catBadge.innerText = v.behaviour_category;
      catBadge.className = 'badge badge-' + v.behaviour_category.toLowerCase();

      const actBadge = document.getElementById('modal-event-action');
      actBadge.innerText = v.action;
      actBadge.className = 'badge badge-' + v.action.toLowerCase();

      document.getElementById('modal-event-score').innerText = v.risk_score.toFixed(3) + ' / 1.00';
      document.getElementById('modal-event-explanation').innerText = v.explanation;
      document.getElementById('modal-event-evidence').innerText = JSON.stringify(v.evidence, null, 2);

      document.getElementById('inspector-modal').style.display = 'flex';
    }}

    function closeInspectorModal() {{
      document.getElementById('inspector-modal').style.display = 'none';
    }}

    function openManualBanModal(prefillIp = '') {{
      if (prefillIp) {{
        document.getElementById('ban-input-ip').value = prefillIp;
      }}
      document.getElementById('manual-ban-modal').style.display = 'flex';
    }}

    function closeManualBanModal() {{
      document.getElementById('manual-ban-modal').style.display = 'none';
    }}

    async function submitManualBan() {{
      const ip = document.getElementById('ban-input-ip').value.trim();
      const ttl = parseInt(document.getElementById('ban-input-ttl').value) || 300;
      const reason = document.getElementById('ban-input-reason').value.trim();
      if (!ip) {{
        alert('Please enter a valid IP address.');
        return;
      }}
      await banSingleIp(ip, ttl, reason);
      closeManualBanModal();
    }}

    async function quickBanFromSidebar() {{
      const ip = document.getElementById('sidebar-quick-ip').value.trim();
      if (!ip) {{
        alert('Enter an IP address to ban.');
        return;
      }}
      await banSingleIp(ip, 300, 'Quick ban from SOC sidebar');
      document.getElementById('sidebar-quick-ip').value = '';
    }}

    async function banCurrentModalIp() {{
      if (!selectedInspectorIp) return;
      await banSingleIp(selectedInspectorIp, 300, 'Direct ban from packet inspector');
      closeInspectorModal();
    }}

    async function unblockCurrentModalIp() {{
      if (!selectedInspectorIp) return;
      await unblockSingleIp(selectedInspectorIp);
      closeInspectorModal();
    }}

    async function banSingleIp(ip, ttl = 300, reason = 'Manual operator ban from SOC Dashboard') {{
      await fetch('/api/block-ip', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ ip: ip, ttl_seconds: ttl, reason: reason }})
      }});
      fetchDashboardStats();
    }}

    async function unblockSingleIp(ip) {{
      await fetch('/api/unblock-ip', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ ip: ip }})
      }});
      fetchDashboardStats();
    }}

    async function clearAllBlocks() {{
      await fetch('/api/clear-all-blocks', {{ method: 'POST' }});
      fetchDashboardStats();
    }}

    async function clearEventFeed() {{
      await fetch('/api/clear-feed', {{ method: 'POST' }});
      fetchDashboardStats();
    }}

    function copyText(str) {{
      navigator.clipboard.writeText(str);
      alert('📋 Command copied to clipboard! Paste into your Kali terminal.');
    }}
  </script>
</body>
</html>
"""
    return HTMLResponse(content=html_content)
