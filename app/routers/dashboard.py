"""
Cyber Threat Intelligence & Gateway SOC Dashboard (Team Rudranix)
Pygenic Arc — API Abuse & Behavioral Threat Detection Platform

Serves the interactive SOC Dashboard, Mentor Education Hub, and Live Attack Simulator.
"""

import time
from typing import Any, Dict
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from app.services.threat_engine import threat_engine

router = APIRouter(tags=["dashboard"])


class UnblockRequest(BaseModel):
    ip: str


@router.get("/api/dashboard-stats")
async def get_dashboard_stats():
    """Returns live telemetry for dashboard auto-refresh."""
    return threat_engine.get_dashboard_data()


@router.post("/api/unblock-ip")
async def unblock_ip(req: UnblockRequest):
    """Permits mentors to unblock an IP during live demonstrations."""
    res = threat_engine.unblock_ip(req.ip)
    return {"success": res, "unblocked_ip": req.ip}


@router.post("/api/clear-all-blocks")
async def clear_all_blocks():
    """Clears all current enforcement blocks."""
    count = len(threat_engine.local_store.blocked_ips)
    threat_engine.local_store.blocked_ips.clear()
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
    Renders the live Cybersecurity Threat Intelligence SOC Dashboard & Educational Simulator.
    """
    host = request.headers.get("host", "localhost:8000")
    host_ip = host.split(":")[0]

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Pygenic Arc | Cyber Threat Gateway SOC & Educational Lab</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Outfit:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg-base: #060911;
      --bg-surface: #0e1424;
      --bg-card: rgba(16, 23, 41, 0.75);
      --border-color: rgba(255, 255, 255, 0.08);
      --border-focus: rgba(0, 240, 255, 0.4);
      --cyan-accent: #00f0ff;
      --cyan-glow: rgba(0, 240, 255, 0.25);
      --red-alert: #ff3366;
      --red-glow: rgba(255, 51, 102, 0.25);
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
        radial-gradient(circle at 90% 80%, rgba(255, 51, 102, 0.04) 0%, transparent 40%);
    }}

    /* Top Nav */
    header {{
      background: rgba(14, 20, 36, 0.9);
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

    /* Educational Simulator Hub */
    .simulator-hub {{
      background: linear-gradient(135deg, rgba(14, 20, 36, 0.95), rgba(22, 16, 38, 0.95));
      border: 1px solid rgba(0, 240, 255, 0.25);
      border-radius: 14px;
      padding: 1.5rem 2rem;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
      display: flex;
      flex-direction: column;
      gap: 1.25rem;
    }}
    .sim-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
    }}
    .sim-title {{
      font-size: 1.2rem;
      font-weight: 800;
      display: flex;
      align-items: center;
      gap: 0.6rem;
      color: #fff;
    }}
    .sim-tabs {{
      display: flex;
      gap: 0.5rem;
      flex-wrap: wrap;
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 0.75rem;
    }}
    .sim-tab-btn {{
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid var(--border-color);
      color: var(--text-muted);
      font-size: 0.85rem;
      font-weight: 600;
      padding: 0.5rem 1rem;
      border-radius: 6px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      transition: all 0.2s;
    }}
    .sim-tab-btn:hover {{
      color: #fff;
      border-color: var(--cyan-accent);
    }}
    .sim-tab-btn.active {{
      background: rgba(0, 240, 255, 0.12);
      border-color: var(--cyan-accent);
      color: var(--cyan-accent);
      box-shadow: 0 0 12px var(--cyan-glow);
    }}

    .sim-content-card {{
      background: rgba(0, 0, 0, 0.35);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 1.5rem;
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }}
    .sim-grid {{
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 1.5rem;
    }}
    @media (max-width: 960px) {{
      .sim-grid {{ grid-template-columns: 1fr; }}
    }}
    .sim-info-block h4 {{
      font-size: 1rem;
      font-weight: 700;
      color: #fff;
      margin-bottom: 0.4rem;
    }}
    .sim-info-block p {{
      font-size: 0.85rem;
      color: var(--text-muted);
      line-height: 1.5;
      margin-bottom: 0.75rem;
    }}
    .sim-math-box {{
      background: #04060c;
      border: 1px solid var(--border-color);
      border-left: 3px solid var(--cyan-accent);
      border-radius: 6px;
      padding: 0.75rem 1rem;
      font-family: var(--font-mono);
      font-size: 0.8rem;
      color: var(--cyan-accent);
      margin-bottom: 0.75rem;
    }}
    .btn-fire-sim {{
      background: linear-gradient(135deg, var(--red-alert), #b80040);
      color: #fff;
      border: none;
      padding: 0.75rem 1.25rem;
      border-radius: 8px;
      font-weight: 700;
      font-size: 0.9rem;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      box-shadow: 0 0 20px rgba(255, 51, 102, 0.3);
      transition: all 0.2s;
    }}
    .btn-fire-sim:hover {{
      transform: translateY(-2px);
      box-shadow: 0 0 25px rgba(255, 51, 102, 0.5);
    }}
    .btn-fire-benign {{
      background: linear-gradient(135deg, var(--green-safe), #009944);
      box-shadow: 0 0 20px rgba(0, 230, 118, 0.3);
    }}
    .btn-fire-benign:hover {{
      box-shadow: 0 0 25px rgba(0, 230, 118, 0.5);
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
        <h1>Behavioral Threat Gateway & SOC <span style="font-size: 0.75rem; background: rgba(0, 240, 255, 0.15); color: var(--cyan-accent); padding: 0.2rem 0.6rem; border-radius: 4px; font-family: var(--font-mono);">PORT 8000</span></h1>
        <span>Team Rudranix &bull; Annvation-2K26 Hackathon</span>
      </div>
    </div>
    <div class="header-links">
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
        <span class="status-pulse"></span> DEFENSES ARMED
      </span>
    </div>
  </header>

  <main>
    <!-- Top Statistics Cards -->
    <div class="metrics-grid">
      <div class="card" style="--card-accent: var(--cyan-accent);">
        <div class="card-label">Total Requests Inspected</div>
        <div class="card-value" id="val-total-requests">0</div>
        <div class="card-subtext">Real-time sliding window behavioral assessment</div>
      </div>
      <div class="card" style="--card-accent: var(--red-alert);">
        <div class="card-label">Threats Blocked (429 / 403)</div>
        <div class="card-value" style="color: var(--red-alert);" id="val-blocked">0</div>
        <div class="card-subtext">Automated soft/hard blocks enforced</div>
      </div>
      <div class="card" style="--card-accent: var(--yellow-warn);">
        <div class="card-label">Throttled Requests</div>
        <div class="card-value" style="color: var(--yellow-warn);" id="val-throttled">0</div>
        <div class="card-subtext">Artificial delay + Retry-After latency degradation</div>
      </div>
      <div class="card" style="--card-accent: var(--green-safe);">
        <div class="card-label">Markov Engine Status</div>
        <div class="card-value" style="color: var(--green-safe);" id="val-threat-level">MONITORING</div>
        <div class="card-subtext">Sequence model & entropy scoring active</div>
      </div>
    </div>

    <!-- Educational Simulator Hub -->
    <div class="simulator-hub">
      <div class="sim-header">
        <div class="sim-title">
          <span>🎓 Mentor Educational Guide & Interactive Threat Simulator</span>
        </div>
        <div>
          <span style="font-size: 0.8rem; color: var(--text-muted); font-family: var(--font-mono);">
            Select an attack vector below to learn the algorithm or fire a simulated test:
          </span>
        </div>
      </div>

      <div class="sim-tabs">
        <button class="sim-tab-btn active" onclick="switchSimTab('stuffing')">
          1. Credential Stuffing
        </button>
        <button class="sim-tab-btn" onclick="switchSimTab('scraping')">
          2. Content Scraping
        </button>
        <button class="sim-tab-btn" onclick="switchSimTab('idor')">
          3. Sequential IDOR
        </button>
        <button class="sim-tab-btn" onclick="switchSimTab('sequence')">
          4. Workflow Sequence Anomaly
        </button>
        <button class="sim-tab-btn" onclick="switchSimTab('benign')">
          5. Legitimate Flash Sale Burst
        </button>
      </div>

      <!-- Simulator Tab 1: Credential Stuffing -->
      <div id="sim-tab-stuffing" class="sim-content-card">
        <div class="sim-grid">
          <div class="sim-info-block">
            <h4>Dual-Axis Velocity Correlation vs Password Spraying</h4>
            <p>
              <strong>The Threat:</strong> Automated botnets spray leaked credentials across <code>/auth/login</code>. They rotate user accounts or pace requests to stay below simple static RPS limits.<br>
              <strong>Why Static WAFs Fail:</strong> Static rate limits only measure single-endpoint requests per second. A bot sending 1 login attempt every 2 seconds slips right through.<br>
              <strong>Pygenic Arc Innovation:</strong> Correlates authentication failures along two independent axes: source IP failures ($F_{{IP}} \ge 5$) and targeted account failures ($F_{{User}} \ge 3$). Once exceeded, the IP is automatically soft-blocked for 180s with <code>429 Too Many Requests</code>.
            </p>
            <div class="sim-math-box">
              Mathematical Rule: Risk = min(1.0, 0.70 + (F_IP / 10.0)) | Soft-Block Trigger: F_IP &ge; 5 or F_User &ge; 3
            </div>
          </div>
          <div style="display: flex; flex-direction: column; justify-content: center; gap: 0.75rem;">
            <button class="btn-fire-sim" onclick="launchSimulatedStuffing()">
              ⚡ Simulate Credential Spraying
            </button>
            <span style="font-size: 0.75rem; color: var(--text-muted); text-align: center;">Fires 5 rapid failed logins to trigger soft-block</span>
          </div>
        </div>
      </div>

      <!-- Simulator Tab 2: Content Scraping -->
      <div id="sim-tab-scraping" class="sim-content-card" style="display: none;">
        <div class="sim-grid">
          <div class="sim-info-block">
            <h4>Inter-Arrival Timing Entropy Analysis ($\sigma < 30\text{{ms}}$)</h4>
            <p>
              <strong>The Threat:</strong> Scraper scripts systematically harvest catalog pricing and inventory on <code>/products</code>.<br>
              <strong>Why Static WAFs Fail:</strong> Scrapers tuned to 5 RPS bypass volume-based thresholds.<br>
              <strong>Pygenic Arc Innovation:</strong> Analyzes inter-arrival time standard deviation $\sigma$. Software loops execute with rigid clock precision ($\sigma < 30\text{{ms}}$), whereas human interactions exhibit wide cognitive entropy ($\sigma > 150\text{{ms}}$).
            </p>
            <div class="sim-math-box">
              Formula: &sigma; = &radic;[ (1 / (N-1)) &Sigma; (t_i - &mu;)^2 ] | Bot Threshold: &sigma; &lt; 30.0 ms & Pacing &lt; 1500 ms
            </div>
          </div>
          <div style="display: flex; flex-direction: column; justify-content: center; gap: 0.75rem;">
            <button class="btn-fire-sim" onclick="launchSimulatedScraping()">
              ⚡ Simulate Machine Scraper
            </button>
            <span style="font-size: 0.75rem; color: var(--text-muted); text-align: center;">Sends requests at rigid 40ms clock intervals</span>
          </div>
        </div>
      </div>

      <!-- Simulator Tab 3: Sequential IDOR -->
      <div id="sim-tab-idor" class="sim-content-card" style="display: none;">
        <div class="sim-grid">
          <div class="sim-info-block">
            <h4>Sequential Identifier Walking & 404 Error Clustering</h4>
            <p>
              <strong>The Threat:</strong> Insecure Direct Object Reference (IDOR) exploitation and directory fuzzing where attackers crawl consecutive IDs: <code>/users/1 &rarr; /users/2 &rarr; /users/3</code>.<br>
              <strong>Why Static WAFs Fail:</strong> Each request looks like an ordinary, valid GET request.<br>
              <strong>Pygenic Arc Innovation:</strong> Tracks endpoint path sequence sliding windows. Detects constant delta progression $\forall i: |ID_{{i+1}} - ID_i| = 1$ and flags 404 error concentration across diverse resource paths.
            </p>
            <div class="sim-math-box">
              Detection Condition: Consecutive Step Progression (|ID_next - ID_prev| == 1) &ge; 3 steps &rarr; Risk = 0.94
            </div>
          </div>
          <div style="display: flex; flex-direction: column; justify-content: center; gap: 0.75rem;">
            <button class="btn-fire-sim" onclick="launchSimulatedIdor()">
              ⚡ Simulate IDOR Crawl
            </button>
            <span style="font-size: 0.75rem; color: var(--text-muted); text-align: center;">Walks /gateway/users/1..5 sequentially</span>
          </div>
        </div>
      </div>

      <!-- Simulator Tab 4: Abnormal Sequence -->
      <div id="sim-tab-sequence" class="sim-content-card" style="display: none;">
        <div class="sim-grid">
          <div class="sim-info-block">
            <h4>Markov State Transition Matrix Modeling</h4>
            <p>
              <strong>The Threat:</strong> Attackers or bots skipping business workflow steps, e.g. jumping straight to <code>POST /checkout</code> without browsing or adding items.<br>
              <strong>Why Static WAFs Fail:</strong> The checkout endpoint itself is completely legitimate; WAFs have no memory of prior session context.<br>
              <strong>Pygenic Arc Innovation:</strong> Trains a state transition probability matrix $P(s_{{t}} \mid s_{{t-1}})$. Transition <code>START &rarr; /checkout</code> has near-zero baseline probability ($P \le 0.001$), generating an anomaly score $> 0.85$ and blocking fraudulent completion.
            </p>
            <div class="sim-math-box">
              Sequence Anomaly: L_seq = - (1 / M) &Sigma; ln P(s_i | s_{{i-1}}) | Anomaly Score = min(1.0, (L_seq - 1.2) / 4.5)
            </div>
          </div>
          <div style="display: flex; flex-direction: column; justify-content: center; gap: 0.75rem;">
            <button class="btn-fire-sim" onclick="launchSimulatedSequenceBypass()">
              ⚡ Simulate Sequence Bypass
            </button>
            <span style="font-size: 0.75rem; color: var(--text-muted); text-align: center;">Attempts direct checkout without prior cart items</span>
          </div>
        </div>
      </div>

      <!-- Simulator Tab 5: Benign Flash Burst -->
      <div id="sim-tab-benign" class="sim-content-card" style="display: none;">
        <div class="sim-grid">
          <div class="sim-info-block">
            <h4>Legitimate High-Volume Traffic Discrimination</h4>
            <p>
              <strong>The Scenario:</strong> Legitimate shoppers rushing during a flash sale or product release.<br>
              <strong>The Problem with Static WAFs:</strong> Static rate limits block real paying customers with 429s, causing business revenue loss.<br>
              <strong>Pygenic Arc Solution:</strong> Differentiates benign bursts from bots by observing legal Markov workflow transitions (<code>/products &rarr; /cart/add &rarr; /checkout</code>) and natural human inter-arrival variance ($\sigma > 150\text{{ms}}$). Classified as <code>BENIGN_BURST</code> with risk score &lt; 0.15.
            </p>
            <div class="sim-math-box">
              Classification Rule: High RPS + Legal Sequence Navigation + High Timing Variance &rarr; ALLOWED (BENIGN_BURST)
            </div>
          </div>
          <div style="display: flex; flex-direction: column; justify-content: center; gap: 0.75rem;">
            <button class="btn-fire-sim btn-fire-benign" onclick="launchSimulatedBenignBurst()">
              ⚡ Simulate Legitimate Flash Burst
            </button>
            <span style="font-size: 0.75rem; color: var(--text-muted); text-align: center;">Simulates high-velocity valid human shopping sequence</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Live Telemetry Stream and Sidebar -->
    <div class="dashboard-layout">
      <!-- Live Traffic & Attack Feed -->
      <div class="stream-container">
        <div class="section-header">
          <div class="section-title">
            <span>🛡️ Live Behavioral Threat Stream</span>
            <span style="font-size: 0.75rem; color: var(--cyan-accent); font-family: var(--font-mono);">[AUTO-REFRESH 1.5s]</span>
          </div>
          <div style="display: flex; gap: 0.5rem;">
            <button onclick="clearAllBlocks()" class="unblock-btn" style="border-color: var(--red-alert); color: var(--red-alert);">Unblock All IPs</button>
            <button onclick="clearEventFeed()" class="unblock-btn">Clear Feed</button>
          </div>
        </div>
        <div class="table-responsive">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Client IP</th>
                <th>Target Endpoint</th>
                <th>Risk Score</th>
                <th>Detected Category</th>
                <th>Action</th>
                <th>Evidence Reason (Click Row to Inspect)</th>
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

      <!-- Sidebar: Active Enforcements & Kali Commands -->
      <div class="sidebar-panel">
        <!-- Active Enforcements Card -->
        <div class="block-card">
          <div class="section-header" style="padding: 0 0 1rem 0;">
            <h3 style="font-size: 1rem; font-weight: 700;">Active Enforcement Blocks</h3>
            <span id="active-block-count" class="badge badge-soft_block">0</span>
          </div>
          <div id="active-blocks-list" style="font-size: 0.85rem; font-family: var(--font-mono);">
            <div style="color: var(--text-muted); padding: 0.5rem 0;">No active IP blocks.</div>
          </div>
        </div>

        <!-- Kali Linux Attack Commands Drawer -->
        <div class="block-card">
          <h3 style="font-size: 1rem; font-weight: 700; margin-bottom: 0.25rem;">Kali Linux Terminal Attacks</h3>
          <p style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 1rem;">
            Run these exact commands in your Kali VM against <code>{host_ip}</code>:
          </p>

          <div>
            <span style="font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono);">1. Credential Stuffing (Spray):</span>
            <div class="kali-cmd-box">
              <button class="copy-chip" onclick="copyText('for p in pass1 pass2 pass3 pass4 pass5; do curl -X POST http://{host_ip}:8000/gateway/auth/login -H \\"Content-Type: application/json\\" -d \\"{{\\\\\\"username\\\\\\":\\\\\\"admin\\\\\\",\\\\\\"password\\\\\\":\\\\\\"$p\\\\\\"}}\\"; sleep 0.1; done')">Copy</button>
              <code>for p in pass1 pass2 pass3 pass4 pass5; do curl -X POST http://{host_ip}:8000/gateway/auth/login -d '{{"username":"admin","password":"$p"}}'; sleep 0.1; done</code>
            </div>
          </div>

          <div style="margin-top: 0.75rem;">
            <span style="font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono);">2. Machine Scraper (Timing Entropy):</span>
            <div class="kali-cmd-box">
              <button class="copy-chip" onclick="copyText('for i in $(seq 1 12); do curl -s http://{host_ip}:8000/gateway/products; sleep 0.08; done')">Copy</button>
              <code>for i in $(seq 1 12); do curl -s http://{host_ip}:8000/gateway/products; sleep 0.08; done</code>
            </div>
          </div>

          <div style="margin-top: 0.75rem;">
            <span style="font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono);">3. Sequential IDOR Enumeration:</span>
            <div class="kali-cmd-box">
              <button class="copy-chip" onclick="copyText('for id in $(seq 1 6); do curl -s http://{host_ip}:8000/gateway/users/$id; sleep 0.15; done')">Copy</button>
              <code>for id in $(seq 1 6); do curl -s http://{host_ip}:8000/gateway/users/$id; sleep 0.15; done</code>
            </div>
          </div>

          <div style="margin-top: 0.75rem;">
            <span style="font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono);">4. Sequence Workflow Bypass:</span>
            <div class="kali-cmd-box">
              <button class="copy-chip" onclick="copyText('curl -i -X POST http://{host_ip}:8000/gateway/checkout -H \\"Content-Type: application/json\\" -d \\"{{\\\\\\"payment_method\\\\\\":\\\\\\"card\\\\\\"}}\\"')">Copy</button>
              <code>curl -i -X POST http://{host_ip}:8000/gateway/checkout -d '{{"payment_method":"card"}}'</code>
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
          <h3 style="font-size: 1.25rem; font-weight: 800; color: #fff;">🔬 Threat Explainability & Evidence Inspector</h3>
          <span style="font-size: 0.8rem; color: var(--text-muted); font-family: var(--font-mono);">Deep architectural evidence attribution vector</span>
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
        <div style="font-size: 0.85rem; font-weight: 700; color: #fff; margin-bottom: 0.5rem;">Behavioral Rationale & Decision Explanation:</div>
        <div id="modal-event-explanation" style="background: rgba(0, 0, 0, 0.4); border-left: 3px solid var(--cyan-accent); padding: 0.75rem 1rem; border-radius: 4px; font-size: 0.85rem; color: var(--text-main); line-height: 1.5;">
          High-confidence threat detected [CREDENTIAL_STUFFING]. Automatic soft-block enforced with Retry-After.
        </div>
      </div>

      <div>
        <div style="font-size: 0.85rem; font-weight: 700; color: #fff; margin-bottom: 0.5rem;">Mathematical Evidence & Sliding Window Features:</div>
        <pre id="modal-event-evidence" style="background: #04060c; border: 1px solid var(--border-color); border-radius: 8px; padding: 1rem; font-family: var(--font-mono); font-size: 0.8rem; color: var(--cyan-accent); max-height: 180px; overflow-y: auto; white-space: pre-wrap;"></pre>
      </div>

      <div style="display: flex; justify-content: flex-end;">
        <button class="pill-link" onclick="closeInspectorModal()">Close Inspector</button>
      </div>
    </div>
  </div>

  <script>
    const HOST_IP = "{host_ip}";
    let currentEvents = [];

    // Auto-refresh loop
    document.addEventListener('DOMContentLoaded', () => {{
      fetchDashboardStats();
      setInterval(fetchDashboardStats, 1500);
    }});

    function switchSimTab(tab) {{
      const tabs = ['stuffing', 'scraping', 'idor', 'sequence', 'benign'];
      tabs.forEach(t => {{
        document.getElementById('sim-tab-' + t).style.display = (t === tab) ? 'block' : 'none';
      }});
      document.querySelectorAll('.sim-tab-btn').forEach((btn, idx) => {{
        btn.classList.toggle('active', tabs[idx] === tab);
      }});
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

        // Active Blocks List
        const blockList = document.getElementById('active-blocks-list');
        document.getElementById('active-block-count').innerText = data.active_blocks.length;

        if (data.active_blocks.length === 0) {{
          blockList.innerHTML = '<div style="color: var(--text-muted); padding: 0.5rem 0;">No active IP blocks.</div>';
        }} else {{
          blockList.innerHTML = data.active_blocks.map(b => `
            <div style="background: rgba(255, 51, 102, 0.1); border: 1px solid rgba(255, 51, 102, 0.3); border-radius: 8px; padding: 0.75rem; margin-bottom: 0.5rem;">
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="color: var(--red-alert); font-weight: 700;">${{b.ip}}</span>
                <span style="font-size: 0.75rem; color: var(--yellow-warn);">${{b.ttl}}s left</span>
              </div>
              <div style="font-size: 0.75rem; color: var(--text-muted); margin: 0.25rem 0;">Vector: ${{b.category}}</div>
              <button onclick="unblockSingleIp('${{b.ip}}')" class="unblock-btn" style="width: 100%; margin-top: 0.25rem;">Unblock IP</button>
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

    // Simulated Attacks triggered right inside the browser
    async function launchSimulatedStuffing() {{
      alert('🚀 Launching simulated credential spray: 5 rapid failed logins to /gateway/login...');
      for (let i = 1; i <= 5; i++) {{
        try {{
          await fetch('/gateway/login', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{ username: 'admin', password: 'bad_pass_' + i }})
          }});
        }} catch (e) {{}}
        await new Promise(r => setTimeout(r, 120));
      }}
      fetchDashboardStats();
    }}

    async function launchSimulatedScraping() {{
      alert('🚀 Launching simulated scraper: 10 rigid 40ms requests to /gateway/products...');
      for (let i = 1; i <= 10; i++) {{
        try {{ await fetch('/gateway/products'); }} catch (e) {{}}
        await new Promise(r => setTimeout(r, 40));
      }}
      fetchDashboardStats();
    }}

    async function launchSimulatedIdor() {{
      alert('🚀 Launching simulated IDOR crawl: Sequential walking /gateway/users/1..5...');
      for (let id = 1; id <= 5; id++) {{
        try {{ await fetch('/gateway/users/' + id); }} catch (e) {{}}
        await new Promise(r => setTimeout(r, 150));
      }}
      fetchDashboardStats();
    }}

    async function launchSimulatedSequenceBypass() {{
      alert('🚀 Launching simulated workflow bypass: Direct POST /gateway/checkout...');
      try {{
        await fetch('/gateway/checkout', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ payment_method: 'unauthorized_bypass' }})
        }});
      }} catch (e) {{}}
      fetchDashboardStats();
    }}

    async function launchSimulatedBenignBurst() {{
      alert('🚀 Simulating legitimate flash sale burst with human cognitive variance...');
      const flow = ['/gateway/products', '/gateway/products/101', '/gateway/cart/add', '/gateway/checkout'];
      for (const ep of flow) {{
        try {{
          if (ep === '/gateway/cart/add') {{
            await fetch(ep, {{ method: 'POST', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify({{ product_id: 101 }}) }});
          }} else if (ep === '/gateway/checkout') {{
            await fetch(ep, {{ method: 'POST', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify({{ payment_method: 'card' }}) }});
          }} else {{
            await fetch(ep);
          }}
        }} catch (e) {{}}
        await new Promise(r => setTimeout(r, 180 + Math.random() * 250));
      }}
      fetchDashboardStats();
    }}
  </script>
</body>
</html>
"""
    return HTMLResponse(content=html_content)
