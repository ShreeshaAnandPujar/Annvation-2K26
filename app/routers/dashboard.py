"""
Cyber Threat Intelligence & Gateway Security Dashboard (Team Rudranix)
Serves the live interactive Web UI for Hackathon mentors and evaluators.
"""

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


@router.get("/dashboard", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    """
    Renders the live Cybersecurity Threat Intelligence Dashboard.
    """
    host = request.headers.get("host", "localhost:8000")
    host_ip = host.split(":")[0]

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Pygenic Arc | Cyber Threat Gateway Dashboard</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Outfit:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg-base: #07090e;
      --bg-surface: #0e131f;
      --bg-card: rgba(18, 24, 38, 0.7);
      --border-color: rgba(255, 255, 255, 0.08);
      --border-focus: rgba(0, 240, 255, 0.4);
      --cyan-accent: #00f0ff;
      --cyan-glow: rgba(0, 240, 255, 0.25);
      --red-alert: #ff3366;
      --red-glow: rgba(255, 51, 102, 0.25);
      --yellow-warn: #ffb800;
      --green-safe: #00e676;
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
      background: rgba(14, 19, 31, 0.85);
      backdrop-filter: blur(12px);
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
      background: linear-gradient(135deg, var(--cyan-accent), #7928ca);
      color: #000;
      font-weight: 800;
      font-size: 1.1rem;
      padding: 0.35rem 0.75rem;
      border-radius: 6px;
      letter-spacing: 0.5px;
    }}
    .brand h1 {{
      font-size: 1.25rem;
      font-weight: 700;
      letter-spacing: -0.5px;
    }}
    .brand span {{
      color: var(--text-muted);
      font-size: 0.85rem;
      margin-left: 0.5rem;
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
      padding: 0.4rem 0.85rem;
      border-radius: 20px;
      text-decoration: none;
      font-size: 0.85rem;
      font-family: var(--font-mono);
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      gap: 0.4rem;
    }}
    .pill-link:hover {{
      border-color: var(--cyan-accent);
      background: var(--cyan-glow);
      color: var(--cyan-accent);
    }}
    .status-pulse {{
      display: inline-block;
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--green-safe);
      box-shadow: 0 0 10px var(--green-safe);
      animation: pulse 2s infinite;
    }}
    @keyframes pulse {{
      0% {{ transform: scale(0.95); opacity: 0.8; }}
      50% {{ transform: scale(1.2); opacity: 1; }}
      100% {{ transform: scale(0.95); opacity: 0.8; }}
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

    /* Metric Cards */
    .metrics-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 1.25rem;
    }}
    .card {{
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 1.5rem;
      backdrop-filter: blur(8px);
      position: relative;
      overflow: hidden;
      transition: transform 0.2s ease, border-color 0.2s ease;
    }}
    .card:hover {{
      transform: translateY(-2px);
      border-color: rgba(255, 255, 255, 0.15);
    }}
    .card::before {{
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0; height: 2px;
      background: var(--card-accent, var(--cyan-accent));
    }}
    .card-label {{
      font-size: 0.85rem;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: var(--text-muted);
      margin-bottom: 0.5rem;
    }}
    .card-value {{
      font-size: 2.25rem;
      font-weight: 800;
      font-family: var(--font-mono);
      display: flex;
      align-items: baseline;
      gap: 0.5rem;
    }}
    .card-subtext {{
      font-size: 0.8rem;
      color: var(--text-muted);
      margin-top: 0.5rem;
    }}

    /* Layout Split */
    .dashboard-layout {{
      display: grid;
      grid-template-columns: 2.5fr 1fr;
      gap: 1.5rem;
    }}

    /* Table & Panels */
    .section-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
    }}
    .section-title {{
      font-size: 1.2rem;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 0.6rem;
    }}
    .stream-container {{
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      overflow: hidden;
      display: flex;
      flex-direction: column;
    }}
    .table-responsive {{
      overflow-x: auto;
      max-height: 520px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 0.9rem;
    }}
    thead {{
      background: rgba(0, 0, 0, 0.3);
      position: sticky;
      top: 0;
      z-index: 10;
      border-bottom: 1px solid var(--border-color);
    }}
    th {{
      padding: 0.85rem 1rem;
      font-family: var(--font-mono);
      font-weight: 600;
      font-size: 0.8rem;
      color: var(--text-muted);
      text-transform: uppercase;
    }}
    td {{
      padding: 0.9rem 1rem;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      font-family: var(--font-mono);
      font-size: 0.85rem;
    }}
    tbody tr:hover {{
      background: rgba(255, 255, 255, 0.02);
    }}

    /* Badges */
    .badge {{
      display: inline-block;
      padding: 0.25rem 0.6rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      font-family: var(--font-mono);
    }}
    .badge-soft_block {{ background: rgba(255, 51, 102, 0.15); color: var(--red-alert); border: 1px solid var(--red-alert); }}
    .badge-throttled  {{ background: rgba(255, 184, 0, 0.15); color: var(--yellow-warn); border: 1px solid var(--yellow-warn); }}
    .badge-allowed    {{ background: rgba(0, 230, 118, 0.15); color: var(--green-safe); border: 1px solid var(--green-safe); }}

    .cat-stuffing   {{ color: #ff3366; }}
    .cat-scraping   {{ color: #ff9100; }}
    .cat-enumeration {{ color: #d500f9; }}
    .cat-sequence   {{ color: #ffd600; }}
    .cat-benign     {{ color: #00e676; }}

    /* Risk Score Gauge Mini */
    .score-container {{
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}
    .score-bar-bg {{
      width: 60px;
      height: 6px;
      background: rgba(255, 255, 255, 0.1);
      border-radius: 3px;
      overflow: hidden;
    }}
    .score-bar-fill {{
      height: 100%;
      border-radius: 3px;
    }}

    /* Sidebar info */
    .sidebar-panel {{
      display: flex;
      flex-direction: column;
      gap: 1.5rem;
    }}
    .block-card {{
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 1.25rem;
    }}
    .active-ip-item {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 0.6rem 0;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }}
    .unblock-btn {{
      background: transparent;
      border: 1px solid rgba(255, 255, 255, 0.2);
      color: var(--text-muted);
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-size: 0.75rem;
      cursor: pointer;
      font-family: var(--font-mono);
      transition: all 0.2s;
    }}
    .unblock-btn:hover {{
      border-color: var(--cyan-accent);
      color: var(--cyan-accent);
    }}

    /* Kali Helper Box */
    .kali-box {{
      background: #05070a;
      border: 1px dashed var(--border-color);
      border-radius: 10px;
      padding: 1rem;
      font-family: var(--font-mono);
      font-size: 0.8rem;
    }}
    .kali-cmd {{
      background: #111520;
      padding: 0.5rem;
      border-radius: 6px;
      color: var(--cyan-accent);
      margin: 0.5rem 0;
      word-break: break-all;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }}
    .copy-btn {{
      background: rgba(255,255,255,0.1);
      border: none;
      color: #fff;
      padding: 0.2rem 0.4rem;
      border-radius: 4px;
      cursor: pointer;
      font-size: 0.7rem;
    }}

    /* Evidence detail modal/accordion */
    .expand-row {{
      cursor: pointer;
    }}
    .evidence-box {{
      background: rgba(0, 0, 0, 0.3);
      padding: 0.75rem;
      font-size: 0.8rem;
      color: var(--text-muted);
      border-left: 2px solid var(--cyan-accent);
      margin: 0.25rem 0;
    }}
  </style>
</head>
<body>

  <header>
    <div class="brand">
      <div class="logo-badge">PYGENIC ARC</div>
      <div>
        <h1>API Abuse & Behavioral Threat Gateway</h1>
        <span>Team Rudranix &bull; Annvation-2K26</span>
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
        <div class="card-subtext">Real-time deep behavioral inspection</div>
      </div>
      <div class="card" style="--card-accent: var(--red-alert);">
        <div class="card-label">Attacks Blocked (429 / 403)</div>
        <div class="card-value" style="color: var(--red-alert);" id="val-blocked">0</div>
        <div class="card-subtext">Auto-isolated by Behavioral Engine</div>
      </div>
      <div class="card" style="--card-accent: var(--yellow-warn);">
        <div class="card-label">Throttled Requests</div>
        <div class="card-value" style="color: var(--yellow-warn);" id="val-throttled">0</div>
        <div class="card-subtext">Suppressed with adaptive Retry-After delay</div>
      </div>
      <div class="card" style="--card-accent: var(--green-safe);">
        <div class="card-label">Active Threat Level</div>
        <div class="card-value" style="color: var(--green-safe);" id="val-threat-level">MONITORING</div>
        <div class="card-subtext">Markov Sequence Model Active</div>
      </div>
    </div>

    <div class="dashboard-layout">
      <!-- Live Traffic & Attack Feed -->
      <div class="stream-container">
        <div class="section-header" style="padding: 1.25rem 1.25rem 0 1.25rem;">
          <div class="section-title">
            <span>🛡️ Live Behavioral Threat Stream</span>
            <span style="font-size: 0.75rem; color: var(--cyan-accent); font-family: var(--font-mono);">[LIVE AUTO-UPDATE 1.5s]</span>
          </div>
          <div>
            <button onclick="clearAllBlocks()" class="unblock-btn" style="border-color: var(--red-alert); color: var(--red-alert);">Clear All Blocks</button>
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
                <th>Action</th>
                <th>Key Evidence</th>
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

      <!-- Sidebar: Active Enforcements & Kali Help -->
      <div class="sidebar-panel">
        <!-- Active Blocks -->
        <div class="block-card">
          <div class="section-header">
            <h3 style="font-size: 1rem; font-weight: 700;">Active IP Blocks</h3>
            <span id="active-block-count" class="badge badge-soft_block">0</span>
          </div>
          <div id="active-blocks-list" style="font-size: 0.85rem; font-family: var(--font-mono);">
            <div style="color: var(--text-muted); padding: 0.5rem 0;">No IPs currently blocked.</div>
          </div>
        </div>

        <!-- Kali Linux Attack Commands Drawer -->
        <div class="block-card">
          <h3 style="font-size: 1rem; font-weight: 700; margin-bottom: 0.5rem;">Kali Linux Attack Console</h3>
          <p style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 1rem;">
            Run these exact commands in your Kali VM terminal to attack:
          </p>

          <div class="kali-box">
            <div style="color: var(--text-muted); font-size: 0.75rem;">1. CREDENTIAL STUFFING (Hydra/Curl):</div>
            <div class="kali-cmd">
              <span>curl -X POST http://{host_ip}:8000/gateway/auth/login -d '{{"username":"admin","password":"123"}}'</span>
            </div>

            <div style="color: var(--text-muted); font-size: 0.75rem; margin-top: 0.5rem;">2. SCRAPING BOT (Zero Variance):</div>
            <div class="kali-cmd">
              <span>for i in {{1..15}}; do curl -s http://{host_ip}:8000/gateway/products; sleep 0.1; done</span>
            </div>

            <div style="color: var(--text-muted); font-size: 0.75rem; margin-top: 0.5rem;">3. IDOR ENUMERATION:</div>
            <div class="kali-cmd">
              <span>for id in {{1..6}}; do curl -s http://{host_ip}:8000/gateway/users/$id; sleep 0.2; done</span>
            </div>

            <div style="color: var(--text-muted); font-size: 0.75rem; margin-top: 0.5rem;">4. WORKFLOW BYPASS (Direct Checkout):</div>
            <div class="kali-cmd">
              <span>curl -X POST http://{host_ip}:8000/gateway/checkout</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </main>

  <script>
    async function fetchStats() {{
      try {{
        const res = await fetch('/api/dashboard-stats');
        const data = await res.json();

        // Update Counter Cards
        document.getElementById('val-total-requests').innerText = data.total_requests;
        document.getElementById('val-blocked').innerText = data.total_blocked;
        document.getElementById('val-throttled').innerText = data.total_throttled;

        if (data.total_blocked > 0) {{
          document.getElementById('val-threat-level').innerText = 'ELEVATED / DEFENDING';
          document.getElementById('val-threat-level').style.color = 'var(--red-alert)';
        }} else {{
          document.getElementById('val-threat-level').innerText = 'MONITORING';
          document.getElementById('val-threat-level').style.color = 'var(--green-safe)';
        }}

        // Update Active Blocks
        const blockContainer = document.getElementById('active-blocks-list');
        document.getElementById('active-block-count').innerText = data.active_blocks.length;
        if (data.active_blocks.length === 0) {{
          blockContainer.innerHTML = '<div style="color: var(--text-muted); padding: 0.5rem 0;">No IPs currently blocked.</div>';
        }} else {{
          blockContainer.innerHTML = data.active_blocks.map(b => `
            <div class="active-ip-item">
              <div>
                <strong style="color: var(--red-alert);">${{b.ip}}</strong>
                <div style="font-size: 0.7rem; color: var(--text-muted);">${{b.category}} (TTL: ${{b.ttl}}s)</div>
              </div>
              <button onclick="unblockIp('${{b.ip}}')" class="unblock-btn">Unblock</button>
            </div>
          `).join('');
        }}

        // Update Live Stream Table
        const tbody = document.getElementById('stream-tbody');
        if (data.recent_events && data.recent_events.length > 0) {{
          tbody.innerHTML = data.recent_events.map(ev => {{
            const v = ev.verdict;
            const score = v.risk_score;
            let scoreColor = 'var(--green-safe)';
            if (score >= 0.7) scoreColor = 'var(--red-alert)';
            else if (score >= 0.4) scoreColor = 'var(--yellow-warn)';

            let actionBadge = 'badge-allowed';
            if (v.action === 'SOFT_BLOCK' || v.action === 'HARD_BLOCK') actionBadge = 'badge-soft_block';
            else if (v.action === 'THROTTLED') actionBadge = 'badge-throttled';

            const evidenceFirst = v.evidence && v.evidence.reasons ? v.evidence.reasons[0] : v.explanation;

            return `
              <tr class="expand-row">
                <td style="color: var(--text-muted);">${{ev.time_str}}</td>
                <td style="color: var(--cyan-accent); font-weight: 600;">${{ev.client_ip}}</td>
                <td style="color: #fff;">${{ev.path}}</td>
                <td>
                  <div class="score-container">
                    <span style="color: ${{scoreColor}}; font-weight: 700;">${{score.toFixed(2)}}</span>
                    <div class="score-bar-bg">
                      <div class="score-bar-fill" style="width: ${{Math.min(100, score * 100)}}%; background: ${{scoreColor}};"></div>
                    </div>
                  </div>
                </td>
                <td class="cat-${{v.behaviour_category.toLowerCase().split('_')[0]}}" style="font-weight: 700;">
                  ${{v.behaviour_category}}
                </td>
                <td>
                  <span class="badge ${{actionBadge}}">${{v.action}}</span>
                </td>
                <td style="color: var(--text-muted); max-width: 250px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${{evidenceFirst}}">
                  ${{evidenceFirst}}
                </td>
              </tr>
            `;
          }}).join('');
        }}
      }} catch (err) {{
        console.error("Dashboard poll error:", err);
      }}
    }}

    async function unblockIp(ip) {{
      await fetch('/api/unblock-ip', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ ip: ip }})
      }});
      fetchStats();
    }}

    async function clearAllBlocks() {{
      await fetch('/api/clear-all-blocks', {{ method: 'POST' }});
      fetchStats();
    }}

    // Poll every 1.5s
    setInterval(fetchStats, 1500);
    fetchStats();
  </script>
</body>
</html>
"""
    return HTMLResponse(content=html_content)
