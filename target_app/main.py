"""
VulnStore Upstream Application with Interactive Web Frontend (Port 8001)

Provides both REST APIs and a visual Web Frontend for mentors and evaluators.
Demonstrates vulnerabilities directly, and showcases protection when routed
through the Pygenic Arc Gateway (Port 8000).
"""

import time
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

app = FastAPI(
    title="VulnStore Upstream API",
    description="Business application protected by the API Gateway Behavioral Threat Engine",
    version="1.0.0",
)

# In-memory database
USERS_DB = {
    "admin": "admin123",
    "john_doe": "secret123",
    "alice": "alice2026",
    "bob": "builder99",
}

USER_PROFILES = {
    1: {"id": 1, "username": "admin", "role": "admin", "email": "admin@vulnstore.io", "api_key": "sec_adm_9941a", "balance": 9999.00},
    2: {"id": 2, "username": "john_doe", "role": "customer", "email": "john@example.com", "balance": 450.00},
    3: {"id": 3, "username": "alice", "role": "customer", "email": "alice@corp.net", "balance": 1280.50},
    4: {"id": 4, "username": "bob", "role": "customer", "email": "bob@contractor.org", "balance": 50.00},
    5: {"id": 5, "username": "sarah", "role": "auditor", "email": "sarah@audit.gov", "balance": 900.00},
}

PRODUCTS_DB = [
    {"id": 101, "name": "Quantum Shield Pro", "price": 299.99, "stock": 45, "category": "Security Hardware", "desc": "Hardware cryptographic token with anti-tamper mesh."},
    {"id": 102, "name": "Cyber Sentinel Hub", "price": 499.00, "stock": 12, "category": "Network Gateway", "desc": "Edge firewall controller with deep packet inspection."},
    {"id": 103, "name": "Zero-Day Analyzer", "price": 1250.00, "stock": 5, "category": "Threat Intel", "desc": "Heuristic binary disassembler and sandbox runtime."},
    {"id": 104, "name": "Encrypted Key Vault", "price": 89.50, "stock": 120, "category": "Access Control", "desc": "Air-gapped biometric hardware seed storage."},
    {"id": 105, "name": "Packet Sniffer Dongle", "price": 35.00, "stock": 200, "category": "Diagnostics", "desc": "USB 3.0 passive bus monitoring adapter."},
]

USER_CARTS: Dict[str, List[int]] = {}


class LoginRequest(BaseModel):
    username: str
    password: str


class CartItem(BaseModel):
    product_id: int
    quantity: int = 1


class CheckoutRequest(BaseModel):
    payment_method: str = "credit_card"


# ── REST API Endpoints ────────────────────────────────────────────────────────

@app.post("/login")
@app.post("/auth/login")
async def login(req: LoginRequest):
    stored_password = USERS_DB.get(req.username)
    if not stored_password or stored_password != req.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials supplied",
        )
    return {
        "message": "Login successful",
        "username": req.username,
        "token": f"jwt_mock_{req.username}_{int(time.time())}",
    }


@app.get("/products")
async def list_products():
    return {"total": len(PRODUCTS_DB), "products": PRODUCTS_DB}


@app.get("/products/{product_id}")
async def get_product(product_id: int):
    for p in PRODUCTS_DB:
        if p["id"] == product_id:
            return p
    raise HTTPException(status_code=404, detail="Product not found")


@app.get("/users/{user_id}")
async def get_user_profile(user_id: int):
    profile = USER_PROFILES.get(user_id)
    if not profile:
        raise HTTPException(status_code=404, detail=f"User ID {user_id} not found")
    return profile


@app.post("/cart/add")
async def add_to_cart(item: CartItem, request: Request):
    client_id = request.headers.get("X-Client-ID", "anonymous")
    if client_id not in USER_CARTS:
        USER_CARTS[client_id] = []
    USER_CARTS[client_id].append(item.product_id)
    return {"message": "Item added to cart", "cart_items": USER_CARTS[client_id]}


@app.get("/cart")
async def view_cart(request: Request):
    client_id = request.headers.get("X-Client-ID", "anonymous")
    items = USER_CARTS.get(client_id, [])
    return {"cart_items": items, "count": len(items)}


@app.post("/checkout")
async def checkout(req: CheckoutRequest, request: Request):
    client_id = request.headers.get("X-Client-ID", "anonymous")
    items = USER_CARTS.get(client_id, [])
    return {
        "order_status": "COMPLETED",
        "order_id": f"ORD_{int(time.time() * 1000)}",
        "items_charged": items,
        "payment": req.payment_method,
        "warning": "Warning: Order placed directly without cart validation" if not items else "Valid checkout flow",
    }


# ── Interactive Web UI ────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def store_web_ui(request: Request):
    host = request.headers.get("host", "localhost:8001")
    host_ip = host.split(":")[0]

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VulnStore | Target Upstream Application</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Outfit:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg-base: #0b0f19;
      --bg-surface: #131a2b;
      --bg-card: rgba(22, 31, 51, 0.8);
      --border-color: rgba(255, 255, 255, 0.08);
      --accent-purple: #7928ca;
      --accent-blue: #0070f3;
      --accent-cyan: #00f0ff;
      --accent-pink: #ff0080;
      --green-safe: #00e676;
      --text-main: #f0f4fc;
      --text-muted: #8a99b5;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: var(--bg-base);
      color: var(--text-main);
      font-family: 'Outfit', sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }}
    header {{
      background: rgba(19, 26, 43, 0.9);
      backdrop-filter: blur(10px);
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
      gap: 0.8rem;
    }}
    .badge-store {{
      background: linear-gradient(135deg, var(--accent-purple), var(--accent-pink));
      padding: 0.35rem 0.75rem;
      border-radius: 6px;
      font-weight: 800;
      font-size: 1rem;
    }}
    .header-links {{
      display: flex;
      gap: 1rem;
      align-items: center;
    }}
    .btn-link {{
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border-color);
      color: var(--text-main);
      padding: 0.4rem 0.85rem;
      border-radius: 20px;
      text-decoration: none;
      font-size: 0.85rem;
      font-family: 'JetBrains Mono', monospace;
      transition: all 0.2s;
    }}
    .btn-link:hover {{
      border-color: var(--accent-cyan);
      color: var(--accent-cyan);
    }}
    .alert-banner {{
      background: rgba(255, 51, 102, 0.1);
      border-bottom: 1px solid rgba(255, 51, 102, 0.3);
      padding: 0.75rem 2rem;
      font-size: 0.85rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }}

    main {{
      max-width: 1300px;
      margin: 0 auto;
      padding: 2rem;
      width: 100%;
      flex: 1;
      display: flex;
      flex-direction: column;
      gap: 2rem;
    }}

    /* Section Tabs */
    .tabs-nav {{
      display: flex;
      gap: 1rem;
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 0.5rem;
    }}
    .tab-btn {{
      background: none;
      border: none;
      color: var(--text-muted);
      font-size: 1rem;
      font-weight: 600;
      padding: 0.5rem 1rem;
      cursor: pointer;
      border-radius: 6px;
      transition: all 0.2s;
    }}
    .tab-btn.active {{
      background: rgba(255, 255, 255, 0.08);
      color: #fff;
    }}

    /* Catalog Grid */
    .product-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
      gap: 1.5rem;
    }}
    .product-card {{
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 1.5rem;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 1rem;
      transition: transform 0.2s, border-color 0.2s;
    }}
    .product-card:hover {{
      transform: translateY(-3px);
      border-color: var(--accent-cyan);
    }}
    .product-category {{
      font-size: 0.75rem;
      color: var(--accent-cyan);
      text-transform: uppercase;
      font-family: 'JetBrains Mono', monospace;
      letter-spacing: 0.5px;
    }}
    .product-title {{
      font-size: 1.2rem;
      font-weight: 700;
    }}
    .product-desc {{
      font-size: 0.85rem;
      color: var(--text-muted);
      line-height: 1.4;
    }}
    .price-row {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-top: 0.5rem;
    }}
    .product-price {{
      font-size: 1.3rem;
      font-weight: 800;
      font-family: 'JetBrains Mono', monospace;
      color: var(--green-safe);
    }}
    .btn-action {{
      background: var(--accent-blue);
      color: #fff;
      border: none;
      padding: 0.5rem 1rem;
      border-radius: 6px;
      font-weight: 600;
      cursor: pointer;
      transition: opacity 0.2s;
    }}
    .btn-action:hover {{ opacity: 0.85; }}

    /* IDOR Explorer Panel */
    .idor-panel {{
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 1.5rem;
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }}
    .idor-controls {{
      display: flex;
      gap: 0.5rem;
      align-items: center;
    }}
    .id-btn {{
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border-color);
      color: #fff;
      padding: 0.4rem 0.8rem;
      border-radius: 6px;
      cursor: pointer;
      font-family: 'JetBrains Mono', monospace;
    }}
    .id-btn:hover {{ border-color: var(--accent-cyan); color: var(--accent-cyan); }}
    .json-display {{
      background: #060910;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 1rem;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.85rem;
      color: #00f0ff;
      white-space: pre-wrap;
      max-height: 250px;
      overflow-y: auto;
    }}
  </style>
</head>
<body>

  <header>
    <div class="brand">
      <div class="badge-store">VulnStore</div>
      <div>
        <h1 style="font-size: 1.15rem; font-weight: 700;">Target E-Commerce Service</h1>
        <span style="font-size: 0.8rem; color: var(--text-muted); font-family: 'JetBrains Mono', monospace;">Port 8001 &bull; Upstream Application</span>
      </div>
    </div>
    <div class="header-links">
      <a href="http://{host_ip}:8000/" target="_blank" class="btn-link" style="border-color: var(--accent-cyan); color: var(--accent-cyan);">
        🛡️ Open Gateway SOC Dashboard (:8000)
      </a>
      <a href="http://{host_ip}:8001/docs" target="_blank" class="btn-link">
        📖 Target Swagger (:8001)
      </a>
      <span class="btn-link" style="color: var(--green-safe);">
        🛒 Cart: <span id="cart-counter">0</span>
      </span>
    </div>
  </header>

  <div class="alert-banner">
    <div>
      <strong style="color: #ff3366;">⚠️ DIRECT UNPROTECTED MODE:</strong>
      You are viewing the raw target backend at <code>:8001</code>. It lacks rate limits, IDOR controls, and sequence models.
    </div>
    <div>
      <a href="http://{host_ip}:8000/gateway/products" target="_blank" style="color: var(--accent-cyan); text-decoration: none; font-weight: 600;">
        Test via Protected Gateway (:8000/gateway) &rarr;
      </a>
    </div>
  </div>

  <main>
    <div class="tabs-nav">
      <button class="tab-btn active" onclick="switchTab('catalog')">📦 Product Catalog (Scraping Target)</button>
      <button class="tab-btn" onclick="switchTab('idor')">🔍 IDOR User Profiles (/users/{{id}})</button>
      <button class="tab-btn" onclick="switchTab('checkout')">⚡ Direct Checkout (Sequence Bypass)</button>
    </div>

    <!-- Tab 1: Catalog -->
    <div id="tab-catalog">
      <div class="product-grid">
        {"".join([f'''
        <div class="product-card">
          <div>
            <div class="product-category">{p["category"]}</div>
            <div class="product-title">{p["name"]}</div>
            <p class="product-desc">{p["desc"]}</p>
          </div>
          <div class="price-row">
            <div class="product-price">${p["price"]}</div>
            <button class="btn-action" onclick="addToCart({p["id"]})">Add to Cart</button>
          </div>
        </div>
        ''' for p in PRODUCTS_DB])}
      </div>
    </div>

    <!-- Tab 2: IDOR Explorer -->
    <div id="tab-idor" style="display: none;">
      <div class="idor-panel">
        <h3 style="font-size: 1.1rem; font-weight: 700;">IDOR / Sequential Profile Inspector</h3>
        <p style="font-size: 0.85rem; color: var(--text-muted);">
          Select a user ID to inspect confidential account details. Notice how unrestricted access exposes admin keys and customer balances:
        </p>
        <div class="idor-controls">
          <span style="font-size: 0.85rem; font-family: 'JetBrains Mono', monospace;">Select ID:</span>
          <button class="id-btn" onclick="fetchUserProfile(1)">ID 1 (Admin)</button>
          <button class="id-btn" onclick="fetchUserProfile(2)">ID 2 (John)</button>
          <button class="id-btn" onclick="fetchUserProfile(3)">ID 3 (Alice)</button>
          <button class="id-btn" onclick="fetchUserProfile(4)">ID 4 (Bob)</button>
          <button class="id-btn" onclick="fetchUserProfile(5)">ID 5 (Sarah)</button>
          <button class="id-btn" onclick="fetchUserProfile(6)">ID 6 (404 Test)</button>
        </div>
        <div class="json-display" id="user-json-viewer">// Click a user ID above to fetch raw account data...</div>
      </div>
    </div>

    <!-- Tab 3: Sequence Bypass -->
    <div id="tab-checkout" style="display: none;">
      <div class="idor-panel">
        <h3 style="font-size: 1.1rem; font-weight: 700;">Workflow Sequence Bypass Demo</h3>
        <p style="font-size: 0.85rem; color: var(--text-muted);">
          In standard applications, users must navigate: <code>Login &rarr; Catalog &rarr; Add Cart &rarr; Checkout</code>.<br>
          Clicking the button below directly triggers <code>POST /checkout</code> without adding items to cart.
        </p>
        <div>
          <button class="btn-action" style="background: #ff0080;" onclick="triggerDirectCheckout()">
            ⚡ Fire Direct POST /checkout (State Skip)
          </button>
        </div>
        <div class="json-display" id="checkout-result-viewer">// Awaiting direct checkout execution...</div>
      </div>
    </div>
  </main>

  <script>
    let cartCount = 0;

    function switchTab(name) {{
      document.getElementById('tab-catalog').style.display = name === 'catalog' ? 'block' : 'none';
      document.getElementById('tab-idor').style.display = name === 'idor' ? 'block' : 'none';
      document.getElementById('tab-checkout').style.display = name === 'checkout' ? 'block' : 'none';

      document.querySelectorAll('.tab-btn').forEach((btn, idx) => {{
        btn.classList.toggle('active', (name === 'catalog' && idx === 0) || (name === 'idor' && idx === 1) || (name === 'checkout' && idx === 2));
      }});
    }}

    async function addToCart(id) {{
      cartCount++;
      document.getElementById('cart-counter').innerText = cartCount;
      await fetch('/cart/add', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ product_id: id, quantity: 1 }})
      }});
    }}

    async function fetchUserProfile(id) {{
      const viewer = document.getElementById('user-json-viewer');
      viewer.innerText = 'Fetching /users/' + id + '...';
      try {{
        const res = await fetch('/users/' + id);
        const data = await res.json();
        viewer.innerText = JSON.stringify(data, null, 2);
      }} catch (err) {{
        viewer.innerText = 'Error: ' + err;
      }}
    }}

    async function triggerDirectCheckout() {{
      const viewer = document.getElementById('checkout-result-viewer');
      viewer.innerText = 'Triggering direct POST /checkout...';
      try {{
        const res = await fetch('/checkout', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ payment_method: 'credit_card' }})
        }});
        const data = await res.json();
        viewer.innerText = JSON.stringify(data, null, 2);
      }} catch (err) {{
        viewer.innerText = 'Error: ' + err;
      }}
    }}
  </script>
</body>
</html>
"""
    return HTMLResponse(content=html)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
