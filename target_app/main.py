"""
VulnStore — Target Upstream Application & Interactive Vulnerability Lab (Port 8001)
Team Rudranix | Pygenic Arc (Annvation-2K26)

A fully functional e-commerce service designed for evaluating API abuse and behavioral defenses.
Provides a rich interactive web frontend with full shopping cart, orders, user authentication,
product filtering, IDOR exploration, and an in-depth Educational Simulation Guide.
"""

import time
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

app = FastAPI(
    title="VulnStore Target Upstream Application",
    description="E-Commerce business microservice protected by Pygenic Arc API Gateway",
    version="2.0.0",
)

# ── In-Memory Database ────────────────────────────────────────────────────────

USERS_DB = {
    "admin": "admin123",
    "john_doe": "secret123",
    "alice": "alice2026",
    "bob": "builder99",
}

USER_PROFILES: Dict[int, Dict[str, Any]] = {
    1: {
        "id": 1,
        "username": "admin",
        "role": "SuperAdmin",
        "full_name": "System Administrator",
        "email": "admin@vulnstore.internal",
        "api_key": "sec_key_live_9941a80c92",
        "balance": 9999.00,
        "phone": "+1 (555) 019-2834",
    },
    2: {
        "id": 2,
        "username": "john_doe",
        "role": "Customer",
        "full_name": "Johnathan Doe",
        "email": "john.doe@cybercorp.net",
        "api_key": "sec_key_live_1094f72b11",
        "balance": 450.00,
        "phone": "+1 (555) 012-4829",
    },
    3: {
        "id": 3,
        "username": "alice",
        "role": "Customer",
        "full_name": "Alice Vance",
        "email": "alice.vance@blackmesa.org",
        "api_key": "sec_key_live_8820c43d99",
        "balance": 1280.50,
        "phone": "+1 (555) 018-7731",
    },
    4: {
        "id": 4,
        "username": "bob",
        "role": "Customer",
        "full_name": "Robert Builder",
        "email": "bob@construction-tech.io",
        "api_key": "sec_key_live_3311e98a02",
        "balance": 50.00,
        "phone": "+1 (555) 014-9920",
    },
    5: {
        "id": 5,
        "username": "sarah",
        "role": "Auditor",
        "full_name": "Sarah Connor",
        "email": "sarah.connor@defense.gov",
        "api_key": "sec_key_live_7719a00b14",
        "balance": 900.00,
        "phone": "+1 (555) 011-8833",
    },
}

PRODUCTS_DB = [
    {
        "id": 101,
        "name": "Quantum Shield Pro HSM",
        "category": "Security Hardware",
        "price": 299.99,
        "stock": 45,
        "rating": 4.9,
        "icon": "🛡️",
        "desc": "Air-gapped hardware security module with anti-tamper mesh, physical cryptographic seed storage, and side-channel shielding.",
    },
    {
        "id": 102,
        "name": "Cyber Sentinel Edge Gateway",
        "category": "Network Gateway",
        "price": 499.00,
        "stock": 12,
        "rating": 4.8,
        "icon": "🌐",
        "desc": "High-throughput 10Gbps edge security firewall controller featuring zero-latency packet scrubbing and threat classification.",
    },
    {
        "id": 103,
        "name": "Zero-Day Heuristic Sandbox",
        "category": "Threat Intel",
        "price": 1250.00,
        "stock": 5,
        "rating": 5.0,
        "icon": "🔬",
        "desc": "Autonomous virtualized detonation chamber with static and dynamic binary analysis for previously unseen zero-day exploits.",
    },
    {
        "id": 104,
        "name": "Encrypted Biometric Key Vault",
        "category": "Access Control",
        "price": 89.50,
        "stock": 120,
        "rating": 4.7,
        "icon": "🔑",
        "desc": "FIPS 140-3 Level 4 certified dual-factor biometric access token with self-wiping physical flash storage.",
    },
    {
        "id": 105,
        "name": "Gigabit Passive Bus Sniffer",
        "category": "Diagnostics",
        "price": 35.00,
        "stock": 200,
        "rating": 4.6,
        "icon": "🔌",
        "desc": "USB 3.2 passive Ethernet bus monitoring adapter with inline packet capture and high-resolution timing extraction.",
    },
    {
        "id": 106,
        "name": "Neural HoneyPot Controller",
        "category": "Threat Intel",
        "price": 850.00,
        "stock": 18,
        "rating": 4.9,
        "icon": "🕸️",
        "desc": "Deceptive reconnaissance decoy platform mimicking enterprise cloud topologies to study active advanced persistent threats.",
    },
]

USER_CARTS: Dict[str, List[Dict[str, Any]]] = {}
USER_ORDERS: Dict[str, List[Dict[str, Any]]] = {}

# ── Schemas ───────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str

class CartItemRequest(BaseModel):
    product_id: int
    quantity: int = 1

class CheckoutRequest(BaseModel):
    payment_method: str = "credit_card"
    shipping_address: Optional[str] = "104 Silicon Valley Way, Suite 400"

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
    # Find profile if exists
    profile = next((p for p in USER_PROFILES.values() if p["username"] == req.username), None)
    return {
        "message": "Login successful",
        "username": req.username,
        "role": profile["role"] if profile else "Customer",
        "balance": profile["balance"] if profile else 100.0,
        "token": f"jwt_mock_{req.username}_{int(time.time())}",
    }


@app.get("/products")
async def list_products(category: Optional[str] = None, search: Optional[str] = None):
    results = PRODUCTS_DB
    if category and category != "All":
        results = [p for p in results if p["category"].lower() == category.lower()]
    if search:
        s = search.lower()
        results = [p for p in results if s in p["name"].lower() or s in p["desc"].lower()]
    return {"total": len(results), "products": results}


@app.get("/products/{product_id}")
async def get_product(product_id: int):
    for p in PRODUCTS_DB:
        if p["id"] == product_id:
            return p
    raise HTTPException(status_code=404, detail=f"Product with ID {product_id} not found")


@app.get("/users/{user_id}")
async def get_user_profile(user_id: int):
    profile = USER_PROFILES.get(user_id)
    if not profile:
        raise HTTPException(
            status_code=404,
            detail=f"User ID {user_id} not found in database",
        )
    return profile


@app.post("/cart/add")
async def add_to_cart(item: CartItemRequest, request: Request):
    client_id = request.headers.get("X-Client-ID", "web_client")
    product = next((p for p in PRODUCTS_DB if p["id"] == item.product_id), None)
    if not product:
        raise HTTPException(status_code=404, detail="Product does not exist")

    if client_id not in USER_CARTS:
        USER_CARTS[client_id] = []

    # Check if item already in cart
    existing = next((i for i in USER_CARTS[client_id] if i["id"] == item.product_id), None)
    if existing:
        existing["quantity"] += item.quantity
    else:
        USER_CARTS[client_id].append({
            "id": product["id"],
            "name": product["name"],
            "price": product["price"],
            "category": product["category"],
            "icon": product["icon"],
            "quantity": item.quantity,
        })

    total_items = sum(i["quantity"] for i in USER_CARTS[client_id])
    return {
        "message": f"Added '{product['name']}' to cart",
        "cart_items": USER_CARTS[client_id],
        "cart_count": total_items,
    }


@app.post("/cart/remove")
async def remove_from_cart(item: CartItemRequest, request: Request):
    client_id = request.headers.get("X-Client-ID", "web_client")
    if client_id in USER_CARTS:
        USER_CARTS[client_id] = [i for i in USER_CARTS[client_id] if i["id"] != item.product_id]
    total_items = sum(i["quantity"] for i in USER_CARTS.get(client_id, []))
    return {"message": "Item removed", "cart_count": total_items, "cart_items": USER_CARTS.get(client_id, [])}


@app.post("/cart/clear")
async def clear_cart(request: Request):
    client_id = request.headers.get("X-Client-ID", "web_client")
    if client_id in USER_CARTS:
        USER_CARTS[client_id] = []
    return {"message": "Cart cleared", "cart_count": 0, "cart_items": []}


@app.get("/cart")
async def view_cart(request: Request):
    client_id = request.headers.get("X-Client-ID", "web_client")
    items = USER_CARTS.get(client_id, [])
    total_cost = sum(i["price"] * i["quantity"] for i in items)
    total_count = sum(i["quantity"] for i in items)
    return {
        "cart_items": items,
        "count": total_count,
        "subtotal": round(total_cost, 2),
    }


@app.post("/checkout")
async def checkout(req: CheckoutRequest, request: Request):
    client_id = request.headers.get("X-Client-ID", "web_client")
    items = list(USER_CARTS.get(client_id, []))
    total_cost = sum(i["price"] * i["quantity"] for i in items)

    order_id = f"ORD-{int(time.time())}"
    order_record = {
        "order_id": order_id,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "items": items,
        "total_amount": round(total_cost, 2),
        "payment_method": req.payment_method,
        "shipping_address": req.shipping_address,
        "status": "CONFIRMED_AND_PAID",
        "bypass_warning": "⚠️ SECURITY NOTICE: Direct POST /checkout executed without prior cart additions!" if not items else None,
    }

    if client_id not in USER_ORDERS:
        USER_ORDERS[client_id] = []
    USER_ORDERS[client_id].append(order_record)

    # Clear cart after successful checkout
    USER_CARTS[client_id] = []

    return {
        "order_status": "COMPLETED",
        "order": order_record,
        "message": "Order successfully placed and processed",
    }


@app.get("/orders")
async def list_orders(request: Request):
    client_id = request.headers.get("X-Client-ID", "web_client")
    return {"orders": USER_ORDERS.get(client_id, [])}


# ── Interactive Web UI with Educational Lab ───────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def store_web_ui(request: Request):
    host = request.headers.get("host", "localhost:8001")
    host_ip = host.split(":")[0]

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VulnStore | Interactive Target Application & Vulnerability Lab</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Outfit:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg-base: #070a13;
      --bg-surface: #0f1626;
      --bg-card: rgba(18, 27, 46, 0.75);
      --border-color: rgba(255, 255, 255, 0.08);
      --accent-purple: #7928ca;
      --accent-blue: #0070f3;
      --accent-cyan: #00f0ff;
      --accent-pink: #ff0080;
      --green-safe: #00e676;
      --red-alert: #ff3366;
      --yellow-warn: #ffb800;
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
      overflow-x: hidden;
      background-image: 
        radial-gradient(circle at 15% 15%, rgba(0, 240, 255, 0.04) 0%, transparent 40%),
        radial-gradient(circle at 85% 85%, rgba(121, 40, 202, 0.05) 0%, transparent 40%);
    }}

    /* Top Header */
    header {{
      background: rgba(15, 22, 38, 0.85);
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
    .brand-badge {{
      background: linear-gradient(135deg, var(--accent-purple), var(--accent-pink));
      color: #fff;
      font-weight: 800;
      font-size: 1.1rem;
      padding: 0.35rem 0.8rem;
      border-radius: 8px;
      letter-spacing: 0.5px;
      box-shadow: 0 0 15px rgba(255, 0, 128, 0.3);
    }}
    .brand-titles h1 {{
      font-size: 1.25rem;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}
    .brand-titles span {{
      font-size: 0.8rem;
      color: var(--text-muted);
      font-family: 'JetBrains Mono', monospace;
    }}
    .nav-actions {{
      display: flex;
      align-items: center;
      gap: 1rem;
    }}
    .btn-pill {{
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border-color);
      color: var(--text-main);
      padding: 0.45rem 1rem;
      border-radius: 20px;
      text-decoration: none;
      font-size: 0.85rem;
      font-family: 'JetBrains Mono', monospace;
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      cursor: pointer;
      transition: all 0.2s ease;
    }}
    .btn-pill:hover {{
      border-color: var(--accent-cyan);
      color: var(--accent-cyan);
      box-shadow: 0 0 12px rgba(0, 240, 255, 0.2);
    }}
    .cart-trigger {{
      background: rgba(0, 230, 118, 0.1);
      border-color: rgba(0, 230, 118, 0.3);
      color: var(--green-safe);
      font-weight: 600;
    }}
    .cart-trigger:hover {{
      border-color: var(--green-safe);
      color: #fff;
      background: rgba(0, 230, 118, 0.2);
    }}
    .user-badge {{
      display: flex;
      align-items: center;
      gap: 0.5rem;
      font-size: 0.85rem;
      font-family: 'JetBrains Mono', monospace;
      color: var(--accent-cyan);
      background: rgba(0, 240, 255, 0.08);
      padding: 0.35rem 0.8rem;
      border-radius: 20px;
      border: 1px solid rgba(0, 240, 255, 0.2);
    }}

    /* Main Container */
    main {{
      max-width: 1400px;
      margin: 0 auto;
      padding: 2rem;
      width: 100%;
      flex: 1;
      display: flex;
      flex-direction: column;
      gap: 2rem;
    }}

    /* Educational Lab Banner Box */
    .edu-banner {{
      background: linear-gradient(135deg, rgba(15, 22, 38, 0.95), rgba(25, 18, 40, 0.95));
      border: 1px solid rgba(0, 240, 255, 0.25);
      border-radius: 14px;
      padding: 1.5rem 2rem;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
      display: flex;
      flex-direction: column;
      gap: 1.25rem;
      position: relative;
      overflow: hidden;
    }}
    .edu-banner::before {{
      content: "";
      position: absolute;
      top: 0; left: 0; width: 4px; height: 100%;
      background: linear-gradient(to bottom, var(--accent-cyan), var(--accent-pink));
    }}
    .edu-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
    }}
    .edu-title {{
      font-size: 1.2rem;
      font-weight: 800;
      display: flex;
      align-items: center;
      gap: 0.6rem;
      color: #fff;
    }}
    .edu-chips {{
      display: flex;
      gap: 0.6rem;
      flex-wrap: wrap;
    }}
    .chip {{
      font-size: 0.75rem;
      padding: 0.25rem 0.6rem;
      border-radius: 4px;
      font-family: 'JetBrains Mono', monospace;
      font-weight: 600;
    }}
    .chip-danger {{ background: rgba(255, 51, 102, 0.2); color: var(--red-alert); border: 1px solid rgba(255, 51, 102, 0.4); }}
    .chip-shield {{ background: rgba(0, 240, 255, 0.15); color: var(--accent-cyan); border: 1px solid rgba(0, 240, 255, 0.3); }}

    .edu-comparison-grid {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1.25rem;
    }}
    @media (max-width: 900px) {{
      .edu-comparison-grid {{ grid-template-columns: 1fr; }}
    }}
    .edu-card {{
      background: rgba(0, 0, 0, 0.3);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 1.25rem;
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
    }}
    .edu-card-title {{
      font-size: 0.95rem;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}
    .edu-card-text {{
      font-size: 0.85rem;
      color: var(--text-muted);
      line-height: 1.5;
    }}
    .edu-card-action {{
      margin-top: auto;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}

    /* Tabs Bar */
    .tabs-bar {{
      display: flex;
      gap: 0.5rem;
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 0.5rem;
      overflow-x: auto;
    }}
    .tab-btn {{
      background: transparent;
      border: 1px solid transparent;
      color: var(--text-muted);
      font-size: 0.95rem;
      font-weight: 600;
      padding: 0.6rem 1.2rem;
      border-radius: 8px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      transition: all 0.2s ease;
      white-space: nowrap;
    }}
    .tab-btn:hover {{
      color: #fff;
      background: rgba(255, 255, 255, 0.04);
    }}
    .tab-btn.active {{
      background: rgba(0, 240, 255, 0.1);
      border-color: rgba(0, 240, 255, 0.3);
      color: var(--accent-cyan);
    }}

    /* Catalog Controls */
    .catalog-controls {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
    }}
    .search-box {{
      display: flex;
      align-items: center;
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0.5rem 1rem;
      gap: 0.5rem;
      width: 320px;
    }}
    .search-box input {{
      background: transparent;
      border: none;
      color: #fff;
      outline: none;
      font-size: 0.9rem;
      width: 100%;
    }}
    .category-pills {{
      display: flex;
      gap: 0.5rem;
      flex-wrap: wrap;
    }}
    .cat-pill {{
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border-color);
      color: var(--text-muted);
      padding: 0.4rem 0.85rem;
      border-radius: 20px;
      font-size: 0.8rem;
      cursor: pointer;
      transition: all 0.2s;
    }}
    .cat-pill.active, .cat-pill:hover {{
      background: rgba(121, 40, 202, 0.2);
      border-color: var(--accent-purple);
      color: #fff;
    }}

    /* Products Grid */
    .products-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
      gap: 1.5rem;
    }}
    .product-card {{
      background: var(--bg-card);
      backdrop-filter: blur(8px);
      border: 1px solid var(--border-color);
      border-radius: 14px;
      padding: 1.5rem;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 1.25rem;
      transition: transform 0.2s, border-color 0.2s, box-shadow 0.2s;
    }}
    .product-card:hover {{
      transform: translateY(-4px);
      border-color: rgba(0, 240, 255, 0.4);
      box-shadow: 0 10px 25px rgba(0, 0, 0, 0.4);
    }}
    .card-top {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
    }}
    .product-icon {{
      font-size: 2.2rem;
      background: rgba(255, 255, 255, 0.04);
      padding: 0.5rem;
      border-radius: 10px;
    }}
    .stock-badge {{
      font-size: 0.75rem;
      font-family: 'JetBrains Mono', monospace;
      color: var(--green-safe);
      background: rgba(0, 230, 118, 0.1);
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
    }}
    .product-category {{
      font-size: 0.75rem;
      color: var(--accent-cyan);
      text-transform: uppercase;
      font-family: 'JetBrains Mono', monospace;
      letter-spacing: 0.5px;
      margin-top: 0.5rem;
    }}
    .product-title {{
      font-size: 1.2rem;
      font-weight: 700;
      margin-top: 0.25rem;
      color: #fff;
    }}
    .product-desc {{
      font-size: 0.85rem;
      color: var(--text-muted);
      line-height: 1.45;
      margin-top: 0.5rem;
    }}
    .product-bottom {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-top: 1rem;
      border-top: 1px solid var(--border-color);
    }}
    .price-value {{
      font-size: 1.4rem;
      font-weight: 800;
      font-family: 'JetBrains Mono', monospace;
      color: var(--green-safe);
    }}
    .btn-buy {{
      background: linear-gradient(135deg, var(--accent-blue), #5046e5);
      color: #fff;
      border: none;
      padding: 0.55rem 1.2rem;
      border-radius: 8px;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      transition: opacity 0.2s, transform 0.1s;
    }}
    .btn-buy:hover {{ opacity: 0.9; transform: scale(1.02); }}

    /* IDOR Tab Section */
    .idor-container {{
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 14px;
      padding: 2rem;
      display: flex;
      flex-direction: column;
      gap: 1.5rem;
    }}
    .user-cards-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
      gap: 1rem;
    }}
    .user-card-btn {{
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 1rem;
      text-align: left;
      cursor: pointer;
      transition: all 0.2s;
    }}
    .user-card-btn:hover, .user-card-btn.active {{
      border-color: var(--accent-cyan);
      box-shadow: 0 0 15px rgba(0, 240, 255, 0.2);
    }}
    .console-viewer {{
      background: #04060c;
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 1.25rem;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.85rem;
      color: #00f0ff;
      white-space: pre-wrap;
      max-height: 350px;
      overflow-y: auto;
    }}

    /* Cart Slide-Over Drawer */
    .drawer-overlay {{
      position: fixed;
      top: 0; left: 0; width: 100vw; height: 100vh;
      background: rgba(0, 0, 0, 0.7);
      backdrop-filter: blur(6px);
      z-index: 200;
      display: none;
    }}
    .drawer-container {{
      position: fixed;
      top: 0; right: 0; width: 440px; height: 100vh;
      background: #0d1220;
      border-left: 1px solid var(--border-color);
      padding: 2rem;
      z-index: 210;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      transform: translateX(100%);
      transition: transform 0.3s cubic-bezier(0.16, 1, 0.3, 1);
    }}
    .drawer-container.open {{
      transform: translateX(0);
    }}
    .cart-items-list {{
      flex: 1;
      overflow-y: auto;
      margin: 1.5rem 0;
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }}
    .cart-item-row {{
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0.75rem 1rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }}

    /* Auth Modal */
    .modal-overlay {{
      position: fixed;
      top: 0; left: 0; width: 100vw; height: 100vh;
      background: rgba(0, 0, 0, 0.7);
      backdrop-filter: blur(6px);
      z-index: 300;
      display: none;
      justify-content: center;
      align-items: center;
    }}
    .modal-box {{
      background: #0d1220;
      border: 1px solid var(--border-color);
      border-radius: 14px;
      padding: 2rem;
      width: 400px;
      max-width: 90vw;
      box-shadow: 0 15px 40px rgba(0, 0, 0, 0.6);
    }}
    .form-group {{
      margin-bottom: 1rem;
    }}
    .form-group label {{
      display: block;
      font-size: 0.8rem;
      color: var(--text-muted);
      margin-bottom: 0.35rem;
      font-family: 'JetBrains Mono', monospace;
    }}
    .form-group input {{
      width: 100%;
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 6px;
      padding: 0.6rem 0.8rem;
      color: #fff;
      font-size: 0.9rem;
      outline: none;
    }}
    .form-group input:focus {{
      border-color: var(--accent-cyan);
    }}
  </style>
</head>
<body>

  <!-- Top Navigation Bar -->
  <header>
    <div class="brand">
      <div class="brand-badge">VulnStore</div>
      <div class="brand-titles">
        <h1>Target E-Commerce Service <span style="font-size: 0.75rem; background: rgba(255, 51, 102, 0.15); color: var(--red-alert); padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: 600;">PORT 8001</span></h1>
        <span>Upstream Business Application &bull; Protected by Pygenic Arc</span>
      </div>
    </div>
    <div class="nav-actions">
      <div id="user-session-display" style="display: none;" class="user-badge">
        <span>👤 <span id="sess-username">admin</span> (<span id="sess-role">Admin</span>)</span>
        <button onclick="logoutUser()" style="background: none; border: none; color: var(--red-alert); cursor: pointer; font-size: 0.75rem; margin-left: 0.5rem;">Logout</button>
      </div>
      <button id="login-open-btn" class="btn-pill" onclick="openLoginModal()">
        🔑 Sign In
      </button>
      <button class="btn-pill cart-trigger" onclick="toggleCartDrawer()">
        🛒 Cart (<span id="cart-counter">0</span>)
      </button>
      <a href="http://{host_ip}:8000/" target="_blank" class="btn-pill" style="border-color: var(--accent-cyan); color: var(--accent-cyan);">
        🛡️ Gateway SOC Dashboard (:8000) &rarr;
      </a>
    </div>
  </header>

  <main>
    <!-- Educational Lab Explainer Box -->
    <div class="edu-banner">
      <div class="edu-header">
        <div class="edu-title">
          <span>🎓 Mentor & Evaluator Interactive Security Lab</span>
        </div>
        <div class="edu-chips">
          <span class="chip chip-danger">Direct Target: Port 8001 (Zero Defenses)</span>
          <span class="chip chip-shield">Pygenic Arc Gateway: Port 8000 (Behavioral Defenses)</span>
        </div>
      </div>

      <div class="edu-comparison-grid">
        <!-- Direct Vulnerability Box -->
        <div class="edu-card">
          <div class="edu-card-title" style="color: var(--red-alert);">
            <span>⚠️ Without Gateway (Direct Access on Port 8001)</span>
          </div>
          <p class="edu-card-text">
            This microservice implements bare business logic. Notice what happens when attacked directly:
            <br>&bull; <strong>Credential Stuffing</strong>: Attackers can spray thousands of passwords without lockout.
            <br>&bull; <strong>IDOR Exposure</strong>: <code>/users/{{id}}</code> leaks confidential emails and admin API keys.
            <br>&bull; <strong>Workflow Bypass</strong>: Directly calling <code>POST /checkout</code> without adding to cart succeeds.
          </p>
          <div class="edu-card-action">
            <span style="font-size: 0.75rem; color: var(--text-muted); font-family: 'JetBrains Mono', monospace;">Status: Exploitable</span>
          </div>
        </div>

        <!-- Protected Gateway Defense Box -->
        <div class="edu-card">
          <div class="edu-card-title" style="color: var(--accent-cyan);">
            <span>🛡️ With Pygenic Arc Gateway (Routed via Port 8000)</span>
          </div>
          <p class="edu-card-text">
            When requests pass through <code>http://{host_ip}:8000/gateway/...</code>:
            <br>&bull; <strong>Dual-Axis Velocity</strong> locks out brute-force attackers after 5 fails with <code>429 SOFT_BLOCK</code>.
            <br>&bull; <strong>Timing Entropy Model</strong> discriminates machine scrapers ($\sigma < 30\text{{ms}}$) vs human bursts.
            <br>&bull; <strong>Markov Chain Model</strong> detects illegal workflow jumps and drops fraudulent checkouts.
          </p>
          <div class="edu-card-action">
            <a href="http://{host_ip}:8000/" target="_blank" class="btn-pill" style="font-size: 0.75rem; border-color: var(--accent-cyan); color: var(--accent-cyan);">
              Inspect Live SOC Telemetry &rarr;
            </a>
          </div>
        </div>
      </div>
    </div>

    <!-- Navigation Tabs -->
    <div class="tabs-bar">
      <button class="tab-btn active" onclick="switchTab('catalog')">
        📦 Product Catalog & Store
      </button>
      <button class="tab-btn" onclick="switchTab('idor')">
        🔍 IDOR Account Explorer (/users/{{id}})
      </button>
      <button class="tab-btn" onclick="switchTab('bypass')">
        ⚡ Workflow Sequence Bypass (/checkout)
      </button>
      <button class="tab-btn" onclick="switchTab('orders')">
        📋 Order Receipts & History (<span id="orders-count">0</span>)
      </button>
    </div>

    <!-- TAB 1: PRODUCT CATALOG -->
    <div id="tab-catalog">
      <div class="catalog-controls" style="margin-bottom: 1.5rem;">
        <div class="category-pills">
          <button class="cat-pill active" onclick="filterCategory('All')">All Hardware & Intel</button>
          <button class="cat-pill" onclick="filterCategory('Security Hardware')">Security Hardware</button>
          <button class="cat-pill" onclick="filterCategory('Network Gateway')">Network Gateway</button>
          <button class="cat-pill" onclick="filterCategory('Threat Intel')">Threat Intel</button>
          <button class="cat-pill" onclick="filterCategory('Access Control')">Access Control</button>
          <button class="cat-pill" onclick="filterCategory('Diagnostics')">Diagnostics</button>
        </div>
        <div class="search-box">
          <span>🔍</span>
          <input type="text" id="search-input" placeholder="Search catalog items..." oninput="handleSearch()">
        </div>
      </div>

      <div class="products-grid" id="products-container">
        <!-- Rendered by JavaScript -->
      </div>
    </div>

    <!-- TAB 2: IDOR EXPLORER -->
    <div id="tab-idor" style="display: none;">
      <div class="idor-container">
        <div>
          <h2 style="font-size: 1.25rem; font-weight: 700; color: #fff;">Insecure Direct Object Reference (IDOR) Laboratory</h2>
          <p style="font-size: 0.85rem; color: var(--text-muted); margin-top: 0.25rem;">
            Click any account card below to execute <code>GET /users/{{id}}</code>. Because this microservice lacks session authorization, any client can access confidential administrator tokens and account balances!
          </p>
        </div>

        <div class="user-cards-grid">
          <div class="user-card-btn" onclick="inspectUser(1)">
            <div style="font-size: 1.5rem;">👑</div>
            <div style="font-weight: 700; margin-top: 0.25rem;">ID 1: admin</div>
            <div style="font-size: 0.75rem; color: var(--red-alert);">SuperAdmin Account</div>
          </div>
          <div class="user-card-btn" onclick="inspectUser(2)">
            <div style="font-size: 1.5rem;">👤</div>
            <div style="font-weight: 700; margin-top: 0.25rem;">ID 2: john_doe</div>
            <div style="font-size: 0.75rem; color: var(--text-muted);">Customer Account</div>
          </div>
          <div class="user-card-btn" onclick="inspectUser(3)">
            <div style="font-size: 1.5rem;">👩‍💻</div>
            <div style="font-weight: 700; margin-top: 0.25rem;">ID 3: alice</div>
            <div style="font-size: 0.75rem; color: var(--text-muted);">Customer Account</div>
          </div>
          <div class="user-card-btn" onclick="inspectUser(4)">
            <div style="font-size: 1.5rem;">👷</div>
            <div style="font-weight: 700; margin-top: 0.25rem;">ID 4: bob</div>
            <div style="font-size: 0.75rem; color: var(--text-muted);">Customer Account</div>
          </div>
          <div class="user-card-btn" onclick="inspectUser(5)">
            <div style="font-size: 1.5rem;">🕵️‍♀️</div>
            <div style="font-weight: 700; margin-top: 0.25rem;">ID 5: sarah</div>
            <div style="font-size: 0.75rem; color: var(--yellow-warn);">Auditor Account</div>
          </div>
          <div class="user-card-btn" onclick="inspectUser(99)">
            <div style="font-size: 1.5rem;">❓</div>
            <div style="font-weight: 700; margin-top: 0.25rem;">ID 99: Missing</div>
            <div style="font-size: 0.75rem; color: var(--text-muted);">Test 404 Probing</div>
          </div>
        </div>

        <div style="display: flex; gap: 1rem; align-items: center; flex-wrap: wrap;">
          <button class="btn-pill" style="border-color: var(--red-alert); color: var(--red-alert);" onclick="testDirectEnumeration()">
            ⚡ Walk All IDs Directly (:8001) — All Leaked!
          </button>
          <button class="btn-pill" style="border-color: var(--accent-cyan); color: var(--accent-cyan);" onclick="testProtectedEnumeration()">
            🛡️ Walk All IDs via Gateway (:8000) — Blocked!
          </button>
        </div>

        <div>
          <div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.5rem; font-family: 'JetBrains Mono', monospace;">Raw JSON Response:</div>
          <div class="console-viewer" id="idor-console">// Select a user card or run test above...</div>
        </div>
      </div>
    </div>

    <!-- TAB 3: WORKFLOW BYPASS -->
    <div id="tab-bypass" style="display: none;">
      <div class="idor-container">
        <div>
          <h2 style="font-size: 1.25rem; font-weight: 700; color: #fff;">State Machine & Sequence Violation Lab</h2>
          <p style="font-size: 0.85rem; color: var(--text-muted); margin-top: 0.25rem;">
            A legitimate user navigates: <code>Browse (/products) &rarr; Select (/products/101) &rarr; Add Cart (/cart/add) &rarr; Checkout (/checkout)</code>.<br>
            Automated exploit bots skip directly to <code>POST /checkout</code> to reserve stock or probe payment gateways.
          </p>
        </div>

        <div style="display: flex; gap: 1rem; flex-wrap: wrap;">
          <button class="btn-pill" style="border-color: var(--accent-pink); color: var(--accent-pink); padding: 0.75rem 1.5rem; font-size: 0.95rem;" onclick="fireDirectCheckoutBypass()">
            ⚡ Fire Direct POST /checkout (Direct :8001 — Succeeds Unchecked!)
          </button>
          <button class="btn-pill" style="border-color: var(--accent-cyan); color: var(--accent-cyan); padding: 0.75rem 1.5rem; font-size: 0.95rem;" onclick="fireProtectedCheckoutBypass()">
            🛡️ Fire Direct POST /checkout via Gateway (:8000 — Stopped by Markov Model!)
          </button>
        </div>

        <div>
          <div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.5rem; font-family: 'JetBrains Mono', monospace;">Checkout Result & Behavioral Anomaly Assessment:</div>
          <div class="console-viewer" id="bypass-console">// Click one of the buttons above to test sequence bypass...</div>
        </div>
      </div>
    </div>

    <!-- TAB 4: ORDERS HISTORY -->
    <div id="tab-orders" style="display: none;">
      <div class="idor-container">
        <h2 style="font-size: 1.25rem; font-weight: 700; color: #fff;">Order Receipts & Transaction History</h2>
        <div id="orders-list-container" style="display: flex; flex-direction: column; gap: 1rem;">
          <div style="color: var(--text-muted); font-size: 0.9rem;">No orders placed yet. Add items to your cart and checkout!</div>
        </div>
      </div>
    </div>
  </main>

  <!-- Slide-Over Cart Drawer -->
  <div class="drawer-overlay" id="cart-drawer-overlay" onclick="toggleCartDrawer()"></div>
  <div class="drawer-container" id="cart-drawer">
    <div>
      <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 1rem;">
        <h3 style="font-size: 1.2rem; font-weight: 700;">Your Shopping Cart</h3>
        <button onclick="toggleCartDrawer()" style="background: none; border: none; color: var(--text-muted); font-size: 1.5rem; cursor: pointer;">&times;</button>
      </div>
      <div class="cart-items-list" id="cart-items-box">
        <!-- Rendered by JS -->
      </div>
    </div>
    <div style="border-top: 1px solid var(--border-color); padding-top: 1.5rem;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
        <span style="color: var(--text-muted); font-size: 0.9rem;">Subtotal:</span>
        <span style="font-size: 1.3rem; font-weight: 800; font-family: 'JetBrains Mono', monospace; color: var(--green-safe);" id="cart-subtotal">$0.00</span>
      </div>
      <div style="display: flex; flex-direction: column; gap: 0.5rem;">
        <button class="btn-buy" style="justify-content: center; padding: 0.8rem; font-size: 1rem;" onclick="processNormalCheckout()">
          💳 Complete Order & Checkout
        </button>
        <button class="btn-pill" style="justify-content: center; border-color: rgba(255, 255, 255, 0.1);" onclick="clearAllCart()">
          Clear Cart
        </button>
      </div>
    </div>
  </div>

  <!-- Login Modal -->
  <div class="modal-overlay" id="login-modal">
    <div class="modal-box">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
        <h3 style="font-size: 1.15rem; font-weight: 700;">Sign in to VulnStore</h3>
        <button onclick="closeLoginModal()" style="background: none; border: none; color: var(--text-muted); font-size: 1.4rem; cursor: pointer;">&times;</button>
      </div>
      <div class="form-group">
        <label>Username</label>
        <input type="text" id="login-user" value="admin">
      </div>
      <div class="form-group">
        <label>Password</label>
        <input type="password" id="login-pass" value="admin123">
      </div>
      <div style="font-size: 0.75rem; color: var(--text-muted); margin-bottom: 1rem; font-family: 'JetBrains Mono', monospace;">
        Test Accounts: admin / admin123 &bull; john_doe / secret123
      </div>
      <button class="btn-buy" style="width: 100%; justify-content: center; padding: 0.75rem;" onclick="performLogin()">
        Authenticate
      </button>
    </div>
  </div>

  <!-- JavaScript Application Logic -->
  <script>
    const HOST_IP = "{host_ip}";
    let allProducts = {PRODUCTS_DB};
    let currentCategory = 'All';
    let userCart = [];
    let currentUser = null;

    // Initialize
    document.addEventListener('DOMContentLoaded', () => {{
      renderProducts();
      refreshCart();
      refreshOrders();
    }});

    function renderProducts() {{
      const container = document.getElementById('products-container');
      const search = document.getElementById('search-input').value.toLowerCase();

      const filtered = allProducts.filter(p => {{
        const matchCat = currentCategory === 'All' || p.category.toLowerCase() === currentCategory.toLowerCase();
        const matchSearch = p.name.toLowerCase().includes(search) || p.desc.toLowerCase().includes(search);
        return matchCat && matchSearch;
      }});

      if (filtered.length === 0) {{
        container.innerHTML = `<div style="grid-column: 1/-1; text-align: center; color: var(--text-muted); padding: 3rem;">No security products match your filter.</div>`;
        return;
      }}

      container.innerHTML = filtered.map(p => `
        <div class="product-card">
          <div>
            <div class="card-top">
              <span class="product-icon">${{p.icon}}</span>
              <span class="stock-badge">${{p.stock}} in stock</span>
            </div>
            <div class="product-category">${{p.category}}</div>
            <div class="product-title">${{p.name}}</div>
            <p class="product-desc">${{p.desc}}</p>
          </div>
          <div class="product-bottom">
            <span class="price-value">$${{p.price.toFixed(2)}}</span>
            <button class="btn-buy" onclick="addToCartItem(${{p.id}})">
              + Add to Cart
            </button>
          </div>
        </div>
      `).join('');
    }}

    function filterCategory(cat) {{
      currentCategory = cat;
      document.querySelectorAll('.cat-pill').forEach(btn => {{
        btn.classList.toggle('active', btn.innerText.includes(cat));
      }});
      renderProducts();
    }}

    function handleSearch() {{
      renderProducts();
    }}

    function switchTab(tab) {{
      document.getElementById('tab-catalog').style.display = tab === 'catalog' ? 'block' : 'none';
      document.getElementById('tab-idor').style.display = tab === 'idor' ? 'block' : 'none';
      document.getElementById('tab-bypass').style.display = tab === 'bypass' ? 'block' : 'none';
      document.getElementById('tab-orders').style.display = tab === 'orders' ? 'block' : 'none';

      document.querySelectorAll('.tab-btn').forEach((b, idx) => {{
        b.classList.toggle('active', 
          (tab === 'catalog' && idx === 0) ||
          (tab === 'idor' && idx === 1) ||
          (tab === 'bypass' && idx === 2) ||
          (tab === 'orders' && idx === 3)
        );
      }});
    }}

    // Cart Operations
    async function addToCartItem(id) {{
      try {{
        const res = await fetch('/cart/add', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ product_id: id, quantity: 1 }})
        }});
        const data = await res.json();
        document.getElementById('cart-counter').innerText = data.cart_count;
        refreshCart();
      }} catch (e) {{
        console.error(e);
      }}
    }}

    async function refreshCart() {{
      try {{
        const res = await fetch('/cart');
        const data = await res.json();
        userCart = data.cart_items || [];
        document.getElementById('cart-counter').innerText = data.count || 0;
        document.getElementById('cart-subtotal').innerText = '$' + (data.subtotal || 0).toFixed(2);

        const list = document.getElementById('cart-items-box');
        if (userCart.length === 0) {{
          list.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 2rem;">Your cart is empty.</div>`;
        }} else {{
          list.innerHTML = userCart.map(i => `
            <div class="cart-item-row">
              <div>
                <div style="font-weight: 600; font-size: 0.9rem;">${{i.name}}</div>
                <div style="font-size: 0.75rem; color: var(--text-muted);">$${{i.price}} &times; ${{i.quantity}}</div>
              </div>
              <button onclick="removeCartItem(${{i.id}})" style="background: none; border: none; color: var(--red-alert); cursor: pointer; font-size: 1.1rem;">&times;</button>
            </div>
          `).join('');
        }}
      }} catch (e) {{
        console.error(e);
      }}
    }}

    async function removeCartItem(id) {{
      await fetch('/cart/remove', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ product_id: id }})
      }});
      refreshCart();
    }}

    async function clearAllCart() {{
      await fetch('/cart/clear', {{ method: 'POST' }});
      refreshCart();
    }}

    function toggleCartDrawer() {{
      const d = document.getElementById('cart-drawer');
      const o = document.getElementById('cart-drawer-overlay');
      const isOpen = d.classList.contains('open');
      if (isOpen) {{
        d.classList.remove('open');
        o.style.display = 'none';
      }} else {{
        d.classList.add('open');
        o.style.display = 'block';
        refreshCart();
      }}
    }}

    async function processNormalCheckout() {{
      try {{
        const res = await fetch('/checkout', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ payment_method: 'corporate_credit_card' }})
        }});
        const data = await res.json();
        toggleCartDrawer();
        refreshOrders();
        switchTab('orders');
        alert('🎉 Order #' + data.order.order_id + ' successfully completed!');
      }} catch (e) {{
        alert('Error: ' + e);
      }}
    }}

    async function refreshOrders() {{
      try {{
        const res = await fetch('/orders');
        const data = await res.json();
        const orders = data.orders || [];
        document.getElementById('orders-count').innerText = orders.length;
        const box = document.getElementById('orders-list-container');
        if (orders.length === 0) {{
          box.innerHTML = `<div style="color: var(--text-muted); font-size: 0.9rem;">No orders placed yet.</div>`;
        }} else {{
          box.innerHTML = orders.map(o => `
            <div style="background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 8px; padding: 1.25rem;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                <span style="font-weight: 700; color: var(--accent-cyan); font-family: 'JetBrains Mono', monospace;">${{o.order_id}}</span>
                <span style="font-size: 0.8rem; color: var(--text-muted);">${{o.timestamp}}</span>
              </div>
              <div style="font-size: 0.85rem; color: #fff;">Amount: <strong style="color: var(--green-safe);">$${{o.total_amount}}</strong> &bull; Status: <strong style="color: var(--green-safe);">${{o.status}}</strong></div>
              ${{o.bypass_warning ? `<div style="margin-top: 0.5rem; color: var(--yellow-warn); font-size: 0.8rem; font-family: 'JetBrains Mono', monospace;">${{o.bypass_warning}}</div>` : ''}}
            </div>
          `).join('');
        }}
      }} catch (e) {{
        console.error(e);
      }}
    }}

    // IDOR Functions
    async function inspectUser(id) {{
      const con = document.getElementById('idor-console');
      con.innerText = 'Executing GET /users/' + id + '...';
      try {{
        const res = await fetch('/users/' + id);
        const data = await res.json();
        con.innerText = '// HTTP ' + res.status + '\\n' + JSON.stringify(data, null, 2);
      }} catch (err) {{
        con.innerText = 'Error: ' + err;
      }}
    }}

    async function testDirectEnumeration() {{
      const con = document.getElementById('idor-console');
      con.innerText = '>>> Running Direct IDOR Enumeration against Port 8001 (UNPROTECTED)...\\n';
      for (let id = 1; id <= 5; id++) {{
        const res = await fetch('/users/' + id);
        const data = await res.json();
        con.innerText += `[ID ${{id}}] HTTP ${{res.status}} -> Leaked User: ${{data.username}} | Role: ${{data.role}} | Balance: $${{data.balance}} | API Key: ${{data.api_key}}\\n`;
      }}
      con.innerText += '\\n⚠️ CRITICAL: All 5 private records exfiltrated because no gateway defense exists on :8001!';
    }}

    async function testProtectedEnumeration() {{
      const con = document.getElementById('idor-console');
      con.innerText = '>>> Running IDOR Enumeration through Gateway (:8000/gateway/users/{{id}})...\\n';
      const gatewayBase = `http://${{HOST_IP}}:8000/gateway/users/`;
      for (let id = 1; id <= 5; id++) {{
        try {{
          const res = await fetch(gatewayBase + id);
          const threatCat = res.headers.get('X-Threat-Category') || 'N/A';
          const threatScore = res.headers.get('X-Threat-Score') || 'N/A';
          const data = await res.json();

          if (res.status === 429 || res.status === 403) {{
            con.innerText += `[ID ${{id}}] HTTP ${{res.status}} [BLOCKED]! Threat: ${{threatCat}} | Score: ${{threatScore}}\\n`;
            con.innerText += `🛡️ GATEWAY ENFORCEMENT TRIGGERED: Sequential identifier enumeration halted automatically!\\n`;
            break;
          }} else {{
            con.innerText += `[ID ${{id}}] HTTP ${{res.status}} | Score: ${{threatScore}} | Category: ${{threatCat}}\\n`;
          }}
        }} catch (e) {{
          con.innerText += `[ID ${{id}}] Network blocked by Gateway CORS or Soft-block!\\n`;
          break;
        }}
      }}
    }}

    // Sequence Bypass Functions
    async function fireDirectCheckoutBypass() {{
      const con = document.getElementById('bypass-console');
      con.innerText = '>>> Firing Direct POST /checkout against :8001 (Direct Mode)...\\n';
      try {{
        const res = await fetch('/checkout', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ payment_method: 'direct_exploit_card' }})
        }});
        const data = await res.json();
        con.innerText += `HTTP ${{res.status}} OK\\n` + JSON.stringify(data, null, 2);
        con.innerText += '\\n⚠️ FLAW EXPLOITED: Target microservice executed checkout order without requiring prior cart sequence!';
      }} catch (e) {{
        con.innerText += 'Error: ' + e;
      }}
    }}

    async function fireProtectedCheckoutBypass() {{
      const con = document.getElementById('bypass-console');
      con.innerText = '>>> Firing Direct POST /checkout through Gateway (:8000/gateway/checkout)...\\n';
      try {{
        const res = await fetch(`http://${{HOST_IP}}:8000/gateway/checkout`, {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ payment_method: 'direct_exploit_card' }})
        }});
        const cat = res.headers.get('X-Threat-Category');
        const score = res.headers.get('X-Threat-Score');
        const data = await res.json();
        con.innerText += `HTTP ${{res.status}} | Category: ${{cat}} | Risk Score: ${{score}}\\n` + JSON.stringify(data, null, 2);
        if (res.status === 429 || res.status === 403) {{
          con.innerText += '\\n🛡️ SUCCESS: Pygenic Arc Markov Sequence Model identified illegal START -> /checkout jump and blocked the attack!';
        }}
      }} catch (e) {{
        con.innerText += 'Error (Interception confirmed): ' + e;
      }}
    }}

    // Auth Modal
    function openLoginModal() {{
      document.getElementById('login-modal').style.display = 'flex';
    }}
    function closeLoginModal() {{
      document.getElementById('login-modal').style.display = 'none';
    }}
    async function performLogin() {{
      const u = document.getElementById('login-user').value;
      const p = document.getElementById('login-pass').value;
      try {{
        const res = await fetch('/auth/login', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ username: u, password: p }})
        }});
        if (!res.ok) throw new Error('Invalid credentials');
        const data = await res.json();
        currentUser = data;
        document.getElementById('sess-username').innerText = data.username;
        document.getElementById('sess-role').innerText = data.role;
        document.getElementById('user-session-display').style.display = 'flex';
        document.getElementById('login-open-btn').style.display = 'none';
        closeLoginModal();
        alert('Welcome, ' + data.username + ' (' + data.role + ')!');
      }} catch (e) {{
        alert('Login Failed: ' + e.message);
      }}
    }}
    function logoutUser() {{
      currentUser = null;
      document.getElementById('user-session-display').style.display = 'none';
      document.getElementById('login-open-btn').style.display = 'inline-flex';
    }}
  </script>
</body>
</html>
"""
    return HTMLResponse(content=html)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
