"""
VulnStore — Target Upstream Application & Interactive Vulnerability Lab (Port 8001)
Team Rudranix | Pygenic Arc (Annvation-2K26)

A fully functional, rich e-commerce microservice and educational security lab.
Includes full product catalog, search, live shopping cart, checkout & purchasing
with real inventory and user wallet balances, receipt generator, order history,
authentication, IDOR inspection, and workflow anomaly testing.
"""

import time
import uuid
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

app = FastAPI(
    title="VulnStore Target Upstream Application",
    description="E-Commerce business microservice protected by Pygenic Arc API Gateway",
    version="2.1.0",
)

# ── CORS Middleware ───────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)


import json
import os

BLOCKED_IPS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "active_blocked_ips.json")


def check_target_ip_banned(client_ip: str) -> tuple[bool, str, float]:
    try:
        if os.path.exists(BLOCKED_IPS_FILE):
            with open(BLOCKED_IPS_FILE, "r") as f:
                data = json.load(f)
            item = data.get(client_ip)
            if item:
                rem = item.get("expiry", 0) - time.time()
                if rem > 0:
                    return True, item.get("category", "PERIMETER_BAN"), rem
    except Exception:
        pass
    try:
        from app.services.threat_engine import threat_engine
        is_blocked, cat, rem_ttl = threat_engine.local_store.is_blocked(client_ip)
        if is_blocked and rem_ttl > 0:
            cat_str = cat.value if hasattr(cat, "value") else str(cat)
            return True, cat_str, rem_ttl
    except Exception:
        pass
    return False, "", 0.0


@app.middleware("http")
async def target_perimeter_ban_enforcement(request: Request, call_next):
    """
    Ensures that if an attacker IP is actively banned across Pygenic Arc,
    they cannot bypass the gateway to access the target store directly.
    """
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        client_ip = xff.split(",")[0].strip()
    elif request.headers.get("X-Real-IP"):
        client_ip = request.headers.get("X-Real-IP").strip()
    elif request.client and request.client.host:
        client_ip = request.client.host
    else:
        client_ip = "127.0.0.1"

    is_blocked, cat_str, rem_ttl = check_target_ip_banned(client_ip)
    if is_blocked and rem_ttl > 0:
        return JSONResponse(
            status_code=403,
            content={
                "error": "Access Blocked by Perimeter Defense",
                "detail": f"Access Denied: IP address {client_ip} is banned until cooldown expires ({round(rem_ttl, 1)}s remaining).",
                "blocked_ip": client_ip,
                "category": cat_str or "PERIMETER_BAN",
                "ttl_remaining_seconds": round(rem_ttl, 1),
            },
            headers={
                "Retry-After": str(max(1, int(rem_ttl))),
                "X-Threat-Score": "1.0",
                "X-Threat-Category": cat_str or "PERIMETER_BAN",
                "X-Threat-Action": "HARD_BLOCK",
            },
        )

    return await call_next(request)

# ── In-Memory Databases ───────────────────────────────────────────────────────

USERS_DB: Dict[str, str] = {
    "admin": "admin123",
    "john_doe": "secret123",
    "alice": "alice2026",
    "bob": "builder99",
    "sarah": "defense2026",
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
        "balance": 350.00,
        "phone": "+1 (555) 014-9920",
    },
    5: {
        "id": 5,
        "username": "sarah",
        "role": "Auditor",
        "full_name": "Sarah Connor",
        "email": "sarah.connor@defense.gov",
        "api_key": "sec_key_live_7719a00b14",
        "balance": 2100.00,
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
        "stock": 8,
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
    {
        "id": 107,
        "name": "RF Spectrum Analyzer SDR",
        "category": "Diagnostics",
        "price": 185.00,
        "stock": 30,
        "rating": 4.8,
        "icon": "📡",
        "desc": "Wideband 100kHz-6GHz software-defined radio transceiver for wireless protocol auditing and electromagnetic surveillance.",
    },
    {
        "id": 108,
        "name": "Optical Fiber Tap Injector",
        "category": "Diagnostics",
        "price": 420.00,
        "stock": 15,
        "rating": 4.9,
        "icon": "💡",
        "desc": "Non-intrusive singlemode optical line coupler with zero insertion attenuation for full-duplex traffic extraction.",
    },
]

USER_CARTS: Dict[str, List[Dict[str, Any]]] = {}
USER_ORDERS: Dict[str, List[Dict[str, Any]]] = {}

# ── Schemas ───────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str

class RegisterRequest(BaseModel):
    username: str
    password: str
    full_name: Optional[str] = None
    email: Optional[str] = None

class CartItemRequest(BaseModel):
    product_id: int
    quantity: int = 1

class CheckoutRequest(BaseModel):
    payment_method: str = "credit_card"
    shipping_address: Optional[str] = "104 Silicon Valley Way, Suite 400"
    recipient_name: Optional[str] = None
    username: Optional[str] = None

# ── Health Check ──────────────────────────────────────────────────────────────

@app.get("/health")
@app.get("/api/health")
async def health_check():
    return {"status": "ok", "service": "vulnstore", "port": 8001}


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
    profile = next((p for p in USER_PROFILES.values() if p["username"] == req.username), None)
    return {
        "message": "Login successful",
        "username": req.username,
        "user_id": profile["id"] if profile else 1,
        "full_name": profile["full_name"] if profile else req.username,
        "role": profile["role"] if profile else "Customer",
        "balance": profile["balance"] if profile else 500.0,
        "email": profile["email"] if profile else f"{req.username}@vulnstore.internal",
        "token": f"jwt_mock_{req.username}_{int(time.time())}",
    }


@app.post("/register")
@app.post("/auth/register")
async def register(req: RegisterRequest):
    if req.username in USERS_DB:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Username '{req.username}' already registered",
        )
    USERS_DB[req.username] = req.password
    new_id = max(USER_PROFILES.keys()) + 1
    new_profile = {
        "id": new_id,
        "username": req.username,
        "role": "Customer",
        "full_name": req.full_name or req.username.capitalize(),
        "email": req.email or f"{req.username}@example.com",
        "api_key": f"sec_key_live_{uuid.uuid4().hex[:10]}",
        "balance": 1000.00,
        "phone": "+1 (555) 019-9988",
    }
    USER_PROFILES[new_id] = new_profile
    return {
        "message": "Account created successfully with $1,000.00 starter balance",
        "username": req.username,
        "user_id": new_id,
        "role": "Customer",
        "balance": 1000.00,
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
    subtotal = sum(i["price"] * i["quantity"] for i in USER_CARTS[client_id])
    return {
        "message": f"Added '{product['name']}' to cart",
        "cart_items": USER_CARTS[client_id],
        "cart_count": total_items,
        "subtotal": round(subtotal, 2),
    }


@app.post("/cart/update")
async def update_cart_quantity(item: CartItemRequest, request: Request):
    client_id = request.headers.get("X-Client-ID", "web_client")
    if client_id not in USER_CARTS:
        USER_CARTS[client_id] = []

    if item.quantity <= 0:
        USER_CARTS[client_id] = [i for i in USER_CARTS[client_id] if i["id"] != item.product_id]
    else:
        existing = next((i for i in USER_CARTS[client_id] if i["id"] == item.product_id), None)
        if existing:
            existing["quantity"] = item.quantity
        else:
            product = next((p for p in PRODUCTS_DB if p["id"] == item.product_id), None)
            if product:
                USER_CARTS[client_id].append({
                    "id": product["id"],
                    "name": product["name"],
                    "price": product["price"],
                    "category": product["category"],
                    "icon": product["icon"],
                    "quantity": item.quantity,
                })

    total_items = sum(i["quantity"] for i in USER_CARTS.get(client_id, []))
    subtotal = sum(i["price"] * i["quantity"] for i in USER_CARTS.get(client_id, []))
    return {
        "message": "Cart updated",
        "cart_items": USER_CARTS.get(client_id, []),
        "cart_count": total_items,
        "subtotal": round(subtotal, 2),
    }


@app.post("/cart/remove")
async def remove_from_cart(item: CartItemRequest, request: Request):
    client_id = request.headers.get("X-Client-ID", "web_client")
    if client_id in USER_CARTS:
        USER_CARTS[client_id] = [i for i in USER_CARTS[client_id] if i["id"] != item.product_id]
    total_items = sum(i["quantity"] for i in USER_CARTS.get(client_id, []))
    subtotal = sum(i["price"] * i["quantity"] for i in USER_CARTS.get(client_id, []))
    return {
        "message": "Item removed",
        "cart_count": total_items,
        "subtotal": round(subtotal, 2),
        "cart_items": USER_CARTS.get(client_id, []),
    }


@app.post("/cart/clear")
async def clear_cart(request: Request):
    client_id = request.headers.get("X-Client-ID", "web_client")
    if client_id in USER_CARTS:
        USER_CARTS[client_id] = []
    return {"message": "Cart cleared", "cart_count": 0, "subtotal": 0.0, "cart_items": []}


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

    # Allow simulation item if direct bypass without cart is tested
    if not items:
        # If cart was empty, create single sample item for bypass evaluation
        items = [{
            "id": 101,
            "name": "Quantum Shield Pro HSM",
            "price": 299.99,
            "category": "Security Hardware",
            "icon": "🛡️",
            "quantity": 1,
        }]
        is_direct_bypass = True
    else:
        is_direct_bypass = False

    subtotal = sum(i["price"] * i["quantity"] for i in items)
    tax = round(subtotal * 0.00, 2)  # Zero tax promotional rate
    total_cost = round(subtotal + tax, 2)

    # Decrement stock for real items
    for item in items:
        prod = next((p for p in PRODUCTS_DB if p["id"] == item["id"]), None)
        if prod and prod["stock"] >= item["quantity"]:
            prod["stock"] -= item["quantity"]

    # Deduct balance if user is provided
    user_profile = None
    if req.username:
        user_profile = next((p for p in USER_PROFILES.values() if p["username"] == req.username), None)
        if user_profile:
            user_profile["balance"] = max(0.0, round(user_profile["balance"] - total_cost, 2))

    order_id = f"ORD-{int(time.time())}-{uuid.uuid4().hex[:4].upper()}"
    tracking_id = f"TRK-{uuid.uuid4().hex[:8].upper()}"

    order_record = {
        "order_id": order_id,
        "tracking_id": tracking_id,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "customer": req.recipient_name or (user_profile["full_name"] if user_profile else "Authorized Customer"),
        "username": req.username or (user_profile["username"] if user_profile else "anonymous"),
        "items": items,
        "item_count": sum(i["quantity"] for i in items),
        "subtotal": subtotal,
        "tax": tax,
        "total_amount": total_cost,
        "payment_method": req.payment_method,
        "shipping_address": req.shipping_address or "104 Silicon Valley Way, Suite 400",
        "status": "CONFIRMED_AND_PAID",
        "remaining_balance": user_profile["balance"] if user_profile else None,
        "bypass_warning": "⚠️ SECURITY NOTICE: Direct POST /checkout executed without prior cart additions!" if is_direct_bypass else None,
    }

    if client_id not in USER_ORDERS:
        USER_ORDERS[client_id] = []
    USER_ORDERS[client_id].insert(0, order_record)

    # Empty user cart after successful checkout
    USER_CARTS[client_id] = []

    return {
        "order_status": "COMPLETED",
        "order": order_record,
        "message": f"Order #{order_id} successfully confirmed and dispatched",
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
  <title>VulnStore | Interactive E-Commerce & Vulnerability Lab</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Outfit:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg-base: #070a13;
      --bg-surface: #0f1626;
      --bg-card: rgba(18, 27, 46, 0.75);
      --border-color: rgba(255, 255, 255, 0.08);
      --border-focus: rgba(0, 240, 255, 0.4);
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
      gap: 0.6rem;
      font-size: 0.85rem;
      font-family: 'JetBrains Mono', monospace;
      color: var(--accent-cyan);
      background: rgba(0, 240, 255, 0.08);
      padding: 0.35rem 0.8rem;
      border-radius: 20px;
      border: 1px solid rgba(0, 240, 255, 0.2);
    }}

    main {{
      flex: 1;
      max-width: 1400px;
      width: 100%;
      margin: 0 auto;
      padding: 2rem;
      display: flex;
      flex-direction: column;
      gap: 2rem;
    }}

    /* Educational Banner */
    .edu-banner {{
      background: linear-gradient(180deg, rgba(121, 40, 202, 0.1) 0%, rgba(0, 240, 255, 0.03) 100%);
      border: 1px solid rgba(121, 40, 202, 0.3);
      border-radius: 12px;
      padding: 1.5rem;
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }}
    .edu-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
    }}
    .edu-title {{
      font-weight: 700;
      font-size: 1.1rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
      color: #fff;
    }}
    .edu-chips {{
      display: flex;
      gap: 0.5rem;
    }}
    .chip {{
      font-size: 0.75rem;
      font-family: 'JetBrains Mono', monospace;
      padding: 0.25rem 0.6rem;
      border-radius: 4px;
      font-weight: 600;
    }}
    .chip-danger {{ background: rgba(255, 51, 102, 0.15); color: var(--red-alert); border: 1px solid rgba(255, 51, 102, 0.3); }}
    .chip-shield {{ background: rgba(0, 240, 255, 0.15); color: var(--accent-cyan); border: 1px solid rgba(0, 240, 255, 0.3); }}

    .edu-comparison-grid {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1.25rem;
    }}
    .edu-card {{
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 1.25rem;
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
    }}
    .edu-card-title {{
      font-weight: 700;
      font-size: 0.95rem;
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
      justify-content: flex-end;
    }}

    /* Tabs Bar */
    .tabs-bar {{
      display: flex;
      gap: 0.5rem;
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 0.5rem;
    }}
    .tab-btn {{
      background: none;
      border: none;
      color: var(--text-muted);
      padding: 0.6rem 1.25rem;
      font-size: 0.95rem;
      font-family: 'Outfit', sans-serif;
      font-weight: 600;
      border-radius: 8px;
      cursor: pointer;
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}
    .tab-btn:hover {{
      color: #fff;
      background: rgba(255, 255, 255, 0.04);
    }}
    .tab-btn.active {{
      color: var(--accent-cyan);
      background: rgba(0, 240, 255, 0.08);
      border: 1px solid rgba(0, 240, 255, 0.2);
    }}

    /* Catalog Section */
    .catalog-controls {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
    }}
    .category-pills {{
      display: flex;
      gap: 0.5rem;
      flex-wrap: wrap;
    }}
    .cat-pill {{
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      color: var(--text-muted);
      padding: 0.4rem 0.8rem;
      border-radius: 20px;
      font-size: 0.85rem;
      cursor: pointer;
      transition: all 0.2s;
    }}
    .cat-pill:hover, .cat-pill.active {{
      border-color: var(--accent-cyan);
      color: var(--accent-cyan);
      background: rgba(0, 240, 255, 0.05);
    }}
    .search-box {{
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0.4rem 0.8rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
      width: 260px;
    }}
    .search-box input {{
      background: none;
      border: none;
      color: #fff;
      font-family: 'Outfit', sans-serif;
      font-size: 0.85rem;
      outline: none;
      width: 100%;
    }}

    /* Products Grid */
    .products-grid {{
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
      transition: all 0.25s ease;
    }}
    .product-card:hover {{
      border-color: rgba(0, 240, 255, 0.4);
      transform: translateY(-3px);
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
      border: 1px solid var(--border-color);
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
      font-family: 'JetBrains Mono', monospace;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-top: 0.5rem;
    }}
    .product-title {{
      font-size: 1.1rem;
      font-weight: 700;
      color: #fff;
      margin-top: 0.25rem;
    }}
    .product-desc {{
      font-size: 0.85rem;
      color: var(--text-muted);
      line-height: 1.4;
      margin-top: 0.5rem;
    }}
    .product-bottom {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-top: 1px solid var(--border-color);
      padding-top: 1rem;
    }}
    .price-value {{
      font-size: 1.3rem;
      font-weight: 800;
      font-family: 'JetBrains Mono', monospace;
      color: #fff;
    }}
    .btn-buy {{
      background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));
      color: #000;
      font-weight: 700;
      font-size: 0.85rem;
      border: none;
      padding: 0.5rem 1rem;
      border-radius: 8px;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 0.4rem;
      transition: all 0.2s ease;
    }}
    .btn-buy:hover {{
      box-shadow: 0 0 15px rgba(0, 240, 255, 0.4);
      transform: scale(1.02);
    }}

    /* Cart Slide-Over Drawer */
    .drawer-overlay {{
      position: fixed;
      top: 0; left: 0; width: 100vw; height: 100vh;
      background: rgba(0, 0, 0, 0.6);
      backdrop-filter: blur(4px);
      z-index: 200;
      display: none;
    }}
    .drawer-container {{
      position: fixed;
      top: 0; right: -450px; width: 420px; height: 100vh;
      background: #0b101d;
      border-left: 1px solid var(--border-color);
      z-index: 201;
      padding: 2rem;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      transition: right 0.3s ease;
      box-shadow: -10px 0 30px rgba(0, 0, 0, 0.7);
    }}
    .drawer-container.open {{
      right: 0;
    }}
    .cart-items-list {{
      display: flex;
      flex-direction: column;
      gap: 0.85rem;
      margin-top: 1.5rem;
      max-height: 60vh;
      overflow-y: auto;
    }}
    .cart-item-row {{
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0.85rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }}
    .qty-btn {{
      background: rgba(255, 255, 255, 0.08);
      border: 1px solid var(--border-color);
      color: #fff;
      width: 24px;
      height: 24px;
      border-radius: 4px;
      cursor: pointer;
      font-weight: 700;
      font-family: 'JetBrains Mono', monospace;
    }}

    /* IDOR & Exploit Explorer Sections */
    .idor-container {{
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 2rem;
      display: flex;
      flex-direction: column;
      gap: 1.5rem;
    }}
    .user-cards-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
      gap: 1rem;
    }}
    .user-card-btn {{
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 1rem;
      text-align: left;
      cursor: pointer;
      transition: all 0.2s ease;
    }}
    .user-card-btn:hover {{
      border-color: var(--accent-cyan);
      box-shadow: 0 0 10px rgba(0, 240, 255, 0.2);
    }}
    .console-viewer {{
      background: #04060c;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 1rem;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.8rem;
      color: var(--accent-cyan);
      max-height: 260px;
      overflow-y: auto;
      white-space: pre-wrap;
    }}

    /* Modals */
    .modal-overlay {{
      position: fixed;
      top: 0; left: 0; width: 100vw; height: 100vh;
      background: rgba(0, 0, 0, 0.75);
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
      width: 460px;
      max-width: 90vw;
      box-shadow: 0 15px 40px rgba(0, 0, 0, 0.8), 0 0 20px rgba(0, 240, 255, 0.15);
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
    .form-group input, .form-group select {{
      width: 100%;
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 6px;
      padding: 0.6rem 0.8rem;
      color: #fff;
      font-size: 0.9rem;
      outline: none;
    }}
    .form-group input:focus, .form-group select:focus {{
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
        <span>👤 <strong id="sess-username">admin</strong> (<span id="sess-role">Admin</span>)</span>
        <span style="color: var(--green-safe); font-weight: 700;" id="sess-balance">$9,999.00</span>
        <button onclick="logoutUser()" style="background: none; border: none; color: var(--red-alert); cursor: pointer; font-size: 0.75rem; margin-left: 0.3rem;">Logout</button>
      </div>
      <button id="login-open-btn" class="btn-pill" onclick="openLoginModal()">
        🔑 Sign In / Register
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
            <br>&bull; <strong>Credential Stuffing</strong>: Attackers spray thousands of passwords without lockout.
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
            <br>&bull; <strong>Timing Entropy Model</strong> discriminates machine scrapers (&sigma; &lt; 30ms) vs human bursts.
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
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <h2 style="font-size: 1.25rem; font-weight: 700; color: #fff;">Order Receipts & Transaction History</h2>
          <button onclick="refreshOrders()" class="btn-pill">🔄 Refresh Orders</button>
        </div>
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
        <button class="btn-buy" style="justify-content: center; padding: 0.8rem; font-size: 1rem;" onclick="openCheckoutModal()">
          💳 Proceed to Checkout & Pay
        </button>
        <button class="btn-pill" style="justify-content: center; border-color: rgba(255, 255, 255, 0.1);" onclick="clearAllCart()">
          Clear Cart
        </button>
      </div>
    </div>
  </div>

  <!-- Checkout Purchasing Modal -->
  <div class="modal-overlay" id="checkout-modal" onclick="closeCheckoutModal()">
    <div class="modal-box" onclick="event.stopPropagation()">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; border-bottom: 1px solid var(--border-color); padding-bottom: 0.75rem;">
        <h3 style="font-size: 1.2rem; font-weight: 700; color: #fff;">💳 Complete Secure Purchase</h3>
        <button onclick="closeCheckoutModal()" style="background: none; border: none; color: var(--text-muted); font-size: 1.4rem; cursor: pointer;">&times;</button>
      </div>

      <div style="background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 8px; padding: 0.85rem; margin-bottom: 1rem;">
        <div style="display: flex; justify-content: space-between; font-size: 0.85rem; color: var(--text-muted);">
          <span>Cart Items: <strong id="chk-item-count" style="color: #fff;">0</strong></span>
          <span>Subtotal: <strong id="chk-subtotal" style="color: #fff;">$0.00</strong></span>
        </div>
        <div style="display: flex; justify-content: space-between; font-size: 0.95rem; font-weight: 700; margin-top: 0.5rem; color: var(--green-safe);">
          <span>Order Total:</span>
          <span id="chk-total" style="font-family: 'JetBrains Mono', monospace;">$0.00</span>
        </div>
      </div>

      <div class="form-group">
        <label>Payment Method</label>
        <select id="chk-payment-method">
          <option value="corporate_credit_card">💳 Corporate Amex / Visa (Ending in 4921)</option>
          <option value="wallet_balance">💰 Account Wallet Balance (Fast Checkout)</option>
          <option value="crypto_hsm_vault">🔒 Quantum Encrypted Crypto Key Vault</option>
          <option value="direct_wire">🏦 Enterprise Wire Transfer / Purchase Order</option>
        </select>
      </div>

      <div class="form-group">
        <label>Shipping Address / Dispatch Facility</label>
        <input type="text" id="chk-address" value="104 Silicon Valley Way, Bldg 4, Sector 7">
      </div>

      <div class="form-group">
        <label>Recipient / Authorized Operator</label>
        <input type="text" id="chk-recipient" value="System Security Officer">
      </div>

      <button class="btn-buy" style="width: 100%; justify-content: center; padding: 0.85rem; font-size: 1rem;" onclick="processNormalCheckout()">
        ✅ Authorize & Confirm Purchase
      </button>
    </div>
  </div>

  <!-- Order Receipt Confirmation Modal -->
  <div class="modal-overlay" id="receipt-modal" onclick="closeReceiptModal()">
    <div class="modal-box" style="width: 520px;" onclick="event.stopPropagation()">
      <div style="text-align: center; margin-bottom: 1.25rem;">
        <div style="font-size: 2.5rem; margin-bottom: 0.5rem;">🎉</div>
        <h3 style="font-size: 1.3rem; font-weight: 800; color: var(--green-safe);">Purchase Order Confirmed!</h3>
        <p style="font-size: 0.85rem; color: var(--text-muted); margin-top: 0.25rem;">Your secure hardware package has been allocated and queued for dispatch.</p>
      </div>

      <div id="receipt-details-box" style="background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 8px; padding: 1.25rem; font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; line-height: 1.6; margin-bottom: 1.5rem;">
        <!-- Filled by JS -->
      </div>

      <div style="display: flex; gap: 0.5rem;">
        <button class="btn-buy" style="flex: 1; justify-content: center; padding: 0.75rem;" onclick="goToOrdersTab()">
          View Orders History
        </button>
        <button class="btn-pill" style="justify-content: center; padding: 0.75rem;" onclick="closeReceiptModal()">
          Close
        </button>
      </div>
    </div>
  </div>

  <!-- Login / Register Modal -->
  <div class="modal-overlay" id="login-modal" onclick="closeLoginModal()">
    <div class="modal-box" onclick="event.stopPropagation()">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
        <div style="display: flex; gap: 0.5rem;">
          <button id="auth-tab-login" class="cat-pill active" onclick="switchAuthTab('login')">Sign In</button>
          <button id="auth-tab-register" class="cat-pill" onclick="switchAuthTab('register')">Register</button>
        </div>
        <button onclick="closeLoginModal()" style="background: none; border: none; color: var(--text-muted); font-size: 1.4rem; cursor: pointer;">&times;</button>
      </div>

      <!-- Login Form -->
      <div id="auth-form-login">
        <div class="form-group">
          <label>Username</label>
          <input type="text" id="login-user" value="admin">
        </div>
        <div class="form-group">
          <label>Password</label>
          <input type="password" id="login-pass" value="admin123">
        </div>

        <div style="margin-bottom: 1rem;">
          <label style="display: block; font-size: 0.75rem; color: var(--text-muted); margin-bottom: 0.35rem; font-family: 'JetBrains Mono', monospace;">Quick Switch Demo Accounts:</label>
          <div style="display: flex; gap: 0.35rem; flex-wrap: wrap;">
            <button class="cat-pill" onclick="quickFillAccount('admin', 'admin123')">👑 admin</button>
            <button class="cat-pill" onclick="quickFillAccount('alice', 'alice2026')">👩‍💻 alice ($1280)</button>
            <button class="cat-pill" onclick="quickFillAccount('john_doe', 'secret123')">👤 john_doe</button>
            <button class="cat-pill" onclick="quickFillAccount('bob', 'builder99')">👷 bob</button>
            <button class="cat-pill" onclick="quickFillAccount('sarah', 'defense2026')">🕵️ sarah</button>
          </div>
        </div>

        <button class="btn-buy" style="width: 100%; justify-content: center; padding: 0.75rem;" onclick="performLogin()">
          Authenticate & Load Wallet
        </button>
      </div>

      <!-- Register Form -->
      <div id="auth-form-register" style="display: none;">
        <div class="form-group">
          <label>Username</label>
          <input type="text" id="reg-user" placeholder="e.g. security_lead">
        </div>
        <div class="form-group">
          <label>Full Name</label>
          <input type="text" id="reg-name" placeholder="e.g. Alex Mercer">
        </div>
        <div class="form-group">
          <label>Password</label>
          <input type="password" id="reg-pass" placeholder="Password">
        </div>
        <button class="btn-buy" style="width: 100%; justify-content: center; padding: 0.75rem;" onclick="performRegister()">
          Create Account ($1,000 Starter Credit)
        </button>
      </div>
    </div>
  </div>

  <!-- JavaScript Application Logic -->
  <script>
    const HOST_IP = "{host_ip}";
    let allProducts = {PRODUCTS_DB};
    let currentCategory = 'All';
    let userCart = [];
    let currentUser = null;

    // Auto-detect base path (if proxied via /gateway/ or accessed directly)
    const isProxied = window.location.pathname.startsWith('/gateway');
    const apiBase = isProxied ? '/gateway' : '';

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

      if (tab === 'orders') {{
        refreshOrders();
      }}
    }}

    // Cart Operations
    async function addToCartItem(id) {{
      try {{
        const res = await fetch(apiBase + '/cart/add', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ product_id: id, quantity: 1 }})
        }});
        const data = await res.json();
        document.getElementById('cart-counter').innerText = data.cart_count || 0;
        refreshCart();
        // Open drawer on add
        const d = document.getElementById('cart-drawer');
        const o = document.getElementById('cart-drawer-overlay');
        d.classList.add('open');
        o.style.display = 'block';
      }} catch (e) {{
        console.error(e);
      }}
    }}

    async function changeCartQty(id, newQty) {{
      try {{
        await fetch(apiBase + '/cart/update', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ product_id: id, quantity: newQty }})
        }});
        refreshCart();
      }} catch (e) {{
        console.error(e);
      }}
    }}

    async function refreshCart() {{
      try {{
        const res = await fetch(apiBase + '/cart');
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
                <div style="font-size: 0.75rem; color: var(--text-muted);">$${{i.price.toFixed(2)}} &times; ${{i.quantity}} = <strong style="color: #fff;">$${{(i.price * i.quantity).toFixed(2)}}</strong></div>
              </div>
              <div style="display: flex; align-items: center; gap: 0.4rem;">
                <button class="qty-btn" onclick="changeCartQty(${{i.id}}, ${{i.quantity - 1}})">-</button>
                <span style="font-size: 0.85rem; font-weight: 700; min-width: 16px; text-align: center;">${{i.quantity}}</span>
                <button class="qty-btn" onclick="changeCartQty(${{i.id}}, ${{i.quantity + 1}})">+</button>
                <button onclick="removeCartItem(${{i.id}})" style="background: none; border: none; color: var(--red-alert); cursor: pointer; font-size: 1.2rem; margin-left: 0.4rem;">&times;</button>
              </div>
            </div>
          `).join('');
        }}
      }} catch (e) {{
        console.error(e);
      }}
    }}

    async function removeCartItem(id) {{
      await fetch(apiBase + '/cart/remove', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ product_id: id }})
      }});
      refreshCart();
    }}

    async function clearAllCart() {{
      await fetch(apiBase + '/cart/clear', {{ method: 'POST' }});
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

    // Checkout Flow
    function openCheckoutModal() {{
      if (userCart.length === 0) {{
        alert('Your cart is empty. Add products before proceeding to checkout.');
        return;
      }}
      toggleCartDrawer();
      const count = userCart.reduce((sum, i) => sum + i.quantity, 0);
      const sub = userCart.reduce((sum, i) => sum + (i.price * i.quantity), 0);
      document.getElementById('chk-item-count').innerText = count;
      document.getElementById('chk-subtotal').innerText = '$' + sub.toFixed(2);
      document.getElementById('chk-total').innerText = '$' + sub.toFixed(2);
      if (currentUser) {{
        document.getElementById('chk-recipient').value = currentUser.full_name || currentUser.username;
      }}
      document.getElementById('checkout-modal').style.display = 'flex';
    }}

    function closeCheckoutModal() {{
      document.getElementById('checkout-modal').style.display = 'none';
    }}

    async function processNormalCheckout() {{
      const payMethod = document.getElementById('chk-payment-method').value;
      const address = document.getElementById('chk-address').value;
      const recipient = document.getElementById('chk-recipient').value;

      try {{
        const res = await fetch(apiBase + '/checkout', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{
            payment_method: payMethod,
            shipping_address: address,
            recipient_name: recipient,
            username: currentUser ? currentUser.username : null,
          }})
        }});
        const data = await res.json();
        closeCheckoutModal();

        if (currentUser && data.order.remaining_balance !== null) {{
          currentUser.balance = data.order.remaining_balance;
          document.getElementById('sess-balance').innerText = '$' + currentUser.balance.toFixed(2);
        }}

        // Render Receipt Modal
        const o = data.order;
        const details = document.getElementById('receipt-details-box');
        details.innerHTML = `
          <div style="color: var(--accent-cyan); font-weight: 700; margin-bottom: 0.5rem;">ORDER: ${{o.order_id}}</div>
          <div>Tracking: <strong style="color: #fff;">${{o.tracking_id}}</strong></div>
          <div>Date: ${{o.timestamp}}</div>
          <div>Recipient: ${{o.customer}}</div>
          <div>Address: ${{o.shipping_address}}</div>
          <div>Payment: ${{o.payment_method}}</div>
          <hr style="border-color: var(--border-color); margin: 0.5rem 0;">
          <div style="color: var(--text-muted); margin-bottom: 0.3rem;">Allocated Hardware Items:</div>
          ${{o.items.map(i => `<div>&bull; ${{i.name}} (&times;${{i.quantity}}) - $${{(i.price * i.quantity).toFixed(2)}}</div>`).join('')}}
          <hr style="border-color: var(--border-color); margin: 0.5rem 0;">
          <div style="font-size: 1rem; font-weight: 800; color: var(--green-safe);">PAID TOTAL: $${{o.total_amount.toFixed(2)}}</div>
        `;

        document.getElementById('receipt-modal').style.display = 'flex';
        refreshCart();
        refreshOrders();
      }} catch (e) {{
        alert('Checkout error: ' + e);
      }}
    }}

    function closeReceiptModal() {{
      document.getElementById('receipt-modal').style.display = 'none';
    }}

    function goToOrdersTab() {{
      closeReceiptModal();
      switchTab('orders');
    }}

    async function refreshOrders() {{
      try {{
        const res = await fetch(apiBase + '/orders');
        const data = await res.json();
        const orders = data.orders || [];
        document.getElementById('orders-count').innerText = orders.length;
        const box = document.getElementById('orders-list-container');
        if (orders.length === 0) {{
          box.innerHTML = `<div style="color: var(--text-muted); font-size: 0.9rem;">No orders placed yet. Add items to your cart and checkout!</div>`;
        }} else {{
          box.innerHTML = orders.map(o => `
            <div style="background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 8px; padding: 1.25rem;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; flex-wrap: wrap; gap: 0.5rem;">
                <span style="font-weight: 700; color: var(--accent-cyan); font-family: 'JetBrains Mono', monospace;">${{o.order_id}}</span>
                <span style="font-size: 0.75rem; background: rgba(0, 230, 118, 0.15); color: var(--green-safe); padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: 700;">${{o.status}}</span>
                <span style="font-size: 0.8rem; color: var(--text-muted); font-family: 'JetBrains Mono', monospace;">${{o.timestamp}}</span>
              </div>
              <div style="font-size: 0.85rem; color: var(--text-main); margin-bottom: 0.5rem;">
                Customer: <strong>${{o.customer}}</strong> &bull; Tracking: <strong style="color: var(--accent-cyan); font-family: 'JetBrains Mono', monospace;">${{o.tracking_id}}</strong> &bull; Total Paid: <strong style="color: var(--green-safe);">$${{o.total_amount.toFixed(2)}}</strong>
              </div>
              <div style="font-size: 0.8rem; color: var(--text-muted); background: rgba(0,0,0,0.3); padding: 0.5rem; border-radius: 4px;">
                ${{o.items.map(i => `${{i.name}} (&times;${{i.quantity}})`).join(', ')}}
              </div>
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
      con.innerText = 'Executing GET ' + apiBase + '/users/' + id + '...';
      try {{
        const res = await fetch(apiBase + '/users/' + id);
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
        const res = await fetch('http://' + HOST_IP + ':8001/users/' + id);
        const data = await res.json();
        con.innerText += `[ID ${{id}}] HTTP ${{res.status}} -> Leaked User: ${{data.username}} | Role: ${{data.role}} | Balance: $${{data.balance}} | API Key: ${{data.api_key}}\\n`;
      }}
      con.innerText += '\\n⚠️ CRITICAL: All private records exfiltrated directly because Port 8001 lacks gateway behavioral inspection!';
    }}

    async function testProtectedEnumeration() {{
      const con = document.getElementById('idor-console');
      con.innerText = '>>> Running IDOR Enumeration through Protected Gateway (:8000/gateway/users/{{id}})...\\n';
      const gatewayBase = `http://${{HOST_IP}}:8000/gateway/users/`;
      for (let id = 1; id <= 5; id++) {{
        try {{
          const res = await fetch(gatewayBase + id);
          const threatCat = res.headers.get('X-Threat-Category') || 'N/A';
          const threatScore = res.headers.get('X-Threat-Score') || 'N/A';
          const threatAction = res.headers.get('X-Threat-Action') || 'N/A';
          const data = await res.json();

          if (res.status === 429 || res.status === 403) {{
            con.innerText += `[ID ${{id}}] HTTP ${{res.status}} [BLOCKED]! Threat: ${{threatCat}} | Action: ${{threatAction}} | Score: ${{threatScore}}\\n`;
            con.innerText += `🛡️ GATEWAY ENFORCEMENT TRIGGERED: Sequential identifier enumeration halted automatically!\\n`;
            break;
          }} else {{
            con.innerText += `[ID ${{id}}] HTTP ${{res.status}} | Score: ${{threatScore}} | Category: ${{threatCat}}\\n`;
          }}
        }} catch (e) {{
          con.innerText += `[ID ${{id}}] Network blocked by Gateway Soft-block or CORS!\\n`;
          break;
        }}
      }}
    }}

    // Sequence Bypass Functions
    async function fireDirectCheckoutBypass() {{
      const con = document.getElementById('bypass-console');
      con.innerText = '>>> Firing Direct POST /checkout against :8001 (Direct Mode)...\\n';
      try {{
        const res = await fetch('http://' + HOST_IP + ':8001/checkout', {{
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
        const cat = res.headers.get('X-Threat-Category') || 'N/A';
        const score = res.headers.get('X-Threat-Score') || 'N/A';
        const act = res.headers.get('X-Threat-Action') || 'N/A';
        const data = await res.json();
        con.innerText += `HTTP ${{res.status}} | Action: ${{act}} | Category: ${{cat}} | Risk Score: ${{score}}\\n` + JSON.stringify(data, null, 2);
        if (res.status === 429 || res.status === 403) {{
          con.innerText += '\\n🛡️ SUCCESS: Pygenic Arc Markov Sequence Model identified illegal START -> /checkout jump and blocked the attack!';
        }}
      }} catch (e) {{
        con.innerText += 'Error: ' + e;
      }}
    }}

    // Auth Modal Logic
    function openLoginModal() {{
      document.getElementById('login-modal').style.display = 'flex';
    }}
    function closeLoginModal() {{
      document.getElementById('login-modal').style.display = 'none';
    }}
    function switchAuthTab(tab) {{
      document.getElementById('auth-form-login').style.display = tab === 'login' ? 'block' : 'none';
      document.getElementById('auth-form-register').style.display = tab === 'register' ? 'block' : 'none';
      document.getElementById('auth-tab-login').classList.toggle('active', tab === 'login');
      document.getElementById('auth-tab-register').classList.toggle('active', tab === 'register');
    }}
    function quickFillAccount(u, p) {{
      document.getElementById('login-user').value = u;
      document.getElementById('login-pass').value = p;
    }}
    async function performLogin() {{
      const u = document.getElementById('login-user').value.trim();
      const p = document.getElementById('login-pass').value.trim();
      try {{
        const res = await fetch(apiBase + '/auth/login', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ username: u, password: p }})
        }});
        if (!res.ok) throw new Error('Invalid credentials supplied');
        const data = await res.json();
        currentUser = data;
        document.getElementById('sess-username').innerText = data.username;
        document.getElementById('sess-role').innerText = data.role;
        document.getElementById('sess-balance').innerText = '$' + (data.balance || 0).toFixed(2);
        document.getElementById('user-session-display').style.display = 'flex';
        document.getElementById('login-open-btn').style.display = 'none';
        closeLoginModal();
        alert('Welcome, ' + data.username + ' (' + data.role + ')! Wallet balance: $' + (data.balance || 0).toFixed(2));
      }} catch (e) {{
        alert('Login Failed: ' + e.message);
      }}
    }}
    async function performRegister() {{
      const u = document.getElementById('reg-user').value.trim();
      const n = document.getElementById('reg-name').value.trim();
      const p = document.getElementById('reg-pass').value.trim();
      if (!u || !p) {{
        alert('Username and password are required.');
        return;
      }}
      try {{
        const res = await fetch(apiBase + '/auth/register', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ username: u, password: p, full_name: n }})
        }});
        if (!res.ok) throw new Error('Registration error');
        const data = await res.json();
        alert(data.message);
        switchAuthTab('login');
        quickFillAccount(u, p);
      }} catch (e) {{
        alert('Registration Failed: ' + e.message);
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
