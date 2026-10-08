"""
Sample Target E-Commerce & User API (Vulnerable Upstream Application)

Represents a typical business backend service that requires protection.
Without the API Gateway, this service has no defense against:
1. Credential Stuffing on /api/v1/auth/login
2. Content Scraping on /api/v1/products
3. IDOR / Resource Enumeration on /api/v1/users/{id}
4. Workflow Bypass / Sequence Skipping on /api/v1/checkout
"""

import time
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request, Response, status
from pydantic import BaseModel

app = FastAPI(
    title="VulnStore Upstream API",
    description="Business application protected by the API Gateway Behavioral Threat Engine",
    version="1.0.0",
)

# Simulated in-memory database
USERS_DB = {
    "admin": "admin123",
    "john_doe": "secret123",
    "alice": "alice2026",
    "bob": "builder99",
}

USER_PROFILES = {
    1: {"id": 1, "username": "admin", "role": "admin", "email": "admin@vulnstore.io", "api_key": "sec_adm_9941a"},
    2: {"id": 2, "username": "john_doe", "role": "customer", "email": "john@example.com", "balance": 450.00},
    3: {"id": 3, "username": "alice", "role": "customer", "email": "alice@corp.net", "balance": 1280.50},
    4: {"id": 4, "username": "bob", "role": "customer", "email": "bob@contractor.org", "balance": 50.00},
    5: {"id": 5, "username": "sarah", "role": "auditor", "email": "sarah@audit.gov", "balance": 900.00},
}

PRODUCTS_DB = [
    {"id": 101, "name": "Quantum Shield Pro", "price": 299.99, "stock": 45, "category": "security"},
    {"id": 102, "name": "Cyber Sentinel Hub", "price": 499.00, "stock": 12, "category": "hardware"},
    {"id": 103, "name": "Zero-Day Analyzer", "price": 1250.00, "stock": 5, "category": "software"},
    {"id": 104, "name": "Encrypted Key Vault", "price": 89.50, "stock": 120, "category": "crypto"},
    {"id": 105, "name": "Packet Sniffer Dongle", "price": 35.00, "stock": 200, "category": "networking"},
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


@app.get("/")
async def root():
    return {
        "status": "online",
        "app": "VulnStore Upstream API",
        "docs_url": "/docs",
        "timestamp": time.time(),
    }


@app.post("/auth/login")
async def login(req: LoginRequest):
    """Vulnerable to credential stuffing if unprotected."""
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
    """Vulnerable to automated scrapers when unprotected."""
    return {"total": len(PRODUCTS_DB), "products": PRODUCTS_DB}


@app.get("/products/{product_id}")
async def get_product(product_id: int):
    for p in PRODUCTS_DB:
        if p["id"] == product_id:
            return p
    raise HTTPException(status_code=404, detail="Product not found")


@app.get("/users/{user_id}")
async def get_user_profile(user_id: int):
    """Vulnerable to IDOR / Sequential Enumeration."""
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
    """
    Vulnerable to abnormal sequence / state bypass:
    Can be called directly without going through /products or /cart!
    """
    client_id = request.headers.get("X-Client-ID", "anonymous")
    items = USER_CARTS.get(client_id, [])
    # If called directly, cart is empty but order completes without gateway defense
    return {
        "order_status": "COMPLETED",
        "order_id": f"ORD_{int(time.time() * 1000)}",
        "items_charged": items,
        "payment": req.payment_method,
        "warning": "Warning: Order placed directly without cart validation" if not items else "Valid checkout flow",
    }


@app.get("/admin/internal")
async def admin_diagnostics():
    """Hidden endpoint sought by directory scanners (ffuf/gobuster)."""
    return {
        "system_status": "CONFIDENTIAL",
        "active_users": len(USER_PROFILES),
        "debug_mode": True,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
