import pytest
from httpx import ASGITransport, AsyncClient

from app.services.threat_engine import (
    BehaviourCategory,
    EnforcementAction,
    threat_engine,
)
from target_app.main import app as target_app, PRODUCTS_DB, USER_PROFILES


@pytest.mark.asyncio
async def test_threat_engine_manual_block_and_unblock():
    threat_engine.clear_all()
    test_ip = "192.168.64.99"

    # Verify not blocked initially
    is_blocked, cat, ttl = threat_engine.local_store.is_blocked(test_ip)
    assert not is_blocked

    # Manually block IP
    threat_engine.manual_block_ip(test_ip, category=BehaviourCategory.MANUAL_BAN, ttl_seconds=300)
    is_blocked, cat, ttl = threat_engine.local_store.is_blocked(test_ip)
    assert is_blocked
    assert cat == BehaviourCategory.MANUAL_BAN
    assert ttl > 0

    # Test analyze_request returns HARD_BLOCK
    verdict = threat_engine.analyze_request(client_id="kali_bot", ip=test_ip, path="/gateway/products")
    assert verdict.action == EnforcementAction.HARD_BLOCK
    assert verdict.risk_score == 1.0

    # Unblock
    threat_engine.unblock_ip(test_ip)
    is_blocked, _, _ = threat_engine.local_store.is_blocked(test_ip)
    assert not is_blocked


@pytest.mark.asyncio
async def test_vulnstore_full_purchasing_flow():
    transport = ASGITransport(app=target_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. List products
        resp = await client.get("/products")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 6

        # 2. Add product to cart
        resp = await client.post("/cart/add", json={"product_id": 101, "quantity": 2})
        assert resp.status_code == 200
        cart_data = resp.json()
        assert cart_data["cart_count"] == 2

        # 3. View cart
        resp = await client.get("/cart")
        assert resp.status_code == 200
        view_data = resp.json()
        assert view_data["count"] == 2
        assert view_data["subtotal"] == 599.98

        # 4. Update cart quantity
        resp = await client.post("/cart/update", json={"product_id": 101, "quantity": 3})
        assert resp.status_code == 200
        assert resp.json()["cart_count"] == 3

        # 5. Checkout
        initial_stock = next(p["stock"] for p in PRODUCTS_DB if p["id"] == 101)
        initial_balance = USER_PROFILES[1]["balance"]

        resp = await client.post(
            "/checkout",
            json={
                "payment_method": "corporate_credit_card",
                "shipping_address": "777 Cyber Defense Alley",
                "recipient_name": "Chief Security Officer",
                "username": "admin",
            },
        )
        assert resp.status_code == 200
        order_data = resp.json()
        assert order_data["order_status"] == "COMPLETED"
        assert order_data["order"]["status"] == "CONFIRMED_AND_PAID"
        assert order_data["order"]["item_count"] == 3
        assert order_data["order"]["total_amount"] == 899.97

        # Stock and balance deducted
        new_stock = next(p["stock"] for p in PRODUCTS_DB if p["id"] == 101)
        assert new_stock == initial_stock - 3
        assert USER_PROFILES[1]["balance"] == initial_balance - 899.97

        # 6. Cart is empty after checkout
        resp = await client.get("/cart")
        assert resp.json()["count"] == 0

        # 7. Orders history
        resp = await client.get("/orders")
        assert resp.status_code == 200
        assert len(resp.json()["orders"]) >= 1


@pytest.mark.asyncio
async def test_vulnstore_auth_and_register():
    transport = ASGITransport(app=target_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Login
        resp = await client.post("/auth/login", json={"username": "admin", "password": "admin123"})
        assert resp.status_code == 200
        assert resp.json()["username"] == "admin"
        assert resp.json()["role"] == "SuperAdmin"

        # Register
        resp = await client.post(
            "/auth/register",
            json={
                "username": "test_operator",
                "password": "password123",
                "full_name": "Test Operator",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["balance"] == 1000.00
