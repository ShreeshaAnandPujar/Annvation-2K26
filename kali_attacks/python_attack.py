import random
"""
Kali Linux Attack Simulation Suite (Pygenic Arc / Team Rudranix)

Demonstrates live cyberattacks against:
1. Direct Unprotected Target Application (Port 8001)
2. Protected API Gateway (Port 8000/gateway)

Demonstrates:
- Credential Stuffing
- Content Scraping (Timing Regularity)
- Sequential IDOR & User Enumeration
- State Machine Sequence Violation
- Legitimate Human Traffic Flow
"""

import argparse
import json
import time
import urllib.error
import urllib.request

DIRECT_URL = "http://127.0.0.1:8001"
GATEWAY_URL = "http://127.0.0.1:8000/gateway"


def send_http(url: str, method: str = "GET", data: dict = None, headers: dict = None) -> tuple[int, str, dict]:
    headers = headers or {}
    encoded_data = None
    if data is not None:
        encoded_data = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=encoded_data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.read().decode("utf-8")
            return resp.status, body, resp_headers
    except urllib.error.HTTPError as e:
        resp_headers = {k.lower(): v for k, v in e.headers.items()}
        body = e.read().decode("utf-8")
        return e.code, body, resp_headers
    except Exception as e:
        return 0, str(e), {}


def attack_credential_stuffing(base_url: str):
    print(f"\n[1] LAUNCHING CREDENTIAL STUFFING ATTACK on {base_url}/auth/login")
    passwords = ["wrongpass1", "wrongpass2", "admin99", "secret", "hackme", "guest123", "hunter2"]
    headers = {"X-Forwarded-For": "198.51.100.11", "X-Client-ID": "stuffer_bot"}
    for i, pwd in enumerate(passwords, start=1):
        url = f"{base_url}/auth/login"
        status, body, h = send_http(url, method="POST", data={"username": "admin", "password": pwd}, headers=headers)
        score = h.get("x-threat-score", "N/A (Direct)")
        cat = h.get("x-threat-category", "N/A")
        action = h.get("x-threat-action", "N/A")
        print(f"  Attempt {i} with '{pwd}': HTTP {status} | Score: {score} | Category: {cat} | Action: {action}")
        if status in (429, 403):
            print(f"  >>> GATEWAY MITIGATION TRIGGERED! Status: {status} (Retry-After: {h.get('retry-after')}s)")
            print(f"  >>> Response Evidence: {body[:140]}...")
            break
        time.sleep(0.08)


def attack_scraping(base_url: str):
    print(f"\n[2] LAUNCHING MACHINE-PACED CONTENT SCRAPING on {base_url}/products")
    headers = {"X-Forwarded-For": "198.51.100.22", "X-Client-ID": "scraper_bot"}
    for i in range(1, 12):
        url = f"{base_url}/products"
        status, body, h = send_http(url, method="GET", headers=headers)
        score = h.get("x-threat-score", "N/A (Direct)")
        cat = h.get("x-threat-category", "N/A")
        action = h.get("x-threat-action", "N/A")
        print(f"  Scrape Request {i} (100ms pacing): HTTP {status} | Score: {score} | Category: {cat} | Action: {action}")
        if status in (429, 403):
            print(f"  >>> GATEWAY BLOCKED SCRAPER! Caught by Timing Entropy! Action: {action}")
            break
        time.sleep(0.10)


def attack_idor(base_url: str):
    print(f"\n[3] LAUNCHING IDOR / ENDPOINT ENUMERATION on {base_url}/users/{{id}}")
    headers = {"X-Forwarded-For": "198.51.100.33", "X-Client-ID": "recon_scanner"}
    for uid in range(1, 8):
        url = f"{base_url}/users/{uid}"
        status, body, h = send_http(url, method="GET", headers=headers)
        score = h.get("x-threat-score", "N/A (Direct)")
        cat = h.get("x-threat-category", "N/A")
        action = h.get("x-threat-action", "N/A")
        if status == 200:
            preview = body[:40] + "..." if len(body) > 40 else body
            print(f"  Walking ID /users/{uid}: HTTP 200 (Extracted: {preview}) | Score: {score}")
        elif status in (429, 403):
            print(f"  Walking ID /users/{uid}: HTTP {status} | >>> GATEWAY BLOCKED ENUMERATION! Category: {cat}")
            break
        else:
            print(f"  Walking ID /users/{uid}: HTTP {status} | Score: {score} | Category: {cat}")
        time.sleep(0.15)


def attack_sequence_bypass(base_url: str):
    print(f"\n[4] LAUNCHING WORKFLOW SEQUENCE BYPASS on {base_url}/checkout")
    headers = {"X-Forwarded-For": "198.51.100.44", "X-Client-ID": "bypass_actor"}
    # Step 1: Browse
    s1, _, h1 = send_http(f"{base_url}/products", method="GET", headers=headers)
    print(f"  Step 1: GET /products -> HTTP {s1}")

    # Step 2: Direct jump to checkout
    time.sleep(0.3)
    s2, body2, h2 = send_http(f"{base_url}/checkout", method="POST", data={"payment_method": "credit_card"}, headers=headers)
    score = h2.get("x-threat-score", "N/A (Direct)")
    cat = h2.get("x-threat-category", "N/A")
    action = h2.get("x-threat-action", "N/A")
    print(f"  Step 2: POST /checkout -> HTTP {s2} | Score: {score} | Category: {cat} | Action: {action}")
    if action == "THROTTLED":
        print(f"  >>> GATEWAY DETECTED SEQUENCE ANOMALY! Action: THROTTLED (Degraded with delay)")
    print(f"  Response: {body2}")


def run_benign(base_url: str):
    print(f"\n[5] RUNNING LEGITIMATE HUMAN FLOW on {base_url}")
    headers = {"X-Forwarded-For": "198.51.100.99", "X-Client-ID": "valid_user"}
    flow = [
        ("POST", "/auth/login", {"username": "admin", "password": "admin123"}),
        ("GET", "/products", None),
        ("GET", "/products/101", None),
        ("POST", "/cart/add", {"product_id": 101, "quantity": 1}),
        ("POST", "/checkout", {"payment_method": "credit_card"}),
    ]
    for method, endpoint, data in flow:
        status, body, h = send_http(f"{base_url}{endpoint}", method=method, data=data, headers=headers)
        score = h.get("x-threat-score", "N/A (Direct)")
        cat = h.get("x-threat-category", "N/A")
        print(f"  Legitimate Step {method} {endpoint} -> HTTP {status} | Score: {score} | Category: {cat}")
        time.sleep(random.uniform(1.0, 2.2))


def main():
    parser = argparse.ArgumentParser(description="Kali Linux Attack Simulator for Pygenic Arc API Gateway")
    parser.add_argument("--target", choices=["direct", "gateway"], default="gateway",
                        help="'direct' hits vulnerable app (8001); 'gateway' hits protected gateway (8000/gateway)")
    parser.add_argument("--attack", choices=["stuffing", "scraping", "idor", "sequence", "benign", "all"], default="all")
    args = parser.parse_args()

    base_url = DIRECT_URL if args.target == "direct" else GATEWAY_URL
    print(f"==================================================")
    print(f"TARGET MODE: {args.target.upper()} ({base_url})")
    print(f"==================================================")

    if args.attack in ("stuffing", "all"):
        attack_credential_stuffing(base_url)
    if args.attack in ("scraping", "all"):
        attack_scraping(base_url)
    if args.attack in ("idor", "all"):
        attack_idor(base_url)
    if args.attack in ("sequence", "all"):
        attack_sequence_bypass(base_url)
    if args.attack in ("benign", "all"):
        run_benign(base_url)


if __name__ == "__main__":
    main()
