"""
Synthetic API Access Log & Request Sequence Dataset Generator (Pygenic Arc)

Generates standardized synthetic datasets containing:
- Normal human shopping workflows
- Legitimate high-volume burst traffic (Flash Sale)
- Distributed / Targeted Credential Stuffing
- Machine-paced Scraping Bots (low timing entropy)
- Endpoint Enumeration & IDOR probing
- Workflow sequence violations (skipping steps to /checkout)

Outputs:
- data/synthetic_api_logs.json
- data/synthetic_api_logs.csv
"""

import csv
import json
import random
import time
from typing import Any, Dict, List

TOTAL_BASE_TIME = time.time() - 3600  # 1 hour ago


def generate_scenario_logs() -> List[Dict[str, Any]]:
    logs: List[Dict[str, Any]] = []

    # ── 1. Legitimate Human Shopper Sessions ──────────────────────────────
    for user_idx in range(1, 15):
        client_id = f"user_{user_idx}"
        client_ip = f"192.168.1.{10 + user_idx}"
        curr_time = TOTAL_BASE_TIME + random.uniform(10, 100)

        # Compliant sequence: Login -> Browse -> Product Detail -> Add to Cart -> Checkout
        flow = [
            ("POST", "/auth/login", 200, client_id),
            ("GET", "/products", 200, None),
            ("GET", f"/products/{random.choice([101, 102, 103])}", 200, None),
            ("POST", "/cart/add", 200, None),
            ("GET", "/cart", 200, None),
            ("POST", "/checkout", 200, None),
        ]
        for method, path, status, username in flow:
            curr_time += random.uniform(1.2, 5.8)  # Natural human pause (high entropy)
            logs.append({
                "timestamp": round(curr_time, 3),
                "client_id": client_id,
                "client_ip": client_ip,
                "method": method,
                "path": path,
                "status_code": status,
                "username": username or "",
                "label": "BENIGN",
                "scenario_name": "Standard Human Shopper",
            })

    # ── 2. Benign High-Volume Flash Sale Traffic ──────────────────────────
    flash_time = TOTAL_BASE_TIME + 500
    for burst_idx in range(1, 40):
        client_id = f"flash_buyer_{burst_idx}"
        client_ip = f"10.50.0.{burst_idx}"
        user_time = flash_time + random.uniform(0.1, 2.0)

        flow = [
            ("GET", "/products", 200, None),
            ("GET", "/products/101", 200, None),
            ("POST", "/cart/add", 200, None),
            ("POST", "/checkout", 200, None),
        ]
        for method, path, status, _ in flow:
            user_time += random.uniform(0.6, 2.5)  # Fast human, but high variance
            logs.append({
                "timestamp": round(user_time, 3),
                "client_id": client_id,
                "client_ip": client_ip,
                "method": method,
                "path": path,
                "status_code": status,
                "username": "",
                "label": "BENIGN_BURST",
                "scenario_name": "Flash Sale Peak Traffic",
            })

    # ── 3. Credential Stuffing Attack ─────────────────────────────────────
    stuffer_time = TOTAL_BASE_TIME + 1200
    stuffer_ip = "198.51.100.88"
    usernames_pool = ["admin", "root", "support", "test", "billing", "service", "john", "alex"]
    for i in range(12):
        stuffer_time += random.uniform(0.05, 0.15)  # rapid machine speed
        logs.append({
            "timestamp": round(stuffer_time, 3),
            "client_id": "stuffer_bot",
            "client_ip": stuffer_ip,
            "method": "POST",
            "path": "/auth/login",
            "status_code": 401,  # Auth failures
            "username": random.choice(usernames_pool),
            "label": "CREDENTIAL_STUFFING",
            "scenario_name": "Distributed Credential Stuffing",
        })

    # ── 4. Content Scraping Bot (Fixed Timing / Low Entropy) ──────────────
    scraper_time = TOTAL_BASE_TIME + 1800
    scraper_ip = "203.0.113.45"
    for i in range(15):
        scraper_time += 0.125  # Exactly 125ms constant interval (entropy ~ 0ms)
        logs.append({
            "timestamp": round(scraper_time, 3),
            "client_id": "price_crawler",
            "client_ip": scraper_ip,
            "method": "GET",
            "path": f"/products/{100 + (i % 5)}",
            "status_code": 200,
            "username": "",
            "label": "SCRAPING",
            "scenario_name": "High-Speed Pricing Scraper",
        })

    # ── 5. Endpoint Enumeration & IDOR Probing ────────────────────────────
    scanner_time = TOTAL_BASE_TIME + 2400
    scanner_ip = "185.220.101.5"
    # Sequential ID walk
    for user_id in range(1, 12):
        scanner_time += random.uniform(0.1, 0.3)
        logs.append({
            "timestamp": round(scanner_time, 3),
            "client_id": "recon_scanner",
            "client_ip": scanner_ip,
            "method": "GET",
            "path": f"/api/v1/users/{user_id}",
            "status_code": 200 if user_id <= 5 else 404,
            "username": "",
            "label": "ENDPOINT_ENUMERATION",
            "scenario_name": "Sequential IDOR & User Enumeration",
        })

    # Directory fuzzing (404 probing)
    hidden_paths = ["/admin/backup", "/config.json", "/.env", "/admin/db", "/phpmyadmin"]
    for p in hidden_paths:
        scanner_time += random.uniform(0.1, 0.25)
        logs.append({
            "timestamp": round(scanner_time, 3),
            "client_id": "recon_scanner",
            "client_ip": scanner_ip,
            "method": "GET",
            "path": p,
            "status_code": 404,
            "username": "",
            "label": "ENDPOINT_ENUMERATION",
            "scenario_name": "Directory Fuzzing / 404 Probing",
        })

    # ── 6. Abnormal Sequence / Workflow Bypass Exploit ────────────────────
    exploit_time = TOTAL_BASE_TIME + 3000
    exploit_ip = "194.26.29.112"
    # Direct jump to checkout without auth or cart
    for step in ["/products", "/checkout", "/checkout", "/checkout"]:
        exploit_time += random.uniform(0.2, 0.8)
        logs.append({
            "timestamp": round(exploit_time, 3),
            "client_id": "exploit_actor",
            "client_ip": exploit_ip,
            "method": "POST" if step == "/checkout" else "GET",
            "path": step,
            "status_code": 200,
            "username": "",
            "label": "ABNORMAL_SEQUENCE",
            "scenario_name": "Checkout State Bypass Exploit",
        })

    # Sort all logs chronologically
    logs.sort(key=lambda x: x["timestamp"])
    return logs


def main():
    from pathlib import Path
    base_dir = Path(__file__).resolve().parent
    data_dir = base_dir / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    dataset = generate_scenario_logs()

    # Save JSON
    json_path = data_dir / "synthetic_api_logs.json"
    with open(json_path, "w") as f:
        json.dump(dataset, f, indent=2)

    # Save CSV
    csv_path = data_dir / "synthetic_api_logs.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(dataset[0].keys()))
        writer.writeheader()
        writer.writerows(dataset)

    print(f"Generated {len(dataset)} synthetic access log records:")
    print(f" -> JSON: {json_path}")
    print(f" -> CSV:  {csv_path}")


if __name__ == "__main__":
    main()
