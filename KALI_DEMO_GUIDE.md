# API Abuse & Behavioral Threat Detection (Pygenic Arc)
### Team Rudranix — Live Attack & Defense Demonstration Guide

---

## 1. System Architecture

```
                  ┌────────────────────────────────────────┐
                  │          KALI LINUX ATTACKER           │
                  │   (Hydra / ffuf / curl / Custom Bot)   │
                  └───────────────┬────────────────────────┘
                                  │
         ┌────────────────────────┴────────────────────────┐
         │                                                 │
   [Direct Attack]                                  [Protected Route]
   http://host:8001/                                http://host:8000/gateway/
         │                                                 │
         ▼                                                 ▼
┌──────────────────────┐                    ┌───────────────────────────────┐
│ VULNERABLE TARGET    │                    │      PYGENIC ARC GATEWAY      │
│     APP (VulnStore)  │                    │   (Behavioral Threat Engine)  │
│                      │                    ├───────────────────────────────┤
│ • Brute-force works  │                    │ 1. Dual-Axis Auth Tracker     │
│ • Scraping succeeds  │                    │ 2. Timing Entropy Evaluator   │
│ • IDOR leaks users   │                    │ 3. IDOR / Enumeration Engine  │
│ • Checkout bypassed  │                    │ 4. Markov Sequence Model      │
│                      │                    │ 5. Graduated Mitigation       │
└──────────────────────┘                    └──────────────┬────────────────┘
                                                           │ (Allowed Traffic Only)
                                                           ▼
                                            ┌───────────────────────────────┐
                                            │ Protected Upstream Target App │
                                            └───────────────────────────────┘
```

---

## 2. Quick Start: Starting the Services

### Terminal 1: Start the Vulnerable Upstream Target App (Port 8001)
```bash
python target_app/main.py
```
*Runs at `http://127.0.0.1:8001`.*

### Terminal 2: Start the Pygenic Arc API Gateway (Port 8000)
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```
*Runs at `http://127.0.0.1:8000`.*

---

## 3. Demonstration Walkthrough: Direct vs. Protected

### Phase 1: Attack the Unprotected Target App
Show the judges that the application is natively vulnerable:
```bash
# Direct attack on Port 8001
./kali_attacks/attack_suite.sh direct
# Or via python:
python kali_attacks/python_attack.py --target direct
```
**Results to Show Judges:**
1. **Credential Stuffing**: Unlimited login attempts, zero rate limiting, passwords tested with HTTP 401 until cracked.
2. **Scraping**: High-frequency curl requests dump product catalog in milliseconds.
3. **IDOR / Enumeration**: Sequential user IDs `/users/1`, `/users/2` return confidential customer records and API keys.
4. **Sequence Bypass**: Hitting `POST /checkout` directly succeeds without an item in the shopping cart!

---

### Phase 2: Route the Attack Through the API Gateway
Demonstrate that the Gateway behavioral engine intercepts and neutralizes the threats:
```bash
# Protected route through Port 8000/gateway
./kali_attacks/attack_suite.sh gateway
# Or via python:
python kali_attacks/python_attack.py --target gateway
```
**Results to Show Judges:**
1. **Credential Stuffing Detected**: After threshold attempts, Gateway returns `HTTP 429 Too Many Requests` with `Retry-After: 180` and `X-Threat-Category: CREDENTIAL_STUFFING`.
2. **Scraping Throttled & Blocked**: Inter-arrival variance analyzed. Near-zero entropy (<30ms) triggers `SCRAPING` block.
3. **Sequential IDOR Blocked**: Resource walking pattern `/users/{1..5}` identified as enumeration attack.
4. **Sequence Violation Blocked**: Markov transition model detects jumping from `START` to `/checkout`, assigning high sequence penalty.
5. **Legitimate Burst Permitted**: High-volume human shoppers with natural variance pass through cleanly (`BENIGN_BURST`, `HTTP 200`).

---

## 4. Live Hackathon Presentation: Interactive Replay Tool

To show why normal and malicious scenarios differ (exact rubric match):
```bash
python demo_replay.py
```
This tool visualizes:
- Real-time animated request streams
- Live Risk Gauge (`0.00` to `1.00`)
- Exact explainability breakdown showing *why* the verdict was reached (timing entropy, auth failure density, sequence likelihood).

---

## 5. Offline Synthetic Log Assessment

To demonstrate log ingestion against the synthetic dataset:
```bash
python log_analyzer.py --file data/synthetic_api_logs.json
```
Produces `output/threat_assessment_results.json` adhering to the required schema:
`[ { "risk_score": 0.94, "behaviour_category": "ENDPOINT_ENUMERATION", "evidence": { ... } } ]`.
