# 🛡️ Kali Linux Live Attack & Evaluation Demonstration Guide
**Team Rudranix — Pygenic Arc (API Abuse & Behavioral Threat Detection)**

This guide provides step-by-step commands to launch real cyberattacks from your **Kali Linux Virtual Machine** against your host machine and show mentors the live protection in the Web SOC Dashboard.

---

## 🌐 Network Setup (Kali VM -> Host Mac)

Your host Mac has the following IP addresses bound to both servers:
1. **VM Bridge / Hypervisor IP**: `192.168.64.1` *(Default for UTM, VMware, Parallels, VirtualBox)*
2. **Local Area Network (Wi-Fi) IP**: `10.0.11.104`

### 1. Verify Connectivity from Kali Linux Terminal
Inside your Kali Linux VM terminal, run:
```bash
# Test ping to Host
ping -c 3 192.168.64.1

# Test reaching the Gateway
curl -s http://192.168.64.1:8000/health
# Expected: {"status":"ok","redis":"ok",...}

# Test reaching the Target App
curl -s http://192.168.64.1:8001/products
# Expected: {"total":5,"products":[...]}
```
*(If `192.168.64.1` is unreachable, use `10.0.11.104`)*

---

## 🖥️ Mentor Presentation Setup (Browser Tabs)

Open these 4 tabs on your host machine (or inside Kali browser):

| Service | URL | What to Show Mentors |
| :--- | :--- | :--- |
| **SOC Threat Intelligence Dashboard** | `http://localhost:8000/` | Real-time live threat stream, risk scores, Markov anomalies, active blocks with countdown, unblock buttons. |
| **Gateway FastAPI Swagger Docs** | `http://localhost:8000/docs` | Standard OpenAPI schema, gateway proxy route, auth endpoints. |
| **Target E-Commerce App UI** | `http://localhost:8001/` | Functional store frontend, product catalog, cart checkout, IDOR user explorer. |
| **Target App Swagger Docs** | `http://localhost:8001/docs` | Upstream API endpoints without gateway layer. |

---

## ⚔️ Live Cyberattacks from Kali Linux

You can launch attacks using either the **Automated Shell Suite**, **Hydra / ffuf / standard Kali tools**, or the **Python Attack Suite**.

### Option A: The Complete Attack Suite (Shell Script)
Copy `kali_attacks/` to your Kali VM (or run directly via shared folder):
```bash
cd kali_attacks
chmod +x attack_suite.sh

# 1. First run against UNPROTECTED Target App (Show Mentors how it FAILS to stop attacks):
./attack_suite.sh direct 192.168.64.1

# 2. Now run against the PROTECTED Gateway (Show Mentors how Pygenic Arc STOPS attacks):
./attack_suite.sh gateway 192.168.64.1
```

---

### Option B: Individual Native Kali Linux Attacks

#### 1. Credential Stuffing (Password Spraying)
```bash
# Spraying passwords against /gateway/auth/login
for pwd in pass1 pass2 pass3 pass4 pass5 pass6; do
  curl -i -X POST http://192.168.64.1:8000/gateway/auth/login \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"admin\", \"password\": \"$pwd\"}"
  sleep 0.1
done
```
- **Gateway Response**: First few return `401 Unauthorized`. Once the adaptive threshold is exceeded, the Gateway returns `429 Too Many Requests` with `X-Threat-Category: CREDENTIAL_STUFFING` and locks out the Kali IP for 180s!
- **SOC Dashboard**: A red alert card appears with the active block countdown, IP, and reason.

#### 2. Automated Content Scraping (Timing Entropy Anomaly)
```bash
# High-frequency machine-paced scraping (80ms rigid timing)
for i in $(seq 1 12); do
  curl -i http://192.168.64.1:8000/gateway/products
  sleep 0.08
done
```
- **Gateway Response**: The timing entropy analyzer detects low timing standard deviation (< 30ms variance), classifying the client as an automated bot scraper. Throttling and `429` enforcement kick in.
- **SOC Dashboard**: Category displays `SCRAPING` with entropy metrics in evidence.

#### 3. Sequential IDOR / Endpoint Enumeration
```bash
# Walking sequential user IDs to exfiltrate private database rows
for id in $(seq 1 8); do
  curl -i http://192.168.64.1:8000/gateway/users/$id
  sleep 0.15
done
```
- **Unprotected (Port 8001)**: Mentors see every single user profile, email, and API key leaked!
- **Protected (Port 8000)**: Behavioral engine detects linear ID walking sequence (`1, 2, 3, 4`) and directory probing (`404` distribution), blocking further access.

#### 4. Abnormal Workflow Sequence Bypass
```bash
# Attackers attempt to jump directly to /checkout without browsing or adding to cart
curl -i -X POST http://192.168.64.1:8000/gateway/checkout \
  -H "Content-Type: application/json" \
  -d '{"payment_method": "credit_card"}'
```
- **Gateway Response**: Markov Chain sequence model detects an illegal state transition (`START -> /checkout` has near-zero transition probability). Request is blocked with `ABNORMAL_SEQUENCE`.

---

### Option C: Python Attack Suite
```bash
python3 python_attack.py --host 192.168.64.1 --target gateway --attack all
```

---

## 🤖 24/7 Autonomous AI Agent & Defense Demonstration

Pygenic Arc features a self-governing **Autonomous AI Threat Sentinel** operating 24/7 at the perimeter:
1. **Autonomous Auto-Blocking**: When malicious behaviors are detected from an attacking IP (Kali Linux VM), the AI Agent immediately computes attack attribution confidence and enforces an autonomic perimeter ban across API Gateway and Bloom Filter.
2. **Autonomous Monitoring ON / OFF Toggle**:
   - In the SOC Dashboard (`http://localhost:8000/`), use the **AUTONOMOUS MONITORING [ON / OFF]** toggle.
   - **Mode ON**: AI Agent automatically quarantines attacker IPs with zero human intervention.
   - **Mode OFF (Standby)**: Passive monitoring mode where attacks are flagged and scored on the radar, but bans require manual approval.
3. **Real-time AI Decision Stream**:
   - The dashboard displays a live feed of the AI Agent's explainable thought process:
     - `Observation`: Multi-failure or low entropy anomaly detection.
     - `Analysis`: Mathematical feature contribution and confidence calculation.
     - `Verdict`: Critical threat confirmation with confidence score.
     - `Mitigation Applied`: Automated perimeter quarantine with TTL.

---

## 🏆 Key Talking Points for Evaluators & Mentors

1. **24/7 Self-Governing Autonomous AI Sentinel**:
   - Autonomous background patrol loop constantly analyzes sliding-window telemetry.
   - Operators have full executive control with an instant **Autonomous ON/OFF switch**.

2. **Defense-in-Depth vs Static Rate Limiting**:
   - Traditional WAFs only count requests per second (RPS).
   - Pygenic Arc uses **sliding window entropy**, **dual-axis failure correlation**, and **Markov transition matrices** to detect low-and-slow automated attacks that slip under static rate limits.

3. **Zero False Positives for Human Bursts**:
   - Normal users generating legitimate bursts (e.g. during a flash sale) exhibit human inter-arrival variance and standard workflow navigation (`/products -> /cart/add -> /checkout`). The engine scores them `BENIGN` or `BENIGN_BURST`.

4. **Explainability & SOC Telemetry**:
   - Every mitigation comes with rich structured evidence:
     `(risk_score, behaviour_category, evidence)`
   - Evaluators can view exact mathematical reasons (timing entropy ms, ID sequences, Markov log-likelihood) directly in the UI.
