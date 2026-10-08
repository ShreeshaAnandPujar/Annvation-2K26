#!/usr/bin/env bash
# ==============================================================================
# Pygenic Arc — Kali Linux Live Cyberattack Demonstration Script (Team Rudranix)
# ==============================================================================
# Usage:
#   ./attack_suite.sh direct       # Launch attacks directly at vulnerable app (Port 8001)
#   ./attack_suite.sh gateway      # Launch attacks through protected Gateway (Port 8000)
# ==============================================================================

MODE="${1:-gateway}"
TARGET_IP="${2:-${GATEWAY_HOST:-192.168.64.1}}"

if [ "$MODE" = "direct" ]; then
  BASE_URL="http://${TARGET_IP}:8001"
  echo "=========================================================="
  echo ">>> ATTACKING DIRECT TARGET APP (UNPROTECTED): $BASE_URL"
  echo ">>> Vulnerabilities will SUCCEED and bypass security."
  echo "=========================================================="
else
  BASE_URL="http://${TARGET_IP}:8000/gateway"
  echo "=========================================================="
  echo ">>> ATTACKING THROUGH API THREAT GATEWAY (PROTECTED): $BASE_URL"
  echo ">>> Behavioral Engine will DETECT, SCORE & BLOCK threats."
  echo "=========================================================="
fi

echo ""
echo "----------------------------------------------------------"
echo "[1] ATTACK: Credential Stuffing on /auth/login"
echo "----------------------------------------------------------"
echo "[*] Spraying passwords against 'admin' account..."
for pwd in "pass1" "pass2" "pass3" "pass4" "pass5" "pass6" "pass7"; do
  STATUS=$(curl -s -D /tmp/hdrs.txt -o /tmp/resp.json -w "%{http_code}" -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"admin\", \"password\": \"$pwd\"}")
  
  SCORE=$(grep -i "x-threat-score:" /tmp/hdrs.txt | tr -d '\r')
  CAT=$(grep -i "x-threat-category:" /tmp/hdrs.txt | tr -d '\r')
  ACTION=$(grep -i "x-threat-action:" /tmp/hdrs.txt | tr -d '\r')
  
  echo " -> Attempt with '$pwd': HTTP $STATUS | $SCORE | $CAT | $ACTION"
  if [ "$STATUS" = "429" ] || [ "$STATUS" = "403" ]; then
    echo " [!] GATEWAY TRIGGERED ENFORCEMENT BLOCK (HTTP $STATUS)!"
    cat /tmp/resp.json
    echo ""
    break
  fi
  sleep 0.15
done

echo ""
echo "----------------------------------------------------------"
echo "[2] ATTACK: Machine-Paced Content Scraping on /products"
echo "----------------------------------------------------------"
echo "[*] Sending machine-paced requests at exact 80ms intervals..."
for i in {1..12}; do
  STATUS=$(curl -s -D /tmp/hdrs.txt -o /tmp/resp.json -w "%{http_code}" "$BASE_URL/products")
  SCORE=$(grep -i "x-threat-score:" /tmp/hdrs.txt | tr -d '\r')
  CAT=$(grep -i "x-threat-category:" /tmp/hdrs.txt | tr -d '\r')
  echo " -> Request $i: HTTP $STATUS | $SCORE | $CAT"
  if [ "$STATUS" = "429" ] || [ "$STATUS" = "403" ]; then
    echo " [!] GATEWAY DETECTED SCRAPER VIA TIMING ENTROPY!"
    cat /tmp/resp.json
    echo ""
    break
  fi
  sleep 0.08
done

echo ""
echo "----------------------------------------------------------"
echo "[3] ATTACK: Sequential IDOR & User Profile Enumeration"
echo "----------------------------------------------------------"
echo "[*] Walking /users/{1..7} to exfiltrate private accounts..."
for uid in {1..7}; do
  STATUS=$(curl -s -D /tmp/hdrs.txt -o /tmp/resp.json -w "%{http_code}" "$BASE_URL/users/$uid")
  CAT=$(grep -i "x-threat-category:" /tmp/hdrs.txt | tr -d '\r')
  SCORE=$(grep -i "x-threat-score:" /tmp/hdrs.txt | tr -d '\r')
  if [ "$STATUS" = "200" ]; then
    DATA=$(head -c 60 /tmp/resp.json)
    echo " -> ID $uid: HTTP 200 (Data Leaked: $DATA...) | $CAT"
  else
    echo " -> ID $uid: HTTP $STATUS | $CAT | $SCORE"
  fi
  if [ "$STATUS" = "429" ] || [ "$STATUS" = "403" ]; then
    echo " [!] GATEWAY DETECTED SEQUENTIAL IDENTIFIER ENUMERATION!"
    cat /tmp/resp.json
    echo ""
    break
  fi
  sleep 0.15
done

echo ""
echo "----------------------------------------------------------"
echo "[4] ATTACK: State Machine / Checkout Workflow Bypass"
echo "----------------------------------------------------------"
echo "[*] Step 1: Browse /products"
curl -s -o /dev/null -w " -> HTTP %{http_code}\n" "$BASE_URL/products"
echo "[*] Step 2: Directly execute /checkout without /cart/add!"
STATUS=$(curl -s -D /tmp/hdrs.txt -o /tmp/resp.json -w "%{http_code}" -X POST "$BASE_URL/checkout" \
  -H "Content-Type: application/json" \
  -d '{"payment_method": "credit_card"}')
CAT=$(grep -i "x-threat-category:" /tmp/hdrs.txt | tr -d '\r')
ACTION=$(grep -i "x-threat-action:" /tmp/hdrs.txt | tr -d '\r')
SCORE=$(grep -i "x-threat-score:" /tmp/hdrs.txt | tr -d '\r')
echo " -> Checkout Result: HTTP $STATUS | $SCORE | $CAT | $ACTION"
cat /tmp/resp.json
echo ""

echo ""
echo "----------------------------------------------------------"
echo "[5] ATTACK: Web Scanner & Malicious Fuzzing Probes"
echo "----------------------------------------------------------"
echo "[*] Sending fuzzer paths (/.env, /wp-admin, /actuator, /phpmyadmin)..."
for probe in "/.env" "/wp-admin" "/actuator/health" "/phpmyadmin"; do
  STATUS=$(curl -s -D /tmp/hdrs.txt -o /tmp/resp.json -w "%{http_code}" "$BASE_URL$probe")
  CAT=$(grep -i "x-threat-category:" /tmp/hdrs.txt | tr -d '\r')
  SCORE=$(grep -i "x-threat-score:" /tmp/hdrs.txt | tr -d '\r')
  ACTION=$(grep -i "x-threat-action:" /tmp/hdrs.txt | tr -d '\r')
  echo " -> Probe '$probe': HTTP $STATUS | $SCORE | $CAT | $ACTION"
  if [ "$STATUS" = "429" ] || [ "$STATUS" = "403" ]; then
    echo " [!] AUTONOMOUS AI AGENT BLOCKED MALICIOUS SCANNER PROBE!"
    cat /tmp/resp.json
    echo ""
    break
  fi
  sleep 0.15
done

echo ""
echo "=========================================================="
echo "Demonstration complete for mode: $MODE against $TARGET_IP"
echo "=========================================================="

