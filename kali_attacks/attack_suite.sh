#!/usr/bin/env bash
# ==============================================================================
# Pygenic Arc — Kali Linux Live Cyberattack Demonstration Script (Team Rudranix)
# ==============================================================================
# Usage:
#   ./attack_suite.sh direct       # Launch attacks directly at vulnerable app (Port 8001)
#   ./attack_suite.sh gateway      # Launch attacks through protected Gateway (Port 8000)
# ==============================================================================

MODE="${1:-gateway}"
GATEWAY_HOST="${GATEWAY_HOST:-127.0.0.1}"
DIRECT_HOST="${DIRECT_HOST:-127.0.0.1}"

if [ "$MODE" = "direct" ]; then
  BASE_URL="http://${DIRECT_HOST}:8001"
  echo "=========================================================="
  echo ">>> ATTACKING DIRECT TARGET APP (UNPROTECTED): $BASE_URL"
  echo ">>> Vulnerabilities will SUCCEED and bypass security."
  echo "=========================================================="
else
  BASE_URL="http://${GATEWAY_HOST}:8000/gateway"
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
  STATUS=$(curl -s -o /tmp/resp.json -w "%{http_code}" -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"admin\", \"password\": \"$pwd\"}")
  
  SCORE=$(curl -s -I -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"admin\", \"password\": \"$pwd\"}" | grep -i "x-threat-score" | tr -d '\r')
  
  echo " -> Attempt with '$pwd': HTTP $STATUS | $SCORE"
  if [ "$STATUS" = "429" ]; then
    echo " [!] GATEWAY TRIGGERED SOFT-BLOCK (429 Too Many Requests)!"
    cat /tmp/resp.json
    echo ""
    break
  fi
  sleep 0.1
done

echo ""
echo "----------------------------------------------------------"
echo "[2] ATTACK: Machine-Paced Content Scraping on /products"
echo "----------------------------------------------------------"
echo "[*] Sending machine-paced requests at exact 100ms intervals..."
for i in {1..10}; do
  STATUS=$(curl -s -o /tmp/resp.json -w "%{http_code}" "$BASE_URL/products")
  SCORE=$(curl -s -I "$BASE_URL/products" | grep -i "x-threat-score" | tr -d '\r')
  echo " -> Request $i: HTTP $STATUS | $SCORE"
  if [ "$STATUS" = "429" ] || [ "$STATUS" = "403" ]; then
    echo " [!] GATEWAY DETECTED SCRAPER VIA TIMING ENTROPY!"
    break
  fi
  sleep 0.10
done

echo ""
echo "----------------------------------------------------------"
echo "[3] ATTACK: Sequential IDOR & User Profile Enumeration"
echo "----------------------------------------------------------"
echo "[*] Walking /users/{1..7} to exfiltrate private accounts..."
for uid in {1..7}; do
  STATUS=$(curl -s -o /tmp/resp.json -w "%{http_code}" "$BASE_URL/users/$uid")
  CAT=$(curl -s -I "$BASE_URL/users/$uid" | grep -i "x-threat-category" | tr -d '\r')
  if [ "$STATUS" = "200" ]; then
    DATA=$(head -c 40 /tmp/resp.json)
    echo " -> ID $uid: HTTP 200 (Data Leaked: $DATA...) | $CAT"
  else
    echo " -> ID $uid: HTTP $STATUS | $CAT"
  fi
  if [ "$STATUS" = "429" ]; then
    echo " [!] GATEWAY DETECTED SEQUENTIAL IDENTIFIER ENUMERATION!"
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
STATUS=$(curl -s -o /tmp/resp.json -w "%{http_code}" -X POST "$BASE_URL/checkout" \
  -H "Content-Type: application/json" \
  -d '{"payment_method": "credit_card"}')
CAT=$(curl -s -I -X POST "$BASE_URL/checkout" \
  -H "Content-Type: application/json" \
  -d '{"payment_method": "credit_card"}' | grep -i "x-threat-category" | tr -d '\r')
ACTION=$(curl -s -I -X POST "$BASE_URL/checkout" \
  -H "Content-Type: application/json" \
  -d '{"payment_method": "credit_card"}' | grep -i "x-threat-action" | tr -d '\r')
echo " -> Checkout Result: HTTP $STATUS | $CAT | $ACTION"
cat /tmp/resp.json
echo ""

echo ""
echo "=========================================================="
echo "Demonstration complete for mode: $MODE"
echo "=========================================================="
