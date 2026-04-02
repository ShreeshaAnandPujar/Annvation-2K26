# API Gateway with Abuse Detection (AGAD)

> A production-grade API gateway that actively distinguishes legitimate users
> from automated attackers using behavioral analysis, probabilistic filtering,
> and graduated enforcement — built from scratch without dropping in an existing
> library.

**Live demo:** https://api-gateway-with-abuse-detection.onrender.com/docs

---

## What This Demonstrates

This project targets the two dominant API abuse patterns that standard rate
limiting cannot address: **credential stuffing** and **scraping**. Volume-based
rate limiting fails against both — a sophisticated attacker distributes credential
stuffing across many IPs and rate-limits scraping to human speeds. This system
detects both using behavioral signals: two-dimensional auth failure tracking and
timing entropy analysis.

The engineering challenge is not the detection logic itself but making it
production-safe — deploying a rule that's too aggressive will block real users at
scale. The shadow mode system solves this by logging would-be blocks against live
traffic before enforcement is enabled, which is how Cloudflare and AWS WAF roll
out new detection rules.

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                         INTERNET                                  │
└──────────────────────────────┬───────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│                     API GATEWAY (FastAPI)                         │
│                                                                   │
│  1. RequestID      → UUID trace ID on every request               │
│  2. Auth           → JWT validation, client_id + role attached    │
│  3. BloomFilter    → O(1) bad IP + bad user-agent check           │
│  4. RateLimit      → sliding window per authenticated client      │
│  5. AbuseDetector  → graduated response (throttle/block)          │
│  6. ShadowMode     → log would-be blocks before enforcement       │
│                                                                   │
└──────┬───────────────────────────────────────────┬───────────────┘
       │ allowed                                   │ blocked
       ▼                                           ▼
  Upstream Services                         429 / 403 + Retry-After
```

See [DESIGN.md](DESIGN.md) for the full architecture diagram and Redis key schema.

---

## Key Engineering Decisions

- **Sliding window over fixed window** — eliminates the boundary spike problem
  where a client can send 2N requests in 2 seconds without exceeding N per window.
  See [DESIGN.md — Decision 1](DESIGN.md#decision-1-sliding-window-over-fixed-window-rate-limiting)

- **Bloom filter for hot-path IP screening** — eliminates a Redis round-trip on
  every request. Two filters: known bad IPs and abusive user-agents, both synced
  from Redis every 60 seconds.
  See [DESIGN.md — Decision 2](DESIGN.md#decision-2-bloom-filter-for-known-bad-ip-and-user-agent-lookup)

- **Graduated response instead of binary block** — three states (ALLOWED →
  THROTTLED → SOFT_BLOCK) reduce false positive damage and avoid tipping off
  attackers.
  See [DESIGN.md — Decision 3](DESIGN.md#decision-3-graduated-response-over-binary-allowblock)

- **Database-backed RBAC with JWT role claims** — user roles stored in
  PostgreSQL, embedded in JWT at login time. Admin promotion requires a direct DB
  update and a fresh login — no server restart required.
  See [DESIGN.md — Decision 7](DESIGN.md#decision-7-database-backed-rbac-with-jwt-role-claims)

- **Shadow mode as a first-class feature** — all enforcement rules run in
  observation-only mode first. Thresholds are tuned against real traffic before
  enforcement is enabled.
  See [DESIGN.md — Decision 6](DESIGN.md#decision-6-shadow-mode-as-a-first-class-feature)

---

## Performance Characteristics

From a 60-second Locust load test with 20 concurrent users (legitimate users,
credential stuffers, and scrapers running simultaneously):

| Metric                        | Result                          |
| ----------------------------- | ------------------------------- |
| Throughput                    | 59 req/s sustained              |
| Legitimate user failure rate  | **0%**                          |
| Credential stuffing detection | Blocked within 10 attempts      |
| P50 gateway latency           | 10ms                            |
| P99 gateway latency           | 440ms (includes throttle delay) |
| Shadow events logged in 60s   | 740                             |

**Production verification** (live on Render, Upstash Redis):

150 parallel requests against the live deployment confirmed the sliding window
enforces exactly at the configured limit:

```
100 × 200 OK    ← exactly the rate limit
 50 × 429       ← every request over the limit rejected
```

Prometheus confirmed: `rate_limit_rejections_total{client_id="demo"} 200.0`
after two parallel test runs. The `client_id` label proves the JWT identity is
tracked, not the IP address.

---

## Production Deployment Notes

### Rate Limiting: Why Sequential curl Fails as a Test

A common mistake when testing rate limiting on a remote deployment is running
requests sequentially:

```bash
# This will NOT trigger rate limiting on a remote host
for i in $(seq 1 300); do curl $BASE/gateway/proxy; done
```

Over a network connection (Render free tier adds ~500ms per request), 300
sequential calls take roughly 5 minutes. The sliding window only counts requests
within the last 60 seconds — at any point only ~60 requests are in the window,
well under the 100-request limit. The limiter is working correctly; the test
method is wrong.

The correct test runs requests in parallel so they all fall within the same
60-second window:

```bash
for i in $(seq 1 150); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    $BASE/gateway/proxy \
    -H "Authorization: Bearer $TOKEN" &
done | sort | uniq -c
# Output: 100 × 200, 50 × 429
```

### Admin Role Promotion

Admin access is database-backed. To promote a user:

```sql
UPDATE users SET role = 'admin' WHERE username = 'target';
```

The user logs in again and receives a JWT with `"role": "admin"`. No server
restart required. The old token with `"role": "user"` receives 403 on admin
endpoints until it expires.

### Runtime Shadow Mode Toggle

Shadow mode can be toggled without redeployment via Redis:

```bash
# Enable shadow mode (observe but don't block)
curl -X POST $BASE/admin/shadow-mode?enabled=true \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Disable shadow mode (enforce blocks)
curl -X POST $BASE/admin/shadow-mode?enabled=false \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

The middleware reads the Redis key `config:shadow_mode_enabled` on every request,
falling back to the `SHADOW_MODE_ENABLED` environment variable if the key is absent.

---

## Quick Start

```bash
git clone https://github.com/macaulaypraise/api-gateway-with-abuse-detection
cd api-gateway-with-abuse-detection
cp .env.example .env
make dev
```

The full stack — FastAPI, Redis, PostgreSQL, and Prometheus — starts in Docker.
No manual configuration required.

Verify everything is running:

```bash
make check-infra
```

---

## API Reference

Interactive API documentation: `http://localhost:8000/docs` (local) or
`https://api-gateway-with-abuse-detection.onrender.com/docs` (live).

| Method | Path                        | Auth required | Description                              |
| ------ | --------------------------- | ------------- | ---------------------------------------- |
| POST   | `/auth/register`            | None          | Register a new user (role: user)         |
| POST   | `/auth/login`               | None          | Login and receive JWT with role claim    |
| GET    | `/gateway/proxy`            | User          | Authenticated gateway endpoint           |
| GET    | `/health`                   | None          | Service health, Redis status, pool stats |
| GET    | `/metrics`                  | None          | Prometheus metrics                       |
| GET    | `/admin/shadow-stats`       | Admin         | Aggregate shadow log by rule             |
| POST   | `/admin/block-ip/{ip}`      | Admin         | Hard block — IP added to Bloom filter    |
| POST   | `/admin/soft-block-ip/{ip}` | Admin         | Temporary block with TTL                 |
| DELETE | `/admin/soft-block-ip/{ip}` | Admin         | Lift a soft block manually               |
| POST   | `/admin/block-agent`        | Admin         | Block a user-agent string                |
| GET    | `/admin/block-status/{ip}`  | Admin         | Check current block state of an IP       |
| POST   | `/admin/shadow-mode`        | Admin         | Toggle shadow mode at runtime            |

---

## Running Tests

```bash
# Unit tests only (no Docker required)
poetry run pytest tests/unit/ -v

# All tests including integration
poetry run pytest tests/ -v

# With coverage report
poetry run pytest tests/ --cov=app --cov-report=term-missing
```

Current coverage: **93%** across **67 tests**.

---

## Load Testing

```bash
# Interactive UI — open http://localhost:8089
make load-test

# Headless — 60 second run with HTML report
make load-test-headless
```

Recommended configuration: 20 users, 2/second spawn rate, mix of
`LegitimateUser`, `CredentialStuffer`, and `Scraper` scenarios.

What to observe during the test:

- Credential stuffers escalate from 401 → 429 as the threshold is hit
- Legitimate users maintain 0% failure rate throughout
- Shadow stats accumulate at `/admin/shadow-stats`
- Prometheus counters increment at `/metrics`

---

## Stack

| Component             | Technology                                             |
| --------------------- | ------------------------------------------------------ |
| Web framework         | FastAPI + Uvicorn                                      |
| Rate limit state      | Redis 7 (sorted sets + Lua scripts)                    |
| IP/agent filtering    | Bloom filter (pybloom-live)                            |
| Auth                  | JWT (python-jose) + bcrypt (asyncio.to_thread)         |
| Database              | PostgreSQL 15 + SQLAlchemy (async)                     |
| Migrations            | Alembic                                                |
| Metrics               | Prometheus                                             |
| Logging               | structlog (JSON output)                                |
| Testing               | pytest + pytest-asyncio + Locust                       |
| Dependency management | Poetry                                                 |
| Containerisation      | Docker Compose                                         |
| CI                    | GitHub Actions                                         |
| Production            | Render (app) + Upstash (Redis) + Supabase (PostgreSQL) |

---

## Project Structure

```
agad/
├── app/
│   ├── core/           # Redis client, DB session, security, metrics, logging
│   ├── middleware/      # Six-step middleware chain
│   ├── routers/         # Auth, gateway, admin endpoints
│   ├── services/        # Rate limiter, abuse detector, bloom filter,
│   │                    # graduated response, shadow logger
│   ├── models/          # SQLAlchemy ORM models (User with UserRole enum)
│   ├── schemas/         # Pydantic request/response schemas
│   └── workers/         # Bloom filter sync background worker
├── tests/
│   ├── unit/            # Pure unit tests, no I/O
│   ├── integration/     # Tests against real Redis and PostgreSQL
│   └── load/            # Locust load test scenarios
├── migrations/          # Alembic migration files
├── DESIGN.md            # Architecture decisions and trade-offs
├── CHANGELOG.md         # Version history
├── CONTRIBUTING.md      # Local setup and contribution guide
└── docker-compose.yml   # Full local development stack
```

---

## Design Document

See [DESIGN.md](DESIGN.md) for:

- Full problem statement and constraints
- Every key decision with alternatives considered and trade-offs
- Known limitations
- What I would change at 10x scale
