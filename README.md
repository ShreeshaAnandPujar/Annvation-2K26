# API Gateway with Abuse Detection (AGAD)

> A production-grade API gateway that actively distinguishes legitimate users
> from automated attackers using behavioral analysis, probabilistic filtering,
> and graduated enforcement — built from scratch without dropping in an existing
> library.

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
│  2. Auth           → JWT validation, client_id attached           │
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

- **Shadow mode as a first-class feature** — all enforcement rules run in
  observation-only mode first. Thresholds are tuned against real traffic before
  enforcement is enabled.
  See [DESIGN.md — Decision 6](DESIGN.md#decision-6-shadow-mode-as-a-first-class-feature)

---

## Performance Characteristics

From a 60-second Locust load test with 20 concurrent users (legitimate users,
credential stuffers, and scrapers running simultaneously):

| Metric | Result |
|---|---|
| Throughput | 59 req/s sustained |
| Legitimate user failure rate | **0%** |
| Credential stuffing detection | Blocked within 10 attempts |
| P50 gateway latency | 10ms |
| P99 gateway latency | 440ms (includes throttle delay) |
| Shadow events logged in 60s | 740 |

---

## Quick Start

```bash
git clone <repo-url> && cd agad
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

Interactive API documentation is available at `http://localhost:8000/docs` once
the stack is running.

Key endpoints:

| Method | Path | Description |
|---|---|---|
| POST | `/auth/register` | Register a new user |
| POST | `/auth/login` | Login and receive JWT token |
| GET | `/gateway/proxy` | Authenticated gateway endpoint |
| GET | `/health` | Service health with Redis status |
| GET | `/metrics` | Prometheus metrics |
| GET | `/admin/shadow-stats` | Aggregate shadow log by rule |
| POST | `/admin/block-ip/{ip}` | Hard block an IP (Bloom filter) |
| POST | `/admin/soft-block-ip/{ip}` | Temporary block with TTL |
| POST | `/admin/block-agent` | Block a user-agent string |
| GET | `/admin/block-status/{ip}` | Check current block state |

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

Current coverage: **93%** across 63 tests.

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
- Shadow stats grow at `/admin/shadow-stats` with `Retry-After` token

---

## Stack

| Component | Technology |
|---|---|
| Web framework | FastAPI + Uvicorn |
| Rate limit state | Redis 7 (sorted sets + Lua scripts) |
| IP/agent filtering | Bloom filter (pybloom-live) |
| Auth | JWT (python-jose) + bcrypt |
| Database | PostgreSQL 15 + SQLAlchemy (async) |
| Migrations | Alembic |
| Metrics | Prometheus |
| Testing | pytest + pytest-asyncio + Locust |
| Dependency management | Poetry |
| Containerisation | Docker Compose |

---

## Project Structure

```
agad/
├── app/
│   ├── core/           # Redis client, DB session, security, exceptions
│   ├── middleware/      # Six-step middleware chain
│   ├── routers/         # Auth, gateway, admin endpoints
│   ├── services/        # Business logic — rate limiter, abuse detector,
│   │                    # bloom filter, graduated response, shadow logger
│   ├── models/          # SQLAlchemy ORM models
│   ├── schemas/         # Pydantic request/response schemas
│   └── workers/         # Bloom filter sync background worker
├── tests/
│   ├── unit/            # Pure unit tests, no I/O
│   ├── integration/     # Tests against real Redis and PostgreSQL
│   └── load/            # Locust load test scenarios
├── migrations/          # Alembic migration files
├── DESIGN.md            # Architecture decisions and trade-offs
└── docker-compose.yml   # Full local development stack
```

---

## Design Document

See [DESIGN.md](DESIGN.md) for:
- Full problem statement and constraints
- Every key decision with alternatives considered and trade-offs
- Known limitations
- What I would change at 10x scale
