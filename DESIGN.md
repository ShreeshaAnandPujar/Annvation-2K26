# API Gateway with Abuse Detection — Design Document

## Problem Statement

Public APIs face two dominant abuse patterns that standard rate limiting cannot
address on its own:

**Credential stuffing** — automated login attempts using stolen username/password
pairs sourced from data breaches. A simple request-count rate limiter fails here
because a sophisticated attacker distributes attempts across many IPs, never
triggering a per-IP volume threshold. The attack is low-volume per source but
high-impact per target.

**Scraping** — automated, high-frequency data extraction. A scraper that
rate-limits itself to human speeds defeats volume-based detection entirely. The
signal is not how many requests are made but how regularly they arrive — human
users have high temporal variance; bots do not.

Both patterns require fundamentally different detection strategies, which is what
makes this project rich for discussion and production-relevant.

---

## Constraints

| Constraint | Target |
|---|---|
| P99 latency added by the gateway | < 10ms on non-throttled path |
| False positive rate for legitimate users | < 1% |
| Rules must be updatable | Without redeployment (thresholds in config) |
| State must be shared | Across multiple gateway instances (no in-process state) |
| Shadow mode | All rules must be validatable before enforcement |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                          INTERNET                               │
│                (clients, bots, legitimate users)                │
└─────────────────────┬───────────────────────────────────────────┘
                      │ HTTP/HTTPS
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                    API GATEWAY (FastAPI)                         │
│  ┌────────────────────────────────────────────────────────┐     │
│  │         Middleware Chain (executes in order)           │     │
│  │                                                        │     │
│  │  1. RequestID       → attach UUID trace ID             │     │
│  │  2. Auth            → validate JWT, set client_id      │     │
│  │  3. BloomFilter     → O(1) bad IP + bad agent check    │     │
│  │  4. RateLimit       → sliding window per client_id     │     │
│  │  5. AbuseDetector   → graduated response engine        │     │
│  │  6. ShadowMode      → log would-be blocks              │     │
│  └────────────────────────────────────────────────────────┘     │
└──────┬─────────────────────────────────────────┬───────────────┘
       │ allowed                                 │ blocked/throttled
       ▼                                         ▼
┌──────────────┐                    ┌────────────────────┐
│   UPSTREAM   │                    │   429 / 403        │
│   SERVICES   │                    │   + Retry-After    │
└──────────────┘                    └────────────────────┘

REDIS LAYER (shared state across all gateway instances)
┌──────────────────────────────────────────────────────┐
│  rate_limit:{client_id}    ← sliding window ZSET     │
│  failed_auth:{ip}          ← credential stuffing     │
│  failed_auth:{username}    ← per-user tracking       │
│  blocked_ip:{ip}           ← soft block with TTL     │
│  request_times:{client}    ← sorted set for scrape   │
│  shadow_log:{request_id}   ← debug/tuning data       │
│  known_bad_ips             ← Bloom filter source     │
│  abusive_agents            ← user-agent fingerprint  │
└──────────────────────────────────────────────────────┘

BLOOM FILTER (in-memory, synced from Redis every 60s)
┌──────────────────────────────────────────────────────┐
│  known_bad_ips    ← O(1) IP check, probabilistic     │
│  abusive_agents   ← user-agent fingerprinting        │
└──────────────────────────────────────────────────────┘
```

---

## Key Decisions

### Decision 1: Sliding Window over Fixed Window Rate Limiting

**Chosen:** Redis sorted set (ZSET) with Lua script atomicity

**Alternatives considered:** Fixed window counter, token bucket, leaky bucket

**Why this choice:** Fixed window counters have a boundary spike problem. A client
can make N requests in the last second of window 1 and N requests in the first
second of window 2 — sending 2N requests in two seconds while technically never
violating the per-window limit. The sliding window eliminates this by maintaining
a rolling log of request timestamps.

The Lua script wraps three Redis operations (ZADD, ZREMRANGEBYSCORE, ZCARD) into a
single atomic unit. Without this, a race condition between the remove and count
steps would allow over-counting under concurrent load.

**Trade-off:** Sorted sets use more Redis memory than a single counter. At 100
req/window with millisecond timestamps, each key holds up to 100 entries at ~50
bytes each — roughly 5KB per active client. Acceptable at the scale this system
targets.

---

### Decision 2: Bloom Filter for Known-Bad IP and User-Agent Lookup

**Chosen:** In-memory pybloom-live filter, synced from Redis every 60 seconds

**Alternatives considered:** Redis SET (exact matching), SQLite lookup table,
external threat intelligence API

**Why this choice:** Every incoming request previously required a Redis SISMEMBER
call to check known-bad IPs — a network round-trip on the hot path. The Bloom
filter keeps both IP and user-agent lists in process memory, checked before the
Redis call. At a 0.1% false positive rate on 1 million entries, the filter
requires approximately 1.1MB of memory.

The worst case is a legitimate IP or user-agent being incorrectly flagged as
malicious. Shadow mode catches these before enforcement is enabled.

**Trade-off:** The filter is probabilistic — it can produce false positives but
never false negatives. A confirmed bad IP will always be caught. The 0.1% false
positive rate is tunable via `BLOOM_FILTER_ERROR_RATE` in settings.

---

### Decision 3: Graduated Response over Binary Allow/Block

**Chosen:** Three-state enforcement engine (ALLOWED → THROTTLED → SOFT_BLOCK)

**Alternatives considered:** Binary allow/block, fixed penalty box, manual review
queue

**Why this choice:** Going directly from allowed to blocked causes two problems.
First, false positive damage is severe — a legitimate client that briefly triggered
a rule is completely cut off. Second, unsophisticated attackers are tipped off
immediately and can adjust their approach.

The three states mitigate both:
- **THROTTLED** — request is delayed by `asyncio.sleep`, served with `Retry-After`.
  Client still functions but slowly. Attacker may not notice detection.
- **SOFT_BLOCK** — 429 returned immediately, TTL-based, auto-expires. Legitimate
  users can recover without admin intervention.
- **HARD_BLOCK** — 403 returned, IP added to Bloom filter permanently. Reserved
  for confirmed malicious actors.

**Trade-off:** More code complexity than a binary block. The scoring logic in
`compute_abuse_score` must be tuned carefully — the ratio thresholds (70% of limit
triggers throttle, 100% triggers soft block) were derived from load test data.

---

### Decision 4: Two-Dimensional Auth Failure Tracking

**Chosen:** Separate Redis counters for `failed_auth:{ip}` and `failed_auth:{username}`

**Alternatives considered:** Single IP-only counter, session-based tracking, ML
anomaly detection

**Why this choice:** Credential stuffing manifests on two axes simultaneously. One
IP hitting many usernames indicates a single attacker running a script. Many IPs
hitting the same username indicates that username was leaked and is under
distributed attack.

Critically, these counters live in different Redis keys — blocking a specific IP
does not affect other IPs targeting the same user, and flagging a username as
under attack does not penalise legitimate users who happen to share a subnet.

**Trade-off:** Corporate NATs can cause false positives on the IP axis when 500
legitimate employees share one public IP. The correct response is to layer IP
signals with session-level signals rather than using IP as the sole arbiter.

---

### Decision 5: Timing Entropy for Scraping Detection

**Chosen:** Standard deviation of inter-request arrival gaps

**Alternatives considered:** ML-based anomaly detection, CAPTCHA challenges,
JavaScript fingerprinting

**Why this choice:** Human users generate requests with high temporal variance —
they click, pause, read, scroll. Bots generate requests with low variance — the
inter-arrival timing is suspiciously regular. Standard deviation over a sliding
window of the last N timestamps quantifies this difference without requiring
JavaScript execution or external services.

A sophisticated bot that rate-limits itself to human *speeds* will still be caught
if it is too *regular*. Pairing entropy analysis with user-agent screening creates
a multi-signal detection approach.

**Trade-off:** Clients behind load balancers or CDNs that merge many users into a
single upstream connection will exhibit artificially low variance. The entropy
threshold should be tuned conservatively (lower value = more sensitive) for APIs
that serve such clients.

---

### Decision 6: Shadow Mode as a First-Class Feature

**Chosen:** All enforcement rules have a shadow mode toggle that logs would-be
blocks without enforcing them

**Alternatives considered:** Staged rollout by percentage, feature flags per rule,
no shadow mode

**Why this choice:** This is how Cloudflare, Fastly, and AWS WAF roll out new
detection rules safely. Deploying an aggressive rule directly to enforcement risks
blocking real users at scale before the threshold has been validated. Shadow mode
allows rules to be run against real production traffic, with the log analysed to
measure precision before switching to enforcement.

The `GET /admin/shadow-stats` endpoint aggregates shadow events by rule, giving
operators the data needed to tune thresholds confidently.

**Trade-off:** Shadow mode adds latency to the middleware chain even when not
blocking — the event must still be logged to Redis. At 24-hour TTL and ~500 bytes
per event, this is acceptable. Shadow mode should be disabled in production once
thresholds are validated.

---

## Performance Characteristics

Results from 60-second Locust load test with 20 concurrent users (7 legitimate,
7 credential stuffers, 6 scrapers):

| Metric | Result |
|---|---|
| Throughput | 59 req/s sustained |
| Legitimate user failure rate | 0% |
| Health endpoint failure rate | 0% |
| Credential stuffing detection | Blocked within 10 attempts |
| P50 gateway latency | 10ms |
| P99 gateway latency | 440ms (includes throttle delay) |
| Shadow events logged in 60s | 740 |

---

## Known Limitations

**Redis as single point of failure.** If Redis becomes unavailable, the rate
limiter, abuse detector, and soft block checks all fail. The current implementation
does not have a fallback strategy. A production deployment should use Redis
Sentinel or Redis Cluster, and the gateway should be configured with a fail-open
or fail-closed policy depending on the business risk model.

**Shared IP in multi-tenant environments.** Corporate NATs cause IP-based signals
to be unreliable. The current system uses IP as a primary signal. A more robust
implementation would weight IP signals alongside session token, device fingerprint,
and API key.

**Bloom filter false positives.** At 0.1% error rate, approximately 1 in 1000
legitimate IPs will be incorrectly flagged. Shadow mode will surface these before
enforcement is enabled, but the operator must actively monitor shadow stats.

**Timing entropy requires warm-up.** The scraping detector needs at least 3
requests from a client before it can compute entropy. A bot that registers a new
account on each session will evade entropy detection. Pairing entropy with
user-agent analysis and registration rate limiting addresses this.

**Token expiry during load tests.** JWT tokens have a 30-minute expiry. Long-running
load tests will see authentication failures as tokens expire. This is correct
behavior — it is not a system defect.

---

## What I Would Change at 10x Scale

**Move detection rules to a dedicated rule engine service.** Abuse patterns evolve
faster than product features. Embedding detection logic in the gateway means
redeploying the gateway to update rules. A separate rules service loaded at runtime
from Redis decouples detection iteration from gateway deployment.

**Redis Cluster instead of single-node Redis.** Single-node Redis becomes a
bottleneck above approximately 100,000 requests/second and a reliability risk in
any production deployment. Redis Cluster with consistent hashing distributes
rate limit state across nodes.

**Gossip protocol for Bloom filter replication.** The current design syncs each
gateway instance independently from a central Redis set. At 10 instances with a
60-second sync interval, the filter state can diverge for up to 60 seconds after
a new bad IP is added. A gossip protocol would converge faster.

**ML-based anomaly detection as a second signal layer.** The current entropy and
threshold approach is rule-based and requires manual tuning. An anomaly detection
model trained on legitimate traffic would adapt to new attack patterns automatically
and reduce the false positive rate over time.

**Per-datacenter rate limiting with global sync.** The current design treats all
gateway instances as peers sharing a single Redis. In a multi-region deployment,
cross-datacenter Redis reads add latency. Each datacenter should enforce local rate
limits with periodic global reconciliation.
