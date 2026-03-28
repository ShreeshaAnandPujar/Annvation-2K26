# app/core/metrics.py
from typing import cast

from prometheus_client import Counter, Gauge, Histogram
from sqlalchemy.engine import Engine
from sqlalchemy.pool import QueuePool

# ── DB pool gauges ────────────────────────────────────────────────────────────
db_pool_checkedout = Gauge(
    "db_pool_checkedout",
    "Number of DB connections currently checked out",
)
db_pool_overflow = Gauge(
    "db_pool_overflow",
    "Number of DB connections above pool_size",
)

# ── Request metrics ───────────────────────────────────────────────────────────
REQUEST_DURATION = Histogram(
    "request_duration_seconds",
    "End-to-end request latency including full middleware chain",
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5],
)

REQUESTS_TOTAL = Counter(
    "requests_total",
    "Total HTTP requests processed",
    labelnames=["status_code", "route"],
)

# ── Abuse detection metrics ───────────────────────────────────────────────────
RATE_LIMIT_REJECTIONS = Counter(
    "rate_limit_rejections_total",
    "Requests rejected by the sliding window rate limiter",
    labelnames=["client_id"],
)

BLOOM_FILTER_HITS = Counter(
    "bloom_filter_hits_total",
    "Requests rejected by Bloom filter (known-bad IP or user-agent)",
    labelnames=["filter_type"],  # "ip" or "agent"
)

ABUSE_DETECTIONS = Counter(
    "abuse_detections_total",
    "Requests flagged by behavioral abuse detector",
    labelnames=["state", "reason_type"],  # state: soft_block/throttled
)


def record_pool_stats(engine: Engine) -> None:
    """Call from /health — updates gauges with current pool state."""
    pool = cast(QueuePool, engine.pool)
    db_pool_checkedout.set(pool.checkedout())
    db_pool_overflow.set(pool.overflow())
