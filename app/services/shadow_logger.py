import json
import time
from typing import Any

import structlog
from redis.asyncio import Redis

logger = structlog.get_logger()

SHADOW_LOG_TTL = 86400


class ShadowLogger:
    """
    Safety net that prevents deploying overly aggressive rules.

    When shadow mode is enabled, requests that WOULD have been
    blocked are logged instead of blocked. Analyze this log to
    tune thresholds before enabling enforcement.

    This is how Cloudflare, Fastly, and AWS WAF roll out new
    detection rules safely.
    """

    def __init__(self, redis_client: Redis):
        self.redis = redis_client

    async def log_shadow_event(
        self,
        request_id: str,
        rule_triggered: str,
        client_id: str,
        path: str,
        reason: str = "",
    ) -> None:
        """Log a would-be block event without actually blocking."""
        key = f"shadow_log:{request_id}"
        event = {
            "request_id": request_id,
            "rule_triggered": rule_triggered,
            "client_id": client_id,
            "path": path,
            "reason": reason,
            "timestamp": int(time.time()),
        }
        await self.redis.set(key, json.dumps(event), ex=SHADOW_LOG_TTL)
        logger.info(
            "shadow_event_logged",
            request_id=request_id,
            rule=rule_triggered,
            client_id=client_id,
        )

    async def get_shadow_stats(self) -> dict[str, Any]:
        """
        Aggregate shadow events by rule using a pipeline batch read.
        Collects all keys first, then fetches values in a single round-trip
        instead of one GET per key.
        """
        pattern = "shadow_log:*"
        stats: dict[str, int] = {}
        total = 0

        keys = [key async for key in self.redis.scan_iter(pattern)]
        if not keys:
            return {"total": 0, "by_rule": {}}

        pipe = self.redis.pipeline()
        for key in keys:
            pipe.get(key)
        values = await pipe.execute()

        for raw in values:
            if raw:
                try:
                    event = json.loads(raw)
                    rule = event.get("rule_triggered", "unknown")
                    stats[rule] = stats.get(rule, 0) + 1
                    total += 1
                except json.JSONDecodeError:
                    continue

        return {"total": total, "by_rule": stats}
