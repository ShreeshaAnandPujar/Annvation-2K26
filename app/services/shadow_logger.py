import json
import time
import logging
from redis.asyncio import Redis

logger = logging.getLogger(__name__)

SHADOW_LOG_TTL = 86400  # 24 hours


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
            "Shadow event logged",
            extra={
                "request_id": request_id,
                "rule": rule_triggered,
                "client_id": client_id,
            }
        )

    async def get_shadow_stats(self) -> dict:
        """
        Aggregate shadow events by rule to identify
        which rules are triggering most frequently.
        Used for threshold tuning before enforcement.
        """
        pattern = "shadow_log:*"
        stats: dict[str, int] = {}
        total = 0

        async for key in self.redis.scan_iter(pattern):
            raw = await self.redis.get(key)
            if raw:
                try:
                    event = json.loads(raw)
                    rule = event.get("rule_triggered", "unknown")
                    stats[rule] = stats.get(rule, 0) + 1
                    total += 1
                except json.JSONDecodeError:
                    continue

        return {"total": total, "by_rule": stats}
