# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- **Fast Checkout pattern in auth routes** — bcrypt runs outside DB session
- **User-agent fingerprinting** via second Bloom filter (abusive_agents)
- **Graduated response system** (ALLOWED → THROTTLED → SOFT_BLOCK)
- **Database-backed RBAC** — `UserRole` enum (`USER`, `ADMIN`) and `role`
  column added to `users` table via Alembic migration; role embedded in JWT
  at login time so `require_admin` reads the claim without a DB query per request
- **Admin promotion pattern** — `UPDATE users SET role = 'admin' WHERE username
= 'target'`; user logs in again to receive updated JWT; no server restart needed
- **Runtime shadow mode toggle** — `POST /admin/shadow-mode` writes to Redis key
  `config:shadow_mode_enabled`; middleware reads it at request time, falling back
  to the `SHADOW_MODE_ENABLED` env var; toggle takes effect immediately
- **`app/core/feature_flags.py`** — `is_shadow_mode_enabled(redis, fallback)`
  helper read by both `AbuseDetectorMiddleware` and `ShadowModeMiddleware`
- **Prometheus domain metrics** — `REQUEST_DURATION` histogram,
  `REQUESTS_TOTAL` counter (labels: status_code, route), `RATE_LIMIT_REJECTIONS`
  counter (label: client_id), `BLOOM_FILTER_HITS` counter (label: filter_type),
  `ABUSE_DETECTIONS` counter (labels: state, reason_type)
- **structlog JSON logging** — `app/core/logging.py` with `configure_logging()`;
  replaces `logging.basicConfig` across all services, workers, and core files
- **Redis startup retry** — exponential backoff in `create_redis_client()`;
  5 attempts, base delay 1s doubling each retry; catches `RedisConnectionError`
  specifically
- **DB pool stats on `/health`** — `checked_out`, `checked_in`, `overflow`,
  `size` exposed via `record_pool_stats()` from `app/core/metrics.py`
- **`POST /admin/shadow-mode`** — admin-protected endpoint to toggle shadow mode
  at runtime without redeployment
- **Live deployment** on Render (app) + Upstash (Redis) + Supabase (PostgreSQL)
- **Production rate limit verification** — 150 parallel requests confirmed
  exactly 100 × 200 and 50 × 429; `rate_limit_rejections_total{client_id="demo"}
200.0` confirmed in Prometheus; JWT identity tracked, not IP address

### Changed

- **`require_admin`** reads JWT `role` claim instead of checking
  `ADMIN_USERNAMES` env var; 401 for missing/invalid token, 403 for wrong role;
  uses `Depends(get_settings_dep)` properly instead of re-importing inside
  the function
- `auth.py` uses **AsyncSessionFactory** directly — no Depends(get_db)
- **`app/routers/auth.py` login** — embeds `{"sub": username, "role": user.role}`
  in JWT; register sets explicit `UserRole.USER` default
- **`BloomFilterService` admin routes** — `block-ip`, `block-agent`, and
  `block-status` now read `request.app.state.bloom` directly; updates live
  middleware filter immediately, not after the 60-second sync cycle
- **`shadow_logger.get_shadow_stats`** — pipeline batch read replaces per-key
  `GET` loop; all keys fetched in a single round-trip
- **`AbuseDetectorMiddleware`** and **`ShadowModeMiddleware`** — both now call
  `is_shadow_mode_enabled(redis, fallback)` instead of reading `settings`
  directly; shadow mode is now a runtime toggle
- **`app/core/database.py`** — pool tuned: `pool_size=10`, `max_overflow=10`,
  `pool_timeout=30`, `pool_recycle=1800`, `statement_timeout=5000ms`
- **`get_db`** — removed redundant `finally: session.close()`; async context
  manager already handles close on exit
- **`require_admin` token parsing** — `split()` with length check replaces
  fragile `split(" ")[1]` indexing
- **`app/models/user.py`** — `DateTime(timezone=True)` with `server_default=
func.now()` and `default=lambda: datetime.now(UTC)`; resolves `datetime.utcnow`
  deprecation in Python 3.12
- **`app/schemas/auth.py` `UserResponse`** — exposes `role` field to clients
- **`conftest.py`** — split into session-scoped `setup_test_schema`
  (`drop_all`/`create_all` once per test run) and function-scoped
  `reset_database` (`TRUNCATE` per test); same isolation at lower overhead
- **Test suite** — 67 tests passing (up from 63), 93% coverage; added
  `test_dependencies.py`, `test_require_admin_valid_admin`,
  `test_non_admin_cannot_access_admin_routes`, Redis retry tests

### Fixed

- **`verify_password` not awaited** — was silently bypassing all password
  validation; coroutine object always evaluates truthy
- **BloomFilter middleware used wrong instance** — `block-ip` admin route was
  creating a new empty `BloomFilterService` per request; middleware's in-memory
  filter was never updated until the 60-second sync
- **`ADMIN_USERNAMES` static RBAC** removed — replaced with database-backed
  `UserRole` enum; any user could bypass admin checks by registering with the
  hardcoded username
- **Duplicate Alembic head** — caused by running `make makemigration` twice;
  resolved via `alembic merge heads` and `alembic stamp`
- **Test DB schema stale after role column addition** — `conftest.py`
  session-scoped `setup_test_schema` now guarantees schema matches models
  on every test run regardless of prior state
- **Rate limit test methodology** — sequential curl over network never triggers
  the limit (requests too slow, window clears between them); correct test uses
  parallel requests via `&` or `xargs -P`

### Removed

- **`ADMIN_USERNAMES` setting** and `admin_username_set` property from
  `app/config.py` — replaced by database role column
- **Bloom filter backward-compat shims** — `add()`, `might_contain()`,
  `add_to_redis()` deleted; nothing in the codebase called the old names
- **Load test generated artifacts** from git tracking — `tests/load/*.html`
  and `tests/load/*.csv` added to `.gitignore`
