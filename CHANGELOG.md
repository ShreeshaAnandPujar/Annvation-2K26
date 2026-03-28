# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- Graduated response system (ALLOWED → THROTTLED → SOFT_BLOCK)
- User-agent fingerprinting via second Bloom filter (abusive_agents)
- Runtime shadow mode toggle via Redis key
- Admin role protection via ADMIN_USERNAMES setting
- Prometheus domain metrics: request duration, rate limit rejections,
  bloom filter hits, abuse detections
- structlog JSON logging across all services and workers
- Redis startup retry with exponential backoff
- Fast Checkout pattern in auth routes — bcrypt runs outside DB session
- DB connection pool stats exposed on /health and /metrics

### Changed

- BloomFilterService admin routes now update live app.state.bloom
  immediately instead of waiting for 60s sync cycle
- shadow_logger.get_shadow_stats now uses pipeline batch read (O(1)
  Redis round-trips instead of O(n))
- auth.py uses AsyncSessionFactory directly — no Depends(get_db)

### Fixed

- verify_password was not awaited — silently bypassed all password
  validation (coroutine object always truthy)
- Bloom filter middleware read from wrong instance on block-ip admin call
