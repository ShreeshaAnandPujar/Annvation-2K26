"""
AGAD Load Test Suite
====================

Three traffic scenarios running simultaneously to prove the system
distinguishes legitimate users from malicious clients under real load.

How to run:
    # Interactive UI (recommended for demos)
    make load-test

    # Headless — CI/CD or scripted runs
    make load-test-headless

Recommended test configuration for a meaningful demo:
    Users: 20 total
    Spawn rate: 2 users/second
    Distribution:
        - 15 LegitimateUsers (75%)
        -  3 CredentialStuffers (15%)
        -  2 Scrapers (10%)

What to observe in the Locust UI:
    1. LegitimateUser requests: consistent 200s, low failure rate
    2. CredentialStuffer requests: shift from 401 → 429 as threshold hit
    3. Scraper requests: 200s early, then 403/429 as entropy detected
    4. Check /admin/shadow-stats during the test to see logged events
    5. Check Prometheus at :9090 for rate_limit_rejections_total counter

Interpreting results:
    - If LegitimateUser failure rate > 1%: thresholds are too aggressive
    - If CredentialStuffer never gets blocked: thresholds are too lenient
    - If Scraper is never detected: entropy threshold needs tuning

The shared localhost IP is a load test environment artifact, not a real detection false positive.
See DESIGN.md for threshold tuning guidance.
"""

from tests.load.scenarios.credential_stuffer import CredentialStuffer
from tests.load.scenarios.legitimate_user import LegitimateUser
from tests.load.scenarios.scraper import Scraper

# Weight distribution — controls how many of each type Locust spawns
# when using the fixed-count mode
__all__ = ["LegitimateUser", "CredentialStuffer", "Scraper"]
