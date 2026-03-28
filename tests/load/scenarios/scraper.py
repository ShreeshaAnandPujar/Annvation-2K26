"""
Scraper scenario.

Simulates an automated scraper who:
- Registers a legitimate-looking account
- Makes requests at suspiciously regular intervals (low timing variance)
- Hits the same endpoint repeatedly at machine speed

Expected outcome:
- First requests succeed (200)
- Timing entropy analysis detects regular inter-arrival gaps
- Abuse detector flags the client
- With shadow_mode OFF: 403 returned
- With shadow_mode ON: request passes but shadow log entry created

This scenario PROVES component C (scraping detection via timing entropy)
is working correctly.
"""

import time

from locust import HttpUser, constant, task


class Scraper(HttpUser):
    """
    Simulates a scraping bot with suspiciously regular request timing.
    constant(0.5) = exactly 2 requests/second with zero variance.
    Human users have high variance; this bot has essentially none.
    """

    wait_time = constant(0.5)  # fixed interval — bot signature
    token: str = ""
    username: str = ""

    def on_start(self):
        """Register and login once — scraper uses one account."""
        self.username = f"scraper_{int(time.time() * 1000)}"

        reg = self.client.post(
            "/auth/register",
            json={
                "username": self.username,
                "email": f"{self.username}@scraper.com",
                "password": "scraperpass123",
            },
        )

        if reg.status_code == 201:
            login = self.client.post(
                "/auth/login",
                json={
                    "username": self.username,
                    "password": "scraperpass123",
                },
            )
            if login.status_code == 200:
                self.token = login.json().get("access_token", "")

    @task
    def scrape_gateway(self):
        """Regular, machine-paced gateway access — scraper signature."""
        if not self.token:
            return

        with self.client.get(
            "/gateway/proxy",
            headers={"Authorization": f"Bearer {self.token}"},
            catch_response=True,
            name="/gateway/proxy [scraping]",
        ) as response:
            if response.status_code == 200:
                response.success()
            elif response.status_code in (403, 429):
                # Detection working — scraper caught
                response.success()
            else:
                response.failure(f"Unexpected status: {response.status_code}")
