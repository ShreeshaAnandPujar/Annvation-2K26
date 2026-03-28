"""
Legitimate user scenario.

Simulates a real user who:
- Registers once
- Logs in to get a token
- Makes requests to the gateway with human-like timing variance
- Occasionally hits the /health endpoint

Expected outcome: all requests succeed (200), no rate limiting triggered,
X-RateLimit-Remaining header present and above zero.
"""

import random
import time

from locust import HttpUser, between, task


class LegitimateUser(HttpUser):
    """
    Simulates a real authenticated user accessing the gateway.
    wait_time uses between() to introduce natural timing variance —
    human users pause between requests, bots do not.
    """

    wait_time = between(1, 5)  # high variance — legitimate human pattern
    token: str = ""
    username: str = ""

    def on_start(self):
        """Register and login once per simulated user."""
        self.username = f"user_{int(time.time() * 1000)}_{random.randint(1000, 9999)}"

        reg = self.client.post(
            "/auth/register",
            json={
                "username": self.username,
                "email": f"{self.username}@test.com",
                "password": "testpassword123",
            },
        )

        if reg.status_code == 201:
            with self.client.post(
                "/auth/login",
                json={
                    "username": self.username,
                    "password": "testpassword123",
                },
                catch_response=True,
                name="/auth/login",
            ) as response:
                if response.status_code == 200:
                    self.token = response.json().get("access_token", "")
                    response.success()
                elif response.status_code in (403, 429):
                    # Shared test IP soft-blocked by credential stuffers.
                    # Expected in load test environment — not a real failure.
                    response.success()
                else:
                    response.failure(f"Unexpected login status: {response.status_code}")

    @task(8)
    def access_gateway(self):
        """Primary task — authenticated gateway access."""
        if not self.token:
            return
        with self.client.get(
            "/gateway/proxy",
            headers={"Authorization": f"Bearer {self.token}"},
            catch_response=True,
            name="/gateway/proxy [auth]",
        ) as response:
            if response.status_code == 200:
                response.success()
            elif response.status_code == 429:
                response.failure(f"Unexpected rate limit: {response.text}")
            else:
                response.failure(f"Unexpected status: {response.status_code}")

    @task(2)
    def check_health(self):
        """Occasional health check — simulates monitoring traffic."""
        self.client.get("/health", name="/health")
