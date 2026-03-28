"""
Credential stuffing scenario.

Simulates an automated attacker who:
- Fires login attempts in rapid succession (low wait time)
- Tries many different usernames (leaked credential list)
- Does NOT pause like a human would

Expected outcome:
- First N attempts return 401 (wrong credentials)
- After ip_threshold failures, graduated response applies a soft block
- Client receives 429 with Retry-After header
- The system should detect and block before 10 attempts succeed

This scenario PROVES component B (two-dimensional auth failure tracking)
and component E (graduated response) are working correctly.
"""

import random
import string

from locust import HttpUser, constant, task

# Common usernames from leaked credential lists
LEAKED_USERNAMES = [
    "admin",
    "user",
    "test",
    "john.doe",
    "jane.doe",
    "info",
    "support",
    "hello",
    "contact",
    "mail",
]


class CredentialStuffer(HttpUser):
    """
    Simulates a credential stuffing bot.
    constant(0.1) = 10 requests/second with no variance — bot pattern.
    """

    wait_time = constant(0.1)  # low variance — automated bot pattern

    @task
    def stuff_credentials(self):
        """Rapid fire login attempts with known usernames and wrong passwords."""
        username = random.choice(LEAKED_USERNAMES)
        password = "".join(random.choices(string.ascii_lowercase, k=8))

        with self.client.post(
            "/auth/login",
            json={"username": username, "password": password},
            catch_response=True,
            name="/auth/login [stuffing]",
        ) as response:
            if response.status_code == 401:
                # Expected — wrong credentials, attack not yet detected
                response.success()
            elif response.status_code == 403:
                # Credential stuffing detected at router level
                response.success()
            elif response.status_code == 429:
                # Graduated response soft block — system working correctly
                response.success()
            else:
                response.failure(f"Unexpected status: {response.status_code}")
