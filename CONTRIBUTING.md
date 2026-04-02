# Contributing

## Local Development

### Prerequisites

- Python 3.12 (managed via pyenv)
- Poetry
- Docker Desktop

### Setup

```bash
git clone https://github.com/macaulaypraise/api-gateway-with-abuse-detection
cd api-gateway-with-abuse-detection
poetry install
cp .env.example .env
cp .env.example .env.test  # edit TEST_DATABASE_URL and TEST_REDIS_URL
```

### Start the stack

```bash
make dev          # starts app, Redis, Postgres, Prometheus
make check-infra  # verifies all services are reachable
make migrate      # applies DB migrations
```

### Run tests

```bash
make test         # full suite with coverage
make test-unit    # unit tests only (no Docker needed)
```

### Pre-commit hooks

```bash
poetry run pre-commit install
poetry run pre-commit run --all-files
```

### Commit convention

Use [Conventional Commits](https://www.conventionalcommits.org/):
`feat:`, `fix:`, `chore:`, `docs:`, `test:`, `refactor:`

### Adding a migration

```bash
make makemigration msg="your description here"
make migrate
```

---

## Admin Role Management

User roles are stored in the `users.role` database column. The default role for
all registered users is `user`. Admin access is granted by direct database update.

### Promoting a user to admin (local)

```bash
docker compose exec postgres psql -U gateway_user -d gateway_db \
  -c "UPDATE users SET role = 'admin' WHERE username = 'target';"
```

### Promoting a user to admin (production)

Run the same SQL via your database provider's console (Supabase SQL editor,
Railway shell, etc.).

After the update, the user logs in again to receive a JWT with `"role": "admin"`.
Their previous token (with `"role": "user"`) will receive 403 on admin endpoints
until it expires (30 minutes).

---

## Shadow Mode

Shadow mode logs would-be blocks without enforcing them. It is controlled by
a Redis key that can be toggled at runtime via the admin API.

### Toggle shadow mode (requires admin token)

```bash
# Enable — observe but don't block
curl -X POST http://localhost:8000/admin/shadow-mode?enabled=true \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Disable — enforce blocks
curl -X POST http://localhost:8000/admin/shadow-mode?enabled=false \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

The toggle takes effect on the next request. The `SHADOW_MODE_ENABLED` env var
is used as a fallback when the Redis key is absent.

---

## Testing Rate Limiting

### Local testing

```bash
# Run 150 requests in parallel — triggers rate limit
for i in $(seq 1 150); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    http://localhost:8000/gateway/proxy \
    -H "Authorization: Bearer $TOKEN" &
done | sort | uniq -c
# Expected: 100 × 200, 50 × 429
```

### Remote testing (important)

Sequential curl calls over a network connection will NOT trigger the rate limit.
Each request takes ~500ms on a remote host, so 300 sequential requests take
~5 minutes — far longer than the 60-second window. Only ~60 requests land in
any window at that speed.

Always use parallel requests when testing against a remote deployment:

```bash
for i in $(seq 1 150); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    $BASE/gateway/proxy \
    -H "Authorization: Bearer $TOKEN" &
done | sort | uniq -c
```

---

## Environment Variables

| Variable                      | Required | Default       | Description                                                    |
| ----------------------------- | -------- | ------------- | -------------------------------------------------------------- |
| `DATABASE_URL`                | Yes      | —             | PostgreSQL connection string                                   |
| `REDIS_URL`                   | Yes      | —             | Redis connection string                                        |
| `SECRET_KEY`                  | Yes      | —             | JWT signing key (32-byte hex)                                  |
| `APP_ENV`                     | No       | `development` | `development`, `test`, or `production`                         |
| `SHADOW_MODE_ENABLED`         | No       | `true`        | Default shadow mode state (overridden by Redis key at runtime) |
| `RATE_LIMIT_REQUESTS`         | No       | `100`         | Max requests per window per client                             |
| `RATE_LIMIT_WINDOW_SECONDS`   | No       | `60`          | Sliding window duration                                        |
| `BLOOM_FILTER_CAPACITY`       | No       | `1000000`     | Expected number of entries                                     |
| `BLOOM_FILTER_ERROR_RATE`     | No       | `0.001`       | False positive rate                                            |
| `AUTH_FAILURE_IP_THRESHOLD`   | No       | `10`          | Failures before IP soft-block                                  |
| `AUTH_FAILURE_USER_THRESHOLD` | No       | `20`          | Failures before username soft-block                            |
| `AUTH_FAILURE_WINDOW_SECONDS` | No       | `300`         | Auth failure counter TTL                                       |
| `SCRAPING_ENTROPY_THRESHOLD`  | No       | `0.5`         | Std dev below which bot is flagged                             |
| `SCRAPING_SAMPLE_SIZE`        | No       | `20`          | Timing samples to keep per client                              |
