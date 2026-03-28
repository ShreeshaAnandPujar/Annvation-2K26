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
