dev:
	docker compose up -d --build

down:
	docker compose down -v

logs:
	docker compose logs -f

check-infra:
	docker compose exec redis redis-cli ping
	docker compose exec postgres psql -U gateway_user -d gateway_db -c "SELECT 1"
	curl http://localhost:8000/health

migrate:
	docker compose exec app poetry run alembic upgrade head

makemigration:
	docker compose exec app poetry run alembic revision --autogenerate -m "$(msg)"

load-test:
	poetry run locust -f tests/load/locustfile.py \
		--host http://localhost:8000

load-test-headless:
	poetry run locust -f tests/load/locustfile.py \
		--host http://localhost:8000 \
		--headless \
		--users 200 \
		--spawn-rate 20 \
		--run-time 60s \
		--html tests/load/report.html \
		--csv tests/load/results
