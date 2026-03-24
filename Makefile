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
