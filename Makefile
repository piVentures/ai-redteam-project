.PHONY: help setup build up down restart logs shell-vuln shell-hardened \
        test-health test-info test-predict test-hardened alerts verify clean

help:
	@echo "Targets:"
	@echo "  setup          - Create venv and install dependencies"
	@echo "  build          - Build Docker image"
	@echo "  up             - Start all services"
	@echo "  down           - Stop all services"
	@echo "  restart        - Restart all services"
	@echo "  logs           - Follow vulnerable API logs"
	@echo "  shell-vuln     - Bash into the vulnerable API container"
	@echo "  shell-hardened - Bash into the hardened API container"
	@echo "  test-health    - Curl /health on both APIs"
	@echo "  test-info      - Curl /model-info on vulnerable API"
	@echo "  test-predict   - POST a sample image to the vulnerable API"
	@echo "  test-hardened  - POST a sample image to the hardened API"
	@echo "  alerts         - Show current detector alerts"
	@echo "  verify         - Run the full verification suite"
	@echo "  clean          - Remove caches and results"

setup:
	python3 -m venv venv
	./venv/bin/pip install --upgrade pip
	./venv/bin/pip install -r requirements.txt

build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down

restart:
	docker compose restart

logs:
	docker compose logs -f api-vuln

shell-vuln:
	docker compose exec api-vuln bash

shell-hardened:
	docker compose exec api-hardened bash

test-health:
	@echo "--- vulnerable ---"
	@curl -s http://localhost:8000/health | python -m json.tool
	@echo "--- hardened ---"
	@curl -s http://localhost:8001/health | python -m json.tool

test-info:
	@curl -s http://localhost:8000/model-info | python -m json.tool

test-predict:
	@curl -s -X POST http://localhost:8000/predict \
		-F "file=@data/samples/cat_0.png" | python -m json.tool

test-hardened:
	@curl -s -X POST http://localhost:8001/predict \
		-H "x-api-key: dev-local-key-change-me" \
		-F "file=@data/samples/cat_0.png" | python -m json.tool

alerts:
	@curl -s http://localhost:8002/alerts | python -m json.tool

verify:
	@echo "=== Docs endpoints ==="
	@curl -s -o /dev/null -w 'vulnerable /docs: %{http_code}\n' http://localhost:8000/docs
	@curl -s -o /dev/null -w 'hardened /docs:   %{http_code}\n' http://localhost:8001/docs
	@echo ""
	@echo "=== Health ==="
	@curl -s http://localhost:8000/health
	@echo ""
	@curl -s http://localhost:8001/health
	@echo ""
	@echo ""
	@echo "=== Memory limits ==="
	@docker stats --no-stream --format "table {{.Name}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.CPUPerc}}"
	@echo ""
	@echo "=== Container user ==="
	@docker compose exec -T api-vuln whoami
	@docker compose exec -T api-hardened whoami
	@echo ""
	@echo "=== Alerts ==="
	@curl -s http://localhost:8002/alerts | python -c "import sys, json; a=json.load(sys.stdin); print(f'{len(a)} alerts')"

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	rm -rf results/evasion/* results/system/* results/alerts.jsonl
