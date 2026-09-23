.PHONY: help setup build up dev-up down logs shell-vuln test-health test-info test-predict alerts clean

help:
	@echo "Targets: setup build up dev-up down logs shell-vuln test-health test-info test-predict alerts clean"

setup:
	python3 -m venv venv
	./venv/bin/pip install --upgrade pip
	./venv/bin/pip install -r requirements.txt

build:
	docker compose build

up:
	docker compose up -d

dev-up:
	docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d

down:
	docker compose down

logs:
	docker compose logs -f api-vuln

shell-vuln:
	docker compose exec api-vuln bash

test-health:
	@curl -s http://localhost:8000/health | python -m json.tool
	@curl -s http://localhost:8001/health | python -m json.tool

test-info:
	@curl -s http://localhost:8000/model-info | python -m json.tool

test-predict:
	@curl -s -X POST http://localhost:8000/predict -F "file=@data/samples/cat_0.png" | python -m json.tool

alerts:
	@curl -s http://localhost:8002/alerts | python -m json.tool

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	rm -rf results/evasion/* results/system/* results/alerts.jsonl
