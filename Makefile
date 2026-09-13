# Production Security Watchtower

SHELL := /bin/bash
PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)

.PHONY: help test lint check scan compose-check up down logs clean

help:
	@printf '%s\n' \
	  'Security Watchtower production commands:' \
	  '  make check         Run compile, unit tests, lint/security checks, Compose validation' \
	  '  make test          Run the unit/regression suite' \
	  '  make lint          Run flake8 and Bandit from the existing environment' \
	  '  make compose-check Validate production Compose configuration' \
	  '  make scan          Run a one-time read-only code scan' \
	  '  make up            Start the production-observational stack' \
	  '  make down          Stop the stack' \
	  '  make logs          Follow watcher logs'

test:
	WATCHTOWER_ENV=production $(PYTHON) -m pytest tests -q

lint:
	$(PYTHON) -m flake8 watchers tests --max-line-length=110 --exclude=__pycache__,.venv
	$(PYTHON) -m bandit -r watchers -ll --exclude ./.venv,./tests

compose-check:
	docker compose config --quiet

check:
	$(PYTHON) -m compileall -q watchers tests
	$(MAKE) test PYTHON="$(PYTHON)"
	$(MAKE) lint PYTHON="$(PYTHON)"
	$(MAKE) compose-check

scan:
	WATCHTOWER_ENV=production $(PYTHON) -c 'from watchers.config import settings; settings.validate(); from watchers.code_watcher import scan_directory; count = sum(scan_directory(path) for path in settings.code_watcher.watch_paths); print(f"Findings: {count}"); raise SystemExit(1 if count else 0)'

up:
	@docker compose up -d --build
	@docker compose ps

down:
	docker compose down

logs:
	docker compose logs -f --tail=200 watchers

clean:
	find . -type d \( -name __pycache__ -o -name .pytest_cache -o -name .coverage \) -prune -exec rm -rf -- {} + 2>/dev/null || true
	find . -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete 2>/dev/null || true
