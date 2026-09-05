.DEFAULT_GOAL := help

UV ?= uv

.PHONY: help setup keys langfuse-up langfuse-down test lint fmt check attack

help:
	@echo "Red Alert local commands"
	@echo ""
	@echo "  setup          uv sync, git hooks, copy .env.example if needed"
	@echo "  keys           fetch stand API keys into .env"
	@echo "  langfuse-up    start local Langfuse (not the stand)"
	@echo "  langfuse-down  stop Langfuse, keep volumes"
	@echo "  test           pytest"
	@echo "  lint           ruff check and ty"
	@echo "  fmt            ruff format"
	@echo "  check          lint and test"
	@echo "  attack         red-alert attack; extra flags via ARGS='...'"

setup:
	$(UV) sync --group dev
	$(UV) run pre-commit install
	@if [ ! -f .env ]; then cp .env.example .env; fi

keys:
	$(UV) run python script/fetch_stand_keys.py

langfuse-up:
	docker compose up -d

langfuse-down:
	docker compose down

test:
	$(UV) run pytest

lint:
	$(UV) run ruff check .
	$(UV) run ty check

fmt:
	$(UV) run ruff format .

check: lint test

attack:
	$(UV) run red-alert attack $(ARGS)
