# BT Hardening Tool

.PHONY: install test lint fmt typecheck check run demo clean

install:            ## create the venv and install everything
	uv sync

test:               ## run the suite
	uv run pytest

test-one:           ## run one test: make test-one TEST=tests/test_x.py::test_y
	uv run pytest $(TEST)

lint:
	uv run ruff check .

fmt:
	uv run ruff format .
	uv run ruff check --fix .

typecheck:
	uv run mypy

check: lint typecheck test   ## what CI runs. Fails fast: a broken step stops the rest.

demo:               ## build a demo estate to click through
	uv run python scripts/demo_estate.py

run:                ## serve the app on localhost:8000
	uv run uvicorn btht.app.main:app --reload --port 8000

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
