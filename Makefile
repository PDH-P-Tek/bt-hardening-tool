# BT Hardening Tool

.PHONY: install test lint fmt typecheck check clean

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

check: lint typecheck test   ## what CI runs

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
