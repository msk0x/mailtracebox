.PHONY: install install-dev run test lint help

help:
	@echo "make install      - Install in a virtual environment"
	@echo "make install-dev  - Install with dev dependencies"
	@echo "make run          - Run a scan (TARGET=user@example.com)"
	@echo "make test         - Run tests"
	@echo "make lint         - Run linter"

install:
	python3 -m venv .venv
	. .venv/bin/activate && pip install -e .
	@echo ""
	@echo "Done! Run: source .venv/bin/activate"
	@echo "Then: mailtracebox scan user@example.com"

install-dev:
	python3 -m venv .venv
	. .venv/bin/activate && pip install -e ".[dev]"
	@echo ""
	@echo "Done! Run: source .venv/bin/activate"

run:
	. .venv/bin/activate && mailtracebox scan $(TARGET)

test:
	. .venv/bin/activate && pytest tests/ -v

lint:
	. .venv/bin/activate && ruff check src/ tests/

update:
	. .venv/bin/activate && mailtracebox update
