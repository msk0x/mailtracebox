.PHONY: install install-dev run test lint update help

help:
	@echo "make install      - Install mailtracebox system-wide (via pipx)"
	@echo "make install-dev  - Install with dev dependencies (in venv)"
	@echo "make run          - Run a scan (TARGET=user@example.com)"
	@echo "make test         - Run tests"
	@echo "make lint         - Run linter"
	@echo "make update       - Update to latest version"

install:
	@command -v pipx >/dev/null 2>&1 || { echo "Installing pipx..."; pip install --user pipx; pipx ensurepath; }
	pipx install -e .
	@echo ""
	@echo "Done! Run: mailtracebox scan user@example.com"

install-dev:
	python3 -m venv .venv
	. .venv/bin/activate && pip install -e ".[dev]"
	@echo ""
	@echo "Done! Run: source .venv/bin/activate"

run:
	mailtracebox scan $(TARGET)

test:
	. .venv/bin/activate && pytest tests/ -v

lint:
	. .venv/bin/activate && ruff check src/ tests/

update:
	mailtracebox update
