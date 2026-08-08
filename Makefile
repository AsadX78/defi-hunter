.PHONY: install test lint verify check lab build

# Install the package + dev dependencies (uses .venv on PEP-668 systems)
PY ?= python3
VENV := .venv

install:
	@if [ -d "$(VENV)" ]; then \
		echo "[*] Installing into existing $(VENV)"; \
		$(VENV)/bin/pip install -q -e ".[dev]"; \
	else \
		echo "[*] Creating $(VENV)"; \
		$(PY) -m venv $(VENV) && $(VENV)/bin/pip install -q -e ".[dev]"; \
	fi
	@echo "[+] Done. Activate with: source $(VENV)/bin/activate  (or run commands via $(VENV)/bin/defihunter)"

# Run the Python test suite
test:
	pytest tests/ -q --tb=short

# Lint (fatal errors only)
lint:
	flake8 defihunter --count --select=E9,F63,F7,F82 --show-source --statistics

# Export templates into the Foundry lab
export:
	python3 scripts/export_templates.py

# Build the lab (compiles all templates + mocks)
build: export
	cd lab && forge build

# Prove every template exploit against the Foundry lab
verify:
	python3 -m defihunter.cli templates verify

# Full check: Python tests + lab exploit suite
check: test build verify
	@echo "[+] All checks passed"
