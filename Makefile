.PHONY: install test lint verify check lab build

# Install the package + dev dependencies
install:
	pip install -e ".[dev]"

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
