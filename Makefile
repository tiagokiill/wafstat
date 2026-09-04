PYTHON ?= python3

.PHONY: test compile dry-run schema-check check

test:
	$(PYTHON) -m pytest tests -q

compile:
	$(PYTHON) -m py_compile wafstat tests/test_public_wafstat_scanner.py scripts/validate_examples.py

dry-run:
	@./wafstat scan example.com --dry-run --json

schema-check:
	$(PYTHON) scripts/validate_examples.py

check: test compile schema-check
	git diff --check
