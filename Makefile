PYTHON ?= python3
GATE := release/gate
EXPERIMENTS := release/experiments

# Bytecode writes are disabled for gate targets: a stray __pycache__ would be
# refused by admission anyway, this just keeps the working tree clean.
GATE_PY_ENV := PYTHONDONTWRITEBYTECODE=1

.PHONY: test demo check wheelhouse manifest release-gate contamination gate-all clean-gate

test:
	PYTHONPATH=src $(PYTHON) -m unittest discover -s tests -v

demo:
	PYTHONPATH=src $(PYTHON) examples/smoke.py

check: test demo

# --- offline release gate ---------------------------------------------------
# wheelhouse is a one-time, networked bootstrap; every later target runs with
# PIP_NO_INDEX=1 against the pinned local wheels only.
wheelhouse:
	bash $(GATE)/bootstrap_wheelhouse.sh
	bash $(GATE)/verify_wheelhouse.sh

# Refresh the approved source allowlist after an *intentional, reviewed*
# source change. The gate refuses to build on hash drift otherwise.
manifest:
	find . -path ./.git -prune -o -name __pycache__ -type d -print -exec rm -rf {} + 2>/dev/null || true
	$(GATE_PY_ENV) $(PYTHON) $(GATE)/gate_run.py --refresh-manifest

release-gate:
	bash $(GATE)/verify_wheelhouse.sh
# Unit tests above run without the bytecode guard; purge interpreter caches
# so the gate evaluates source, not generated .pyc residue.
	find . -path ./.git -prune -o -name __pycache__ -type d -print -exec rm -rf {} + 2>/dev/null || true
	$(GATE_PY_ENV) $(PYTHON) $(GATE)/gate_run.py

# Pollution experiments: canaries injected into sandbox copies only; the real
# source tree is never mutated. Failing any experiment fails this target.
contamination:
	$(GATE_PY_ENV) $(PYTHON) $(EXPERIMENTS)/run_experiments.py

# Full gate for CI: unit tests first, then artifact gate, then pollution runs.
gate-all: test release-gate contamination

clean-gate:
	rm -rf $(GATE)/runs $(GATE)/accepted $(GATE)/quarantine $(GATE)/reports
	rm -rf build dist *.egg-info src/*.egg-info
