PYTHON ?= python3
.PHONY: test demo synth check
test:
	PYTHONPATH=src $(PYTHON) -m unittest discover -s tests -v
demo:
	PYTHONPATH=src $(PYTHON) examples/smoke.py
# 仅消费人工合成规格，产物再交给独立校验器；不接触真实数据或 HMAC 密钥。
synth:
	PYTHONPATH=src $(PYTHON) -m redacta.synth generate \
		examples/synth_spec.json /tmp/redacta-synth-tables.json \
		--meta /tmp/redacta-synth-meta.json
	PYTHONPATH=src $(PYTHON) -m redacta.synth validate \
		examples/synth_spec.json /tmp/redacta-synth-tables.json \
		--meta /tmp/redacta-synth-meta.json
check: test demo synth
