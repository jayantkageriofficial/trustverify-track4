TOOLKIT ?= ../Track-4-Toolkit
.PHONY: setup test test-adapter validate demo evaluate brief practice bench bench-nodes attack ui
setup:
	uv sync --extra messaging --extra dev --locked
test:
	uv run --extra messaging --extra dev --locked pytest -q
test-adapter:
	uv run --extra dev --locked pytest -q tests/test_adapter.py
validate:
	uv run --locked python $(TOOLKIT)/validate.py --entry track4_service.py
demo:
	uv run --extra messaging --locked trustverify demo --directory runtime/demo-$$(date +%s)
evaluate:
	uv run --extra messaging --locked trustverify evaluate --output reports/detector.json
brief:
	uv run --extra messaging --extra dev --locked python scripts/build_brief.py
practice:
	uv run --locked python -m trustverify practice --toolkit $(TOOLKIT)/practice --output reports/practice.json
bench:
	uv run --locked python scripts/bench_adapter.py --output reports/adapter_bench.json
bench-nodes:
	uv run --extra messaging --locked python scripts/bench_nodes.py --output reports/node_bench.json
attack:
	uv run --locked python scripts/attack_adapter.py --output reports/adapter_attack.json
ui:
	uv run --extra messaging --locked python -m trustverify ui
