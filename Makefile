.PHONY: test test-fast test-integration help

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-18s\033[0m %s\n", $$1, $$2}'

test: ## Run all tests (T-fast + T-integration)
	@echo "=== T-fast: Python unit tests ==="
	python3 -m unittest discover -s tests -p "test_*.py" -v
	@echo ""
	@echo "=== T-fast: Bun adversarial tests ==="
	bun test ./tests/test_memory_validation.test.ts
	@echo ""
	@echo "=== All tests complete ==="

test-fast: ## Unit + adversarial only (no subprocess I/O)
	python3 -m unittest tests/test_markdown_retriever.py tests/test_auto_retrieve.py -v
	bun test ./tests/test_memory_validation.test.ts

test-integration: ## Integration + hook I/O only
	python3 -m unittest tests/test_integration.py tests/test_hook_io.py -v
