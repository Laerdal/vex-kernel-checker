# Makefile for VEX Kernel Checker development and testing

# Default Python interpreter
PYTHON := python3

# Directories
PROJECT_DIR := .
TESTS_DIR := tests
EXAMPLES_DIR := examples
DOCS_DIR := docs

# Common commands
.PHONY: help install test test-quick test-coverage test-unit unittest unittest-quiet unittest-module lint format clean benchmark benchmark-quiet ci-benchmark ci-unittest validate setup-dev

help:  ## Show this help message
	@echo "VEX Kernel Checker - Development Commands"
	@echo "========================================="
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install:  ## Install dependencies
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements.txt

install-dev:  ## Install development dependencies
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install coverage flake8 pylint black psutil

test:  ## Run all tests
	$(PYTHON) $(TESTS_DIR)/run_tests.py

test-quick:  ## Run quick smoke tests
	$(PYTHON) $(TESTS_DIR)/run_tests.py --quick

test-coverage:  ## Run tests with coverage reporting
	$(PYTHON) $(TESTS_DIR)/run_tests.py --coverage

test-unit:  ## Run unit tests only
	$(PYTHON) -m unittest discover $(TESTS_DIR) -v

unittest:  ## Run all unit tests using unittest framework
	$(PYTHON) -m unittest discover $(TESTS_DIR) -v

unittest-quiet:  ## Run unit tests with minimal output
	$(PYTHON) -m unittest discover $(TESTS_DIR) -q

unittest-module:  ## Run unit tests for specific module (use MODULE=test_module_name)
	@if [ -z "$(MODULE)" ]; then \
		echo "Usage: make unittest-module MODULE=test_module_name"; \
		echo "Example: make unittest-module MODULE=test_base"; \
		exit 1; \
	fi
	$(PYTHON) -m unittest $(TESTS_DIR).$(MODULE) -v

benchmark:  ## Run performance benchmarks
	$(PYTHON) $(TESTS_DIR)/benchmark.py

benchmark-quiet:  ## Run benchmarks with minimal output
	$(PYTHON) $(TESTS_DIR)/benchmark.py --quiet

validate:  ## Validate configuration (requires arguments)
	@echo "Usage: make validate VEX_FILE=path/to/file.vex KERNEL_CONFIG=path/to/.config KERNEL_SOURCE=path/to/kernel"
	@echo "Example: make validate VEX_FILE=examples/test_real_cve.json KERNEL_CONFIG=/boot/config-$$(uname -r) KERNEL_SOURCE=/usr/src/linux"

validate-run:  ## Run validation with provided arguments
	$(PYTHON) $(TESTS_DIR)/validate_config.py \
		--vex-file $(VEX_FILE) \
		--kernel-config $(KERNEL_CONFIG) \
		--kernel-source $(KERNEL_SOURCE) \
		$(if $(WEBDRIVER),--webdriver $(WEBDRIVER)) \
		$(if $(API_KEY),--api-key $(API_KEY))

lint:  ## Run code linting
	$(PYTHON) -m flake8 vex-kernel-checker.py --count --select=E9,F63,F7,F82 --show-source --statistics
	$(PYTHON) -m flake8 vex-kernel-checker.py --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics

lint-tests:  ## Run linting on test files
	$(PYTHON) -m flake8 $(TESTS_DIR)/*.py --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics

format:  ## Format code with black
	$(PYTHON) -m black vex-kernel-checker.py $(TESTS_DIR)/*.py

format-check:  ## Check code formatting
	$(PYTHON) -m black --check --diff vex-kernel-checker.py $(TESTS_DIR)/*.py

clean:  ## Clean temporary files and caches
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type f -name "*.coverage" -delete 2>/dev/null || true
	rm -rf htmlcov/ 2>/dev/null || true
	rm -rf .coverage 2>/dev/null || true
	rm -rf *.egg-info/ 2>/dev/null || true

setup-dev:  ## Set up development environment
	@echo "Setting up VEX Kernel Checker development environment..."
	make install-dev
	@echo "Development environment ready!"
	@echo "Run 'make test-quick' to verify setup"

setup-test-data:  ## Create test data for development
	@echo "Creating test kernel structure..."
	@mkdir -p test_kernel/drivers/{net,usb,pci,scsi,block}
	@mkdir -p test_kernel/{fs,net/core,kernel,mm,crypto,security}
	@echo "# Test kernel configuration" > test_kernel.config
	@echo "CONFIG_NET=y" >> test_kernel.config
	@echo "CONFIG_USB=y" >> test_kernel.config
	@echo "CONFIG_PCI=y" >> test_kernel.config
	@echo "CONFIG_SCSI=y" >> test_kernel.config
	@echo "CONFIG_BLOCK=y" >> test_kernel.config
	@echo "CONFIG_FILESYSTEMS=y" >> test_kernel.config
	@echo "Test kernel structure created in test_kernel/"

run-example:  ## Run tool with example data (config-only mode)
	@if [ ! -f "test_kernel.config" ]; then make setup-test-data; fi
	$(PYTHON) vex-kernel-checker.py \
		--vex-file $(EXAMPLES_DIR)/test_real_cve.json \
		--kernel-config test_kernel.config \
		--kernel-source test_kernel \
		--config-only \
		--verbose

check-deps:  ## Check if all dependencies are installed
	$(PYTHON) $(TESTS_DIR)/run_tests.py --check-deps

doc:  ## Generate documentation (placeholder)
	@echo "Documentation generation not implemented yet"
	@echo "Available documentation:"
	@echo "  - README.md (main project documentation)"
	@echo "  - tests/README.md (testing documentation)"
	@echo "  - docs/ directory (additional documentation)"

release-check:  ## Run all checks before release
	@echo "Running release checks..."
	make clean
	make test-coverage
	make lint
	make format-check
	make benchmark-quiet
	@echo "Release checks completed successfully!"

# CI/CD targets
ci-test:  ## Run tests for CI/CD
	make test-coverage

ci-lint:  ## Run linting for CI/CD
	make lint
	make format-check

ci-benchmark:  ## Run benchmarks for CI/CD
	make benchmark-quiet

ci-unittest:  ## Run unit tests for CI/CD
	make unittest-quiet

# Help with common development workflows
workflow-fix:  ## Common workflow after making changes
	@echo "Running common development workflow..."
	make format
	make lint
	make test-quick
	@echo "Workflow completed. Ready for commit!"

workflow-pr:  ## Workflow before creating PR
	@echo "Running pre-PR workflow..."
	make clean
	make format-check
	make lint
	make test-coverage
	make benchmark-quiet
	@echo "PR workflow completed successfully!"

# Docker support (placeholder for future)
docker-build:  ## Build Docker image (placeholder)
	@echo "Docker support not implemented yet"

docker-test:  ## Run tests in Docker (placeholder)
	@echo "Docker support not implemented yet"
