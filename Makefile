# =============================================================================
# Makefile - Taint Analysis Masterclass
# =============================================================================
# Common commands for development, analysis, and deployment.
#
# Usage:
#   make help          - Show available commands
#   make setup         - Initial setup
#   make run           - Run VulnShop locally
#   make analyze-all   - Run all analysis tools

.PHONY: help setup install run stop clean \
        analyze-all analyze-pysa analyze-codeql analyze-semgrep \
        benchmark docs-serve docs-build \
        lint format typecheck test \
        docker-build docker-up docker-down docker-logs

# Default target
.DEFAULT_GOAL := help

# =============================================================================
# Variables
# =============================================================================
PYTHON := python3
PIP := pip3
DOCKER_COMPOSE := docker-compose
VENV := venv
VENV_BIN := $(VENV)/bin

# Colors for output
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m # No Color

# =============================================================================
# Help
# =============================================================================
help:
	@echo ""
	@echo "$(BLUE)Taint Analysis Masterclass$(NC)"
	@echo "=============================="
	@echo ""
	@echo "$(GREEN)Setup & Installation:$(NC)"
	@echo "  make setup          - Complete initial setup"
	@echo "  make install        - Install Python dependencies"
	@echo "  make install-dev    - Install development dependencies"
	@echo ""
	@echo "$(GREEN)Running:$(NC)"
	@echo "  make run            - Run VulnShop with Django dev server"
	@echo "  make docker-up      - Start all services with Docker"
	@echo "  make docker-down    - Stop all Docker services"
	@echo "  make docker-logs    - View Docker logs"
	@echo ""
	@echo "$(GREEN)Analysis:$(NC)"
	@echo "  make analyze-all    - Run all three analysis tools"
	@echo "  make analyze-pysa   - Run Pysa taint analysis"
	@echo "  make analyze-codeql - Run CodeQL analysis"
	@echo "  make analyze-semgrep - Run Semgrep analysis"
	@echo ""
	@echo "$(GREEN)Benchmarks:$(NC)"
	@echo "  make benchmark      - Run comparative benchmarks"
	@echo "  make benchmark-report - Generate benchmark report"
	@echo ""
	@echo "$(GREEN)Documentation:$(NC)"
	@echo "  make docs-serve     - Serve documentation locally"
	@echo "  make docs-build     - Build documentation"
	@echo ""
	@echo "$(GREEN)Code Quality:$(NC)"
	@echo "  make lint           - Run linter"
	@echo "  make format         - Format code"
	@echo "  make typecheck      - Run type checker"
	@echo "  make test           - Run tests"
	@echo ""
	@echo "$(GREEN)Maintenance:$(NC)"
	@echo "  make clean          - Clean generated files"
	@echo "  make clean-all      - Clean everything including venv"
	@echo ""

# =============================================================================
# Setup & Installation
# =============================================================================
setup: install-dev docker-build
	@echo "$(GREEN)Setup complete!$(NC)"
	@echo "Run 'make docker-up' to start services"

install:
	@echo "$(BLUE)Installing dependencies...$(NC)"
	cd vulnerable-app && $(PIP) install -r requirements.txt

install-dev:
	@echo "$(BLUE)Installing development dependencies...$(NC)"
	$(PIP) install -r requirements-dev.txt
	pre-commit install || true

venv:
	@echo "$(BLUE)Creating virtual environment...$(NC)"
	$(PYTHON) -m venv $(VENV)
	@echo "Activate with: source $(VENV)/bin/activate"

# =============================================================================
# Running
# =============================================================================
run:
	@echo "$(BLUE)Starting VulnShop...$(NC)"
	cd vulnerable-app && $(PYTHON) manage.py runserver 0.0.0.0:8000

run-migrate:
	@echo "$(BLUE)Running migrations...$(NC)"
	cd vulnerable-app && $(PYTHON) manage.py migrate

docker-build:
	@echo "$(BLUE)Building Docker images...$(NC)"
	$(DOCKER_COMPOSE) build

docker-up:
	@echo "$(BLUE)Starting Docker services...$(NC)"
	$(DOCKER_COMPOSE) up -d vulnshop docs
	@echo "$(GREEN)Services started:$(NC)"
	@echo "  VulnShop: http://localhost:8000"
	@echo "  Docs: http://localhost:8080"

docker-down:
	@echo "$(BLUE)Stopping Docker services...$(NC)"
	$(DOCKER_COMPOSE) down

docker-logs:
	$(DOCKER_COMPOSE) logs -f

stop: docker-down

# =============================================================================
# Analysis
# =============================================================================
analyze-all: analyze-pysa analyze-semgrep
	@echo "$(GREEN)All analyses complete!$(NC)"
	@echo "Results saved to analysis/*/results/"

analyze-pysa:
	@echo "$(BLUE)Running Pysa analysis...$(NC)"
	cd analysis/pysa && ./scripts/run_pysa.sh || echo "$(YELLOW)Pysa analysis completed with warnings$(NC)"

analyze-codeql:
	@echo "$(BLUE)Running CodeQL analysis...$(NC)"
	@echo "$(YELLOW)Note: CodeQL requires the CodeQL CLI to be installed$(NC)"
	cd analysis/codeql && ./scripts/run_analysis.sh || echo "$(YELLOW)CodeQL analysis requires manual setup$(NC)"

analyze-semgrep:
	@echo "$(BLUE)Running Semgrep analysis...$(NC)"
	semgrep scan \
		--config analysis/semgrep/rules/ \
		--config "p/python" \
		--config "p/django" \
		--sarif \
		--output analysis/semgrep/results/semgrep_results.sarif \
		--json-output analysis/semgrep/results/semgrep_results.json \
		vulnerable-app/
	@echo "$(GREEN)Semgrep analysis complete!$(NC)"

analyze-semgrep-docker:
	@echo "$(BLUE)Running Semgrep analysis (Docker)...$(NC)"
	$(DOCKER_COMPOSE) --profile analysis run --rm semgrep

# =============================================================================
# Benchmarks
# =============================================================================
benchmark:
	@echo "$(BLUE)Running benchmarks...$(NC)"
	$(PYTHON) benchmarks/scripts/run_benchmark.py --tool all
	@echo "$(GREEN)Benchmarks complete!$(NC)"

benchmark-report:
	@echo "$(BLUE)Generating benchmark report...$(NC)"
	$(PYTHON) benchmarks/scripts/generate_report.py \
		--input benchmarks/results/comparison.json \
		--output benchmarks/reports/benchmark_report.md
	@echo "$(GREEN)Report generated: benchmarks/reports/benchmark_report.md$(NC)"

# =============================================================================
# Documentation
# =============================================================================
docs-serve:
	@echo "$(BLUE)Starting documentation server...$(NC)"
	mkdocs serve -f docs/mkdocs.yml

docs-build:
	@echo "$(BLUE)Building documentation...$(NC)"
	mkdocs build -f docs/mkdocs.yml --strict
	@echo "$(GREEN)Documentation built: docs/site/$(NC)"

docs-deploy:
	@echo "$(BLUE)Deploying documentation to GitHub Pages...$(NC)"
	mkdocs gh-deploy -f docs/mkdocs.yml

# =============================================================================
# Code Quality
# =============================================================================
lint:
	@echo "$(BLUE)Running linter...$(NC)"
	ruff check .

lint-fix:
	@echo "$(BLUE)Running linter with auto-fix...$(NC)"
	ruff check --fix .

format:
	@echo "$(BLUE)Formatting code...$(NC)"
	ruff format .

format-check:
	@echo "$(BLUE)Checking code formatting...$(NC)"
	ruff format --check .

typecheck:
	@echo "$(BLUE)Running type checker...$(NC)"
	mypy --ignore-missing-imports vulnerable-app/ || true

test:
	@echo "$(BLUE)Running tests...$(NC)"
	pytest tests/ -v

test-cov:
	@echo "$(BLUE)Running tests with coverage...$(NC)"
	pytest tests/ -v --cov=vulnerable-app --cov-report=html

# =============================================================================
# Maintenance
# =============================================================================
clean:
	@echo "$(BLUE)Cleaning generated files...$(NC)"
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pyre/
	rm -rf docs/site/
	rm -rf htmlcov/
	rm -rf .coverage
	@echo "$(GREEN)Clean complete!$(NC)"

clean-all: clean
	@echo "$(BLUE)Cleaning everything...$(NC)"
	rm -rf $(VENV)/
	rm -rf analysis/pysa/results/*.json
	rm -rf analysis/pysa/results/*.sarif
	rm -rf analysis/codeql/results/*
	rm -rf analysis/semgrep/results/*.json
	rm -rf analysis/semgrep/results/*.sarif
	rm -rf benchmarks/results/*.json
	$(DOCKER_COMPOSE) down -v --rmi local 2>/dev/null || true
	@echo "$(GREEN)Full clean complete!$(NC)"

# =============================================================================
# Utility
# =============================================================================
check-tools:
	@echo "$(BLUE)Checking required tools...$(NC)"
	@command -v python3 >/dev/null 2>&1 && echo "$(GREEN)✓$(NC) Python3" || echo "$(RED)✗$(NC) Python3"
	@command -v pip3 >/dev/null 2>&1 && echo "$(GREEN)✓$(NC) pip3" || echo "$(RED)✗$(NC) pip3"
	@command -v docker >/dev/null 2>&1 && echo "$(GREEN)✓$(NC) Docker" || echo "$(RED)✗$(NC) Docker"
	@command -v docker-compose >/dev/null 2>&1 && echo "$(GREEN)✓$(NC) Docker Compose" || echo "$(RED)✗$(NC) Docker Compose"
	@command -v semgrep >/dev/null 2>&1 && echo "$(GREEN)✓$(NC) Semgrep" || echo "$(YELLOW)○$(NC) Semgrep (optional)"
	@command -v pyre >/dev/null 2>&1 && echo "$(GREEN)✓$(NC) Pyre/Pysa" || echo "$(YELLOW)○$(NC) Pyre/Pysa (optional)"
	@command -v codeql >/dev/null 2>&1 && echo "$(GREEN)✓$(NC) CodeQL" || echo "$(YELLOW)○$(NC) CodeQL (optional)"
	@command -v mkdocs >/dev/null 2>&1 && echo "$(GREEN)✓$(NC) MkDocs" || echo "$(YELLOW)○$(NC) MkDocs (optional)"

version:
	@echo "Taint Analysis Masterclass v1.0.0"
