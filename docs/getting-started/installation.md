---
title: Installation
description: Complete installation guide for the Taint Analysis Masterclass project
---

# Installation Guide

This guide walks you through setting up the Taint Analysis Masterclass project locally.

## Prerequisites

Before starting, ensure you have:

| Requirement | Minimum Version | Recommended |
|------------|-----------------|-------------|
| Python | 3.11+ | 3.12 |
| Docker | 20.10+ | Latest |
| Docker Compose | 2.0+ | Latest |
| Git | 2.30+ | Latest |
| Memory | 4GB RAM | 8GB+ |
| Disk Space | 5GB | 10GB+ |

### Platform-Specific Notes

=== "Linux"

    ```bash
    # Ubuntu/Debian
    sudo apt update
    sudo apt install python3.11 python3.11-venv docker.io docker-compose git

    # Add user to docker group
    sudo usermod -aG docker $USER
    ```

=== "macOS"

    ```bash
    # Using Homebrew
    brew install python@3.11 docker docker-compose git

    # Start Docker Desktop from Applications
    ```

=== "Windows"

    ```powershell
    # Using winget
    winget install Python.Python.3.11
    winget install Docker.DockerDesktop
    winget install Git.Git

    # Start Docker Desktop
    ```

## Quick Installation

### Clone the Repository

```bash
git clone https://github.com/laugiov/taint-analysis-masterclass.git
cd taint-analysis-masterclass
```

### Start with Docker (Recommended)

```bash
# Build and start all services
docker-compose up -d

# Verify services are running
docker-compose ps
```

**Expected output:**
```
NAME                STATUS
vulnshop            running (0.0.0.0:8000->8000/tcp)
docs                running (0.0.0.0:8080->8080/tcp)
```

### Access the Applications

| Application | URL | Description |
|------------|-----|-------------|
| VulnShop | [http://localhost:8000](http://localhost:8000) | Vulnerable Django app |
| Documentation | [http://localhost:8080](http://localhost:8080) | This documentation |

## Manual Installation

For development or tool integration, install locally without Docker.

### 1. Create Virtual Environment

```bash
python3.11 -m venv venv
source venv/bin/activate  # Linux/macOS
# .\venv\Scripts\Activate  # Windows
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Development tools
```

### 3. Setup VulnShop

```bash
cd vulnerable-app
python manage.py migrate
python manage.py loaddata fixtures/demo_data.json
python manage.py runserver 8000
```

### 4. Verify Installation

```bash
# Run tests
pytest tests/

# Check VulnShop is running
curl http://localhost:8000/health/
```

## Installing Analysis Tools

### Pysa (Pyre)

```bash
pip install pyre-check

# Verify
pyre --version
```

**Configure for the project:**
```bash
cd analysis/pysa
# Configuration is already in .pyre_configuration
```

### CodeQL

```bash
# Download CodeQL CLI from GitHub releases
# https://github.com/github/codeql-action/releases

# Extract and add to PATH
export PATH="$PATH:/path/to/codeql"

# Verify
codeql --version
```

**Initial setup:**
```bash
cd analysis/codeql
codeql database create ../vulnerable-app-db --language=python --source-root=../../vulnerable-app
```

### Semgrep

```bash
pip install semgrep

# Or using Homebrew (macOS)
brew install semgrep

# Verify
semgrep --version
```

**Test configuration:**
```bash
cd analysis/semgrep
semgrep --validate --config rules/
```

## Running Analyses

### All Tools at Once

```bash
make analyze-all
```

### Individual Tools

```bash
# Pysa
make analyze-pysa
# Or manually:
cd analysis/pysa && ./scripts/run_pysa.sh

# CodeQL
make analyze-codeql
# Or manually:
cd analysis/codeql && ./scripts/run_analysis.sh

# Semgrep
make analyze-semgrep
# Or manually:
cd analysis/semgrep && ./scripts/run_semgrep.sh
```

### View Results

Results are saved in SARIF format for each tool:

```bash
ls -la analysis/*/results/
```

## Troubleshooting

### Docker Issues

**Container won't start:**
```bash
# Check logs
docker-compose logs vulnshop

# Restart containers
docker-compose down && docker-compose up -d
```

**Port conflicts:**
```bash
# Change ports in docker-compose.yml
# Or stop conflicting services
lsof -i :8000
```

### Python Issues

**Wrong Python version:**
```bash
# Use pyenv to manage versions
pyenv install 3.11.0
pyenv local 3.11.0
```

**Missing dependencies:**
```bash
pip install --upgrade -r requirements.txt
```

### Tool-Specific Issues

**Pysa fails:**
```bash
# Ensure type stubs are present
cd analysis/pysa
pyre check --noninteractive
```

**CodeQL database creation fails:**
```bash
# Ensure Python extractor is available
codeql resolve languages
codeql database create --language=python --source-root=../../vulnerable-app fresh-db
```

**Semgrep rule errors:**
```bash
# Validate rules
semgrep --validate --config rules/
```

## Development Setup

For contributing or customizing:

### Install Pre-Commit Hooks

```bash
pip install pre-commit
pre-commit install
```

### Run Tests

```bash
# All tests
pytest

# With coverage
pytest --cov=vulnerable-app --cov-report=html
```

### Documentation Development

```bash
pip install mkdocs-material
cd docs
mkdocs serve
# Access at http://localhost:8000
```

## Next Steps

After installation:

1. **[Explore VulnShop](../vulnshop/overview.md)** - Understand the vulnerable application
2. **[Run Benchmarks](../benchmarks/running.md)** - Compare tool performance
3. **[Tool Guides](../tools/index.md)** - Learn each tool in depth

---

*Need help? [Open an issue](https://github.com/laugiov/taint-analysis-masterclass/issues)*
