---
title: Prerequisites
description: System requirements for running Taint Analysis Masterclass
---

# Prerequisites

Before installing the Taint Analysis Masterclass, ensure your system meets these requirements.

## System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **OS** | Linux, macOS, Windows (WSL2) | Ubuntu 22.04+, macOS 13+ |
| **RAM** | 4 GB | 8 GB+ |
| **Disk Space** | 5 GB | 10 GB |
| **CPU** | 2 cores | 4+ cores |

## Required Software

### Python 3.11+

```bash
# Check version
python3 --version
# Should be 3.11 or higher
```

=== "Ubuntu/Debian"
    ```bash
    sudo apt update
    sudo apt install python3.11 python3.11-venv python3-pip
    ```

=== "macOS"
    ```bash
    brew install python@3.11
    ```

=== "Windows (WSL2)"
    ```bash
    # In WSL2 Ubuntu
    sudo apt update
    sudo apt install python3.11 python3.11-venv python3-pip
    ```

### Docker & Docker Compose

Docker is required for running VulnShop and optionally the documentation server.

```bash
# Check version
docker --version
docker compose version
```

=== "Ubuntu/Debian"
    ```bash
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
    # Log out and back in
    ```

=== "macOS"
    ```bash
    brew install --cask docker
    # Or download Docker Desktop from docker.com
    ```

=== "Windows"
    Download and install [Docker Desktop](https://www.docker.com/products/docker-desktop/)

### Git

```bash
git --version
```

=== "Ubuntu/Debian"
    ```bash
    sudo apt install git
    ```

=== "macOS"
    ```bash
    brew install git
    ```

## Optional (Tool-Specific)

### For Pysa Analysis

Pysa requires Pyre, Meta's type checker.

```bash
pip install pyre-check
pyre --version
```

### For CodeQL Analysis

Download CodeQL CLI from [GitHub Releases](https://github.com/github/codeql-action/releases).

```bash
# After extracting, add to PATH
export PATH="$PATH:/path/to/codeql"
codeql --version
```

### For Semgrep Analysis

```bash
pip install semgrep
# or
brew install semgrep

semgrep --version
```

## Verification Script

Run this script to verify all prerequisites:

```bash
#!/bin/bash
echo "Checking prerequisites..."

# Python
if command -v python3 &>/dev/null; then
    VERSION=$(python3 --version | cut -d' ' -f2)
    echo "✓ Python: $VERSION"
else
    echo "✗ Python 3 not found"
fi

# Docker
if command -v docker &>/dev/null; then
    VERSION=$(docker --version | cut -d' ' -f3 | tr -d ',')
    echo "✓ Docker: $VERSION"
else
    echo "✗ Docker not found"
fi

# Git
if command -v git &>/dev/null; then
    VERSION=$(git --version | cut -d' ' -f3)
    echo "✓ Git: $VERSION"
else
    echo "✗ Git not found"
fi

# Pyre (optional)
if command -v pyre &>/dev/null; then
    echo "✓ Pyre installed"
else
    echo "○ Pyre not installed (optional)"
fi

# Semgrep (optional)
if command -v semgrep &>/dev/null; then
    echo "✓ Semgrep installed"
else
    echo "○ Semgrep not installed (optional)"
fi

# CodeQL (optional)
if command -v codeql &>/dev/null; then
    echo "✓ CodeQL installed"
else
    echo "○ CodeQL not installed (optional)"
fi

echo "Prerequisites check complete."
```

## Network Requirements

The following access may be required:

| Purpose | URLs |
|---------|------|
| Docker images | `docker.io`, `ghcr.io` |
| Python packages | `pypi.org` |
| Semgrep rules | `semgrep.dev` |
| CodeQL packs | `github.com` |

## Next Steps

Once prerequisites are verified:

[:octicons-arrow-right-24: Proceed to Installation](installation.md)
