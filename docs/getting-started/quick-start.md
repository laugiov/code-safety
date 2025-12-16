---
title: Quick Start
description: Get running with Taint Analysis Masterclass in 5 minutes
---

# Quick Start

Get VulnShop running and execute your first taint analysis in under 5 minutes.

## 1. Clone the Repository

```bash
git clone https://github.com/laugiov/taint-analysis-masterclass.git
cd taint-analysis-masterclass
```

## 2. Start VulnShop

```bash
docker-compose up -d
```

Verify it's running:

```bash
docker-compose ps
# Should show vulnshop as running
```

Access VulnShop: [http://localhost:8000](http://localhost:8000)

## 3. Run Your First Analysis

### Option A: Run All Tools

```bash
make analyze-all
```

This runs Pysa, CodeQL, and Semgrep sequentially.

### Option B: Run Individual Tools

=== "Semgrep (Fastest)"
    ```bash
    make analyze-semgrep
    # Or directly:
    cd analysis/semgrep
    ./scripts/run_semgrep.sh
    ```
    **Time:** ~5 seconds

=== "Pysa"
    ```bash
    make analyze-pysa
    # Or directly:
    cd analysis/pysa
    ./scripts/run_pysa.sh
    ```
    **Time:** ~45 seconds

=== "CodeQL"
    ```bash
    make analyze-codeql
    # Or directly:
    cd analysis/codeql
    ./scripts/run_analysis.sh
    ```
    **Time:** ~2 minutes

## 4. View Results

Results are saved in SARIF format (compatible with GitHub Security):

```bash
# Semgrep results
cat analysis/semgrep/results/semgrep_results.json | jq '.results | length'

# Pysa results
cat analysis/pysa/results/pysa_results.json | jq 'length'

# CodeQL results
cat analysis/codeql/results/codeql_results.sarif | jq '.runs[0].results | length'
```

## 5. Explore VulnShop

VulnShop is a deliberately vulnerable e-commerce application. Try these pages:

| Page | Vulnerability | URL |
|------|--------------|-----|
| Login | SQL Injection | `/auth/login/` |
| Search | SQL Injection + XSS | `/catalog/search/` |
| Admin Diagnostics | Command Injection | `/admin-panel/diagnostics/` |
| Webhook Tester | SSRF | `/webhooks/test/` |

!!! warning "Security Notice"
    VulnShop contains real vulnerabilities. Never expose it to the internet!

## 6. Run Benchmarks

Compare tool performance against ground truth:

```bash
cd benchmarks
python scripts/run_benchmarks.py --tools semgrep

# Generate report
python scripts/generate_report.py
```

## What's Next?

<div class="grid cards" markdown>

-   :material-school:{ .lg .middle } **Learn the Theory**

    ---

    Understand how taint analysis works

    [:octicons-arrow-right-24: Taint Analysis 101](../theory/taint-analysis-101.md)

-   :material-tools:{ .lg .middle } **Master the Tools**

    ---

    Deep dive into Pysa, CodeQL, and Semgrep

    [:octicons-arrow-right-24: Tool Comparison](../tools/index.md)

-   :material-bug:{ .lg .middle } **Explore Vulnerabilities**

    ---

    Learn about each vulnerability type

    [:octicons-arrow-right-24: Vulnerability Catalog](../vulnerabilities/index.md)

-   :material-factory:{ .lg .middle } **CI/CD Integration**

    ---

    Add security analysis to your pipeline

    [:octicons-arrow-right-24: Enterprise Guide](../enterprise/index.md)

</div>

## Troubleshooting

### Docker won't start

```bash
# Check Docker daemon
sudo systemctl status docker

# Check port conflicts
lsof -i :8000
```

### Make commands not found

```bash
# Install make
sudo apt install make  # Ubuntu
brew install make      # macOS
```

### Semgrep fails

```bash
# Ensure semgrep is installed
pip install semgrep
semgrep --version
```

### Permission denied on scripts

```bash
chmod +x analysis/*/scripts/*.sh
chmod +x benchmarks/scripts/*.py
```

---

*Need more details? Check the [full installation guide](installation.md).*
