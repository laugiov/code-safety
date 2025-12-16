---
title: Running Benchmarks
description: How to execute benchmarks yourself
---

# Running Benchmarks

Execute and customize benchmarks for your own analysis.

## Prerequisites

```bash
# Required tools
pip install semgrep pyre-check

# CodeQL CLI
# Download from: https://github.com/github/codeql-cli-binaries/releases

# Python dependencies
pip install jq tabulate matplotlib
```

## Quick Start

### Run All Benchmarks

```bash
cd benchmarks
python scripts/run_benchmarks.py --tools all
```

### Run Specific Tool

```bash
# Semgrep only
python scripts/run_benchmarks.py --tools semgrep

# Pysa only
python scripts/run_benchmarks.py --tools pysa

# CodeQL only
python scripts/run_benchmarks.py --tools codeql
```

## Benchmark Script Usage

```bash
python scripts/run_benchmarks.py [OPTIONS]

Options:
  --tools TOOLS        Tools to benchmark (all, semgrep, pysa, codeql)
  --target PATH        Target directory to analyze
  --output DIR         Output directory for results
  --ground-truth FILE  Ground truth file for comparison
  --iterations N       Number of iterations (default: 3)
  --verbose            Enable verbose output
```

### Examples

```bash
# Benchmark with custom target
python scripts/run_benchmarks.py \
  --tools all \
  --target /path/to/your/project \
  --ground-truth custom-ground-truth.json

# Multiple iterations for statistics
python scripts/run_benchmarks.py \
  --tools all \
  --iterations 5 \
  --output results/statistical/
```

## Generating Reports

```bash
python scripts/generate_report.py [OPTIONS]

Options:
  --input DIR          Results directory
  --format FORMAT      Output format (markdown, html, csv)
  --output FILE        Output file path
  --include-charts     Generate visualization charts
```

### Examples

```bash
# Markdown report
python scripts/generate_report.py \
  --input results/ \
  --format markdown \
  --output BENCHMARK_REPORT.md

# HTML report with charts
python scripts/generate_report.py \
  --input results/ \
  --format html \
  --include-charts \
  --output reports/benchmark.html
```

## Custom Ground Truth

### Creating Ground Truth File

```json
{
  "vulnerabilities": [
    {
      "id": "CUSTOM-001",
      "name": "SQL Injection in UserService",
      "type": "sql-injection",
      "cwe": "CWE-89",
      "file": "services/user.py",
      "line": 45,
      "function": "get_user",
      "source": "request.args['id']",
      "sink": "db.execute(query)"
    }
  ]
}
```

### Validating Ground Truth

```bash
python scripts/validate_ground_truth.py ground-truth/custom.json
```

## Interpreting Results

### Result Files

```
results/
├── semgrep/
│   └── results.json
├── pysa/
│   └── results.json
├── codeql/
│   └── results.sarif
└── comparison.json
```

### Comparison Output

```json
{
  "summary": {
    "semgrep": {"tp": 11, "fp": 2, "fn": 5},
    "pysa": {"tp": 12, "fp": 1, "fn": 4},
    "codeql": {"tp": 14, "fp": 1, "fn": 2}
  },
  "metrics": {
    "semgrep": {"precision": 0.85, "recall": 0.69, "f1": 0.76},
    "pysa": {"precision": 0.92, "recall": 0.75, "f1": 0.83},
    "codeql": {"precision": 0.93, "recall": 0.88, "f1": 0.90}
  }
}
```

## Customizing Analysis

### Custom Semgrep Rules

```bash
python scripts/run_benchmarks.py \
  --tools semgrep \
  --semgrep-config /path/to/custom/rules/
```

### Custom Pysa Models

```bash
python scripts/run_benchmarks.py \
  --tools pysa \
  --pysa-models /path/to/custom/models/
```

### Custom CodeQL Queries

```bash
python scripts/run_benchmarks.py \
  --tools codeql \
  --codeql-queries /path/to/custom/queries/
```

## Continuous Benchmarking

### GitHub Actions

```yaml
name: Benchmarks

on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Benchmarks
        run: |
          cd benchmarks
          python scripts/run_benchmarks.py --tools all

      - name: Generate Report
        run: |
          python scripts/generate_report.py --format markdown

      - name: Upload Results
        uses: actions/upload-artifact@v4
        with:
          name: benchmark-results
          path: benchmarks/results/
```

## Troubleshooting

### Semgrep Timeout

```bash
python scripts/run_benchmarks.py \
  --tools semgrep \
  --semgrep-timeout 300
```

### CodeQL Memory Issues

```bash
python scripts/run_benchmarks.py \
  --tools codeql \
  --codeql-ram 16384
```

### Pysa Type Errors

```bash
# Run Pyre check first
pyre check

# Then run Pysa
python scripts/run_benchmarks.py --tools pysa
```
