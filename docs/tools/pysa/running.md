---
title: Running Pysa
description: Execute Pysa analysis and interpret results
---

# Running Pysa

This guide covers executing Pysa analysis, understanding output, and interpreting results.

## Basic Execution

### Using the Provided Script

```bash
cd analysis/pysa
./scripts/run_pysa.sh
```

### Direct Execution

```bash
# Navigate to Pysa configuration directory
cd analysis/pysa

# Run analysis
pyre analyze --save-results-to results/
```

### Full Command Options

```bash
pyre analyze \
  --save-results-to results/ \
  --output-format sarif \
  --maximum-trace-length 20 \
  --no-verify
```

## Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--save-results-to DIR` | Output directory | Current directory |
| `--output-format FORMAT` | Output format (json, sarif, text) | json |
| `--maximum-trace-length N` | Max depth for taint traces | 20 |
| `--no-verify` | Skip model verification | Verify enabled |
| `--dump-call-graph` | Output call graph for debugging | Disabled |
| `--repository-root PATH` | Root for relative paths | Auto-detected |

## Understanding Output

### JSON Output Format

```json
{
  "kind": "issue",
  "data": {
    "callable": "vulnerable_app.authentication.views.login_view",
    "callable_line": 25,
    "code": 5001,
    "line": 32,
    "start": 20,
    "end": 45,
    "filename": "vulnerable-app/authentication/views.py",
    "message": "User-controlled data flows to SQL query",
    "traces": [
      {
        "name": "forward",
        "roots": [
          {
            "call": {
              "position": {"line": 28, "start": 15, "end": 35},
              "resolves_to": ["django.http.request.QueryDict.__getitem__"],
              "port": "result"
            },
            "tito": null,
            "leaves": [{"kind": "UserControlled"}]
          }
        ]
      },
      {
        "name": "backward",
        "roots": [
          {
            "call": {
              "position": {"line": 32, "start": 20, "end": 45},
              "resolves_to": ["django.db.backends.utils.CursorWrapper.execute"],
              "port": "formal(sql)"
            },
            "tito": null,
            "leaves": [{"kind": "SQL"}]
          }
        ]
      }
    ]
  }
}
```

### Key Fields Explained

| Field | Description |
|-------|-------------|
| `code` | Rule code from taint.config |
| `callable` | Function containing the vulnerability |
| `filename` | Source file path |
| `line` | Line number of the sink |
| `message` | Human-readable description |
| `traces` | Forward (source) and backward (sink) traces |

## SARIF Output

For GitHub integration, use SARIF format:

```bash
pyre analyze --output-format sarif --save-results-to results/
```

SARIF files can be uploaded to GitHub Security tab:

```yaml
# .github/workflows/pysa.yml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: analysis/pysa/results/results.sarif
```

## Interpreting Results

### Trace Reading

A typical trace shows the complete data flow:

```
Source: request.GET["username"]
  ↓ (via format-string)
Call: f"SELECT * FROM users WHERE name = '{username}'"
  ↓ (via parameter)
Sink: cursor.execute(query)
```

### Understanding Features

Features describe how taint propagated:

| Feature | Meaning |
|---------|---------|
| `via-format-string` | Taint flowed through f-string or .format() |
| `via-concatenation` | Taint flowed through string concatenation |
| `via-getattr` | Taint flowed through attribute access |
| `via-dictionary` | Taint flowed through dict operations |
| `via-return` | Taint returned from function call |

### Severity Assessment

Pysa reports all findings equally. Assess severity based on:

1. **Source controllability**: How much control does an attacker have?
2. **Sink impact**: What's the worst case if exploited?
3. **Sanitization proximity**: Are there partial sanitizers nearby?

## Filtering Results

### By Rule Code

```python
# scripts/filter_results.py
import json

with open('results/results.json') as f:
    results = json.load(f)

# Filter for SQL injection only (code 5001)
sql_issues = [r for r in results if r['data']['code'] == 5001]
print(f"SQL Injection issues: {len(sql_issues)}")
```

### By File Path

```python
# Filter for authentication module
auth_issues = [r for r in results
               if 'authentication' in r['data']['filename']]
```

### By Severity

```python
# Define severity by rule code
HIGH_SEVERITY = [5001, 5003, 5007]  # SQL, RCE, Deserialization
MEDIUM_SEVERITY = [5004, 5005, 5006]  # Path, SSRF, XSS
LOW_SEVERITY = [5008]  # Logging

high_issues = [r for r in results
               if r['data']['code'] in HIGH_SEVERITY]
```

## Debugging Analysis

### Verbose Mode

```bash
PYRE_LOG_LEVEL=debug pyre analyze 2>&1 | tee analysis.log
```

### Model Verification

```bash
# Check for model errors
pyre analyze --verify-models 2>&1 | grep -i error
```

### Call Graph Analysis

```bash
# Dump call graph for inspection
pyre analyze --dump-call-graph > call_graph.txt
```

### Type Errors

If Pysa fails, first fix type errors:

```bash
pyre check
```

## Performance Optimization

### Incremental Analysis

```bash
# First run - full analysis
pyre analyze --save-results-to results/

# Subsequent runs - incremental
pyre incremental
```

### Parallel Execution

```json
// .pyre_configuration
{
  "number_of_workers": 8
}
```

### Memory Management

```bash
# Increase heap size for large codebases
export PYRE_HEAP_SIZE=8589934592
pyre analyze
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Pysa Security Analysis

on: [push, pull_request]

jobs:
  pysa:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.10'

      - name: Install Pyre
        run: pip install pyre-check

      - name: Run Pysa
        run: |
          cd analysis/pysa
          pyre analyze --output-format sarif \
            --save-results-to results/

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: analysis/pysa/results/results.sarif
```

### GitLab CI

```yaml
pysa:
  stage: security
  image: python:3.10
  script:
    - pip install pyre-check
    - cd analysis/pysa
    - pyre analyze --save-results-to results/
  artifacts:
    paths:
      - analysis/pysa/results/
    reports:
      sast: analysis/pysa/results/results.sarif
```

## Parsing Results Script

Complete parsing script for VulnShop:

```python
#!/usr/bin/env python3
"""Parse and summarize Pysa results."""

import json
import sys
from collections import defaultdict
from pathlib import Path

RULES = {
    5001: "SQL Injection",
    5003: "Command Injection",
    5004: "Path Traversal",
    5005: "SSRF",
    5006: "XSS",
    5007: "Insecure Deserialization",
    5008: "Sensitive Data Logging",
    5009: "XXE",
    5010: "SSTI"
}

def parse_results(results_file: Path):
    with open(results_file) as f:
        results = json.load(f)

    # Group by rule
    by_rule = defaultdict(list)
    for issue in results:
        code = issue['data']['code']
        by_rule[code].append(issue)

    # Summary
    print("=" * 60)
    print("PYSA ANALYSIS SUMMARY")
    print("=" * 60)
    print(f"\nTotal issues: {len(results)}\n")

    print("Issues by type:")
    print("-" * 40)
    for code, issues in sorted(by_rule.items()):
        name = RULES.get(code, f"Unknown ({code})")
        print(f"  {name}: {len(issues)}")

    # Details
    print("\n" + "=" * 60)
    print("DETAILED FINDINGS")
    print("=" * 60)

    for code, issues in sorted(by_rule.items()):
        name = RULES.get(code, f"Unknown ({code})")
        print(f"\n### {name} ({len(issues)} issues)")

        for i, issue in enumerate(issues, 1):
            data = issue['data']
            print(f"\n  {i}. {data['filename']}:{data['line']}")
            print(f"     Function: {data['callable']}")
            print(f"     Message: {data['message']}")

if __name__ == "__main__":
    results_file = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("results/results.json")
    parse_results(results_file)
```

## Common Issues

### "No sources found"

Check that your source models match actual code:

```bash
# Verify sources are defined
grep -r "TaintSource" models/
```

### "Analysis timeout"

Reduce trace length or exclude complex paths:

```bash
pyre analyze --maximum-trace-length 10
```

### "Memory exhausted"

Increase available memory or reduce analysis scope:

```json
{
  "exclude": [".*/large_generated_module/.*"]
}
```

## Next Steps

- [Advanced Techniques](advanced.md) - Complex patterns and optimization
- [Writing Models](models.md) - Customize source/sink definitions
- [Configuration](configuration.md) - Fine-tune settings
