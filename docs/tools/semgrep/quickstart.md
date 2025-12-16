---
title: Semgrep Quick Start
description: Get running with Semgrep in 5 minutes
---

# Semgrep Quick Start

Get Semgrep running and detecting vulnerabilities in under 5 minutes.

## Installation

### Via pip (Recommended)

```bash
pip install semgrep
```

### Via Homebrew (macOS)

```bash
brew install semgrep
```

### Via Docker

```bash
docker run --rm -v "${PWD}:/src" returntocorp/semgrep semgrep --config auto
```

### Verify Installation

```bash
semgrep --version
# Output: semgrep 1.x.x
```

## First Scan

### Using Auto Config

Semgrep's auto mode selects appropriate rules automatically:

```bash
cd vulnerable-app
semgrep --config auto
```

### Using Project Rules

Run with VulnShop's custom rules:

```bash
cd analysis/semgrep
semgrep --config rules/ ../../vulnerable-app/
```

### Using Registry Rules

Semgrep has thousands of community rules:

```bash
# Python security rules
semgrep --config "p/python"

# Django-specific rules
semgrep --config "p/django"

# OWASP Top 10
semgrep --config "p/owasp-top-ten"

# Combine multiple configs
semgrep --config "p/python" --config "p/django" --config rules/
```

## Understanding Output

### Default Output

```
┌──────────────────────────────────────────────────────────────┐
│ 5 Findings                                                   │
└──────────────────────────────────────────────────────────────┘

  authentication/views.py
  ❯❯❱ sql-injection-format-string
        SQL injection via format string

          24┆ cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")

  catalog/views.py
  ❯❯❱ command-injection
        Command injection via os.system

          42┆ os.system(f"convert {input_file} {output_file}")
```

### JSON Output

```bash
semgrep --config rules/ --json vulnerable-app/ > results.json
```

```json
{
  "results": [
    {
      "check_id": "sql-injection-format-string",
      "path": "authentication/views.py",
      "start": {"line": 24, "col": 4},
      "end": {"line": 24, "col": 72},
      "message": "SQL injection via format string",
      "severity": "ERROR"
    }
  ],
  "errors": []
}
```

### SARIF Output (GitHub Compatible)

```bash
semgrep --config rules/ --sarif vulnerable-app/ > results.sarif
```

## Common Options

| Option | Description | Example |
|--------|-------------|---------|
| `--config` | Rule configuration | `--config rules/` |
| `--json` | JSON output | `--json` |
| `--sarif` | SARIF output | `--sarif` |
| `--output` | Output file | `--output results.json` |
| `--severity` | Filter by severity | `--severity ERROR` |
| `--exclude` | Exclude paths | `--exclude tests/` |
| `--include` | Include only paths | `--include src/` |
| `--verbose` | Verbose output | `-v` or `-vvv` |
| `--quiet` | Suppress non-findings | `-q` |

## Filtering Results

### By Severity

```bash
# Only errors
semgrep --config rules/ --severity ERROR vulnerable-app/

# Errors and warnings
semgrep --config rules/ --severity ERROR --severity WARNING vulnerable-app/
```

### By Path

```bash
# Exclude tests
semgrep --config rules/ --exclude "test*" --exclude "*_test.py" vulnerable-app/

# Only specific directories
semgrep --config rules/ --include "authentication/" --include "cart/" vulnerable-app/
```

### By Rule ID

```bash
# Exclude specific rules
semgrep --config rules/ --exclude-rule "hardcoded-secret" vulnerable-app/
```

## Project Configuration

Create `.semgrep.yml` in your project root:

```yaml
rules:
  - id: project-sql-injection
    pattern: cursor.execute(f"...")
    message: Use parameterized queries
    severity: ERROR
    languages: [python]
```

Or create `.semgrep/` directory:

```
.semgrep/
├── sql-injection.yml
├── xss.yml
└── command-injection.yml
```

Then run:

```bash
semgrep --config .semgrep/ .
```

## Using with VulnShop

### Run Analysis Script

```bash
cd analysis/semgrep
./scripts/run_semgrep.sh
```

### Script Contents

```bash
#!/bin/bash
# scripts/run_semgrep.sh

RULES_DIR="rules"
TARGET_DIR="../../vulnerable-app"
OUTPUT_DIR="results"

mkdir -p "$OUTPUT_DIR"

echo "Running Semgrep analysis..."

semgrep \
  --config "$RULES_DIR" \
  --json \
  --output "$OUTPUT_DIR/semgrep_results.json" \
  "$TARGET_DIR"

echo "Results saved to $OUTPUT_DIR/semgrep_results.json"

# Summary
FINDINGS=$(jq '.results | length' "$OUTPUT_DIR/semgrep_results.json")
echo "Total findings: $FINDINGS"
```

### View Results

```bash
# Count findings
jq '.results | length' results/semgrep_results.json

# List findings by rule
jq -r '.results | group_by(.check_id) | .[] | "\(.[0].check_id): \(length)"' results/semgrep_results.json

# Show specific finding details
jq '.results[0]' results/semgrep_results.json
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Semgrep

on: [push, pull_request]

jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/python
            analysis/semgrep/rules/
```

### GitLab CI

```yaml
semgrep:
  stage: test
  image: returntocorp/semgrep
  script:
    - semgrep --config "p/python" --config "rules/" --sarif --output semgrep.sarif .
  artifacts:
    reports:
      sast: semgrep.sarif
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/returntocorp/semgrep
    rev: v1.45.0
    hooks:
      - id: semgrep
        args: ['--config', 'p/python', '--error']
```

## Quick Rule Writing

### Simple Pattern Rule

```yaml
# .semgrep/dangerous-eval.yml
rules:
  - id: dangerous-eval
    pattern: eval($X)
    message: Avoid eval() - can execute arbitrary code
    severity: ERROR
    languages: [python]
```

### Test Your Rule

```bash
# Create test file
echo 'eval(user_input)' > test.py

# Run rule
semgrep --config .semgrep/dangerous-eval.yml test.py
```

## Troubleshooting

### "No rules found"

```bash
# Check rule syntax
semgrep --validate --config rules/

# Verify YAML format
python -c "import yaml; yaml.safe_load(open('rules/sql-injection.yml'))"
```

### "Parse error"

```bash
# Run with verbose output
semgrep --config rules/ -vvv vulnerable-app/ 2>&1 | head -50
```

### "Too many findings"

```bash
# Add exclusions
semgrep --config rules/ \
  --exclude "test*" \
  --exclude "**/migrations/**" \
  --exclude "**/node_modules/**" \
  vulnerable-app/
```

### Performance Issues

```bash
# Limit file types
semgrep --config rules/ --include "*.py" vulnerable-app/

# Use fewer rules
semgrep --config rules/injection/ vulnerable-app/

# Increase timeout
semgrep --config rules/ --timeout 60 vulnerable-app/
```

## Next Steps

- [Writing Rules](rules.md) - Create custom rules
- [Taint Mode](taint-mode.md) - Dataflow tracking
- [Semgrep Overview](index.md) - Full documentation
