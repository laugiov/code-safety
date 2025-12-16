# Pysa Taint Analysis Configuration

> **Pysa** (Python Static Analyzer) is Meta's open-source static analysis tool for Python that performs taint analysis to detect security vulnerabilities.

## Overview

This directory contains the complete Pysa configuration for analyzing the VulnShop vulnerable Django application. Pysa tracks data flow from **sources** (user input) to **sinks** (dangerous operations) to identify potential security vulnerabilities.

## Directory Structure

```
pysa/
├── .pyre_configuration       # Main Pyre/Pysa configuration
├── taint.config             # Taint rules (sources, sinks, rules)
├── models/
│   ├── django_sources.pysa  # Django request sources
│   ├── django_sinks.pysa    # Security-sensitive sinks
│   ├── django_sanitizers.pysa # Safe functions that sanitize data
│   ├── third_party.pysa     # Third-party library models
│   ├── vulnshop_custom.pysa # Application-specific models
│   └── vulnshop_auto.pysa   # Auto-generated view models
├── model_generators/
│   ├── __init__.py
│   └── generate_django_models.py # Auto-generates view models
├── stubs/
│   └── django/              # Type stubs for Django
├── filters/
│   ├── false_positives.json # Known FP suppressions
│   └── baseline.json        # Baseline for diff analysis
├── scripts/
│   ├── run_pysa.sh          # Main execution script
│   └── parse_results.py     # SARIF converter
├── results/
│   └── .gitkeep
└── README.md                # This file
```

## Quick Start

### Prerequisites

```bash
# Install Pyre and Pysa
pip install pyre-check

# Install VulnShop dependencies
pip install -r ../../vulnerable-app/requirements.txt
```

### Running Analysis

```bash
# Full analysis with SARIF output
./scripts/run_pysa.sh

# Skip type checking (faster)
./scripts/run_pysa.sh --skip-type-check

# Verbose output
./scripts/run_pysa.sh --verbose
```

### Output

Results are saved to:
- `results/pysa_results.json` - Raw Pysa findings
- `results/pysa_results.sarif` - SARIF format for GitHub Security
- `results/pysa_output.log` - Analysis log

## Taint Analysis Concepts

### Sources

Sources define where untrusted data enters the application:

```python
# Example: HTTP request parameters
def django.http.request.HttpRequest.GET.__getitem__(
    self, key
) -> TaintSource[UserControlled]: ...
```

**Configured Sources:**
- `UserControlled` - HTTP request data (GET, POST, body)
- `Cookies` - Browser cookies
- `FileSystem` - File contents
- `Database` - Data from database queries
- `Environment` - Environment variables
- `Headers` - HTTP headers
- `URL` - URL path and query strings

### Sinks

Sinks define dangerous operations where tainted data should not flow:

```python
# Example: SQL execution
def django.db.connection.cursor.execute(
    self, sql: TaintSink[SQL], params = None
): ...
```

**Configured Sinks:**
- `SQL` - SQL query execution (CWE-89)
- `CommandExecution` - OS command execution (CWE-78)
- `XSS` - Unescaped HTML output (CWE-79)
- `FileSystem` - File operations (CWE-22)
- `SSRF` - HTTP requests (CWE-918)
- `Deserialization` - Unsafe deserialization (CWE-502)
- `XMLParser` - XML parsing (CWE-611)
- `TemplateInjection` - Template construction (CWE-1336)
- `Logging` - Sensitive data logging (CWE-532)

### Sanitizers

Sanitizers define functions that make tainted data safe:

```python
# Example: HTML escaping
@Sanitize[XSS]
def django.utils.html.escape(text): ...
```

## Detection Matrix

| Vulnerability | CWE | Rule Code | Expected |
|--------------|-----|-----------|----------|
| SQL Injection (Auth) | CWE-89 | 5001 | ✅ |
| SQL Injection (Search) | CWE-89 | 5001 | ✅ |
| Reflected XSS | CWE-79 | 5006 | ✅ |
| Stored XSS | CWE-79 | 5006 | ✅ |
| Command Injection | CWE-78 | 5003 | ✅ |
| Path Traversal | CWE-22 | 5004 | ✅ |
| IDOR | CWE-639 | - | ⚠️ Partial |
| Mass Assignment | CWE-915 | - | ❌ |
| SSRF | CWE-918 | 5005 | ✅ |
| Insecure Deserialization | CWE-502 | 5007 | ✅ |
| SSTI | CWE-1336 | 5010 | ✅ |
| Hardcoded Secrets | CWE-798 | - | ❌ |
| Vulnerable Dependencies | CWE-1035 | - | ❌ |
| Sensitive Logging | CWE-532 | 5008 | ✅ |
| XXE | CWE-611 | 5009 | ✅ |
| Brute Force | CWE-307 | - | ❌ |

**Expected Detection Rate: 12/16 (75%)**

## Writing Custom Models

### Adding a New Source

```python
# models/custom.pysa
def myapp.utils.get_user_input(
    request
) -> TaintSource[UserControlled]: ...
```

### Adding a New Sink

```python
# models/custom.pysa
def myapp.utils.execute_query(
    query: TaintSink[SQL]
): ...
```

### Adding a Sanitizer

```python
# models/custom.pysa
@Sanitize[SQL]
def myapp.utils.sanitize_query(input): ...
```

## Troubleshooting

### "No rules triggered"

1. Verify sources and sinks are correctly modeled
2. Check that taint propagates through the code path
3. Run with `--verbose` for detailed analysis log

### Type Errors

Pysa requires type information. If you see many type errors:

```bash
# Generate type stubs for dependencies
pyre init
```

### Performance Issues

For large codebases:

```bash
# Increase workers
# Edit .pyre_configuration: "workers": 8

# Exclude non-essential directories
# Add to "exclude" in .pyre_configuration
```

## Integration

### GitHub Actions

```yaml
- name: Run Pysa
  run: |
    pip install pyre-check
    cd analysis/pysa
    ./scripts/run_pysa.sh

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: analysis/pysa/results/pysa_results.sarif
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
- repo: local
  hooks:
    - id: pysa
      name: Pysa Security Analysis
      entry: bash -c 'cd analysis/pysa && ./scripts/run_pysa.sh --skip-type-check'
      language: system
      pass_filenames: false
```

## References

- [Pysa Documentation](https://pyre-check.org/docs/pysa-basics/)
- [Pysa Model DSL](https://pyre-check.org/docs/pysa-model-dsl/)
- [Taint Analysis in Pysa](https://pyre-check.org/docs/pysa-features/)
- [SARIF Specification](https://sarifweb.azurewebsites.net/)

---

*Part of the Taint Analysis Masterclass project*
