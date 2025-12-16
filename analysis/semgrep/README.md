# Semgrep Analysis Configuration

> **Semgrep** is a fast, open-source static analysis tool that uses pattern matching to find bugs and security vulnerabilities in code.

## Overview

This directory contains custom Semgrep rules for analyzing the VulnShop vulnerable Django application. Semgrep provides fast, lightweight pattern matching that complements the deeper taint analysis of Pysa and CodeQL.

## Directory Structure

```
semgrep/
├── .semgrep.yml                    # Main configuration
├── rules/
│   ├── injection/
│   │   ├── sql-injection.yml       # SQL injection patterns
│   │   ├── command-injection.yml   # OS command injection
│   │   ├── xss.yml                 # Cross-site scripting
│   │   └── ssti.yml                # Template injection
│   ├── access-control/
│   │   ├── path-traversal.yml      # Path traversal
│   │   ├── idor.yml                # IDOR patterns
│   │   └── mass-assignment.yml     # Mass assignment
│   ├── crypto/
│   │   ├── hardcoded-secrets.yml   # Hardcoded credentials
│   │   └── weak-crypto.yml         # Weak cryptography
│   ├── deserialization/
│   │   └── insecure-deser.yml      # Insecure deserialization
│   ├── ssrf/
│   │   └── ssrf.yml                # SSRF patterns
│   ├── xxe/
│   │   └── xxe.yml                 # XXE patterns
│   └── logging/
│       └── sensitive-data.yml      # Sensitive data logging
├── scripts/
│   └── run_semgrep.sh              # Execution script
├── results/
│   └── .gitkeep
└── README.md                       # This file
```

## Quick Start

### Prerequisites

```bash
# Install Semgrep
pip install semgrep

# Or using Homebrew
brew install semgrep

# Verify installation
semgrep --version
```

### Running Analysis

```bash
# Full analysis with custom and community rules
./scripts/run_semgrep.sh

# Custom rules only
./scripts/run_semgrep.sh --rules-only

# Verbose output
./scripts/run_semgrep.sh --verbose

# JSON output
./scripts/run_semgrep.sh --output-format json
```

### Output

Results are saved to:
- `results/semgrep_results.sarif` - SARIF format for GitHub Security
- `results/semgrep_results.json` - JSON format for processing
- `results/semgrep_output.log` - Analysis log

## Writing Custom Rules

### Basic Rule Structure

```yaml
rules:
  - id: my-rule-id
    message: Description of the issue
    severity: ERROR  # ERROR, WARNING, INFO
    languages: [python]
    metadata:
      cwe: "CWE-89"
      owasp: "A03:2021"
      category: security
    pattern: dangerous_function($USER_INPUT)
```

### Pattern Types

| Pattern | Description |
|---------|-------------|
| `pattern` | Match exact code pattern |
| `pattern-either` | Match any of multiple patterns |
| `pattern-not` | Exclude matches |
| `pattern-inside` | Match within a larger context |
| `pattern-regex` | Use regex matching |
| `patterns` | Combine multiple pattern clauses |

### Metavariables

```yaml
# $VAR matches any expression
pattern: print($VAR)

# Named metavariables track across patterns
patterns:
  - pattern: $FUNC($X)
  - metavariable-regex:
      metavariable: $FUNC
      regex: (eval|exec)
```

### Taint Mode

```yaml
rules:
  - id: sql-injection-taint
    mode: taint
    pattern-sources:
      - pattern: request.GET.get(...)
    pattern-sinks:
      - pattern: cursor.execute($QUERY)
        focus-metavariable: $QUERY
    pattern-sanitizers:
      - pattern: int(...)
```

## Rule Categories

### Injection Rules (`rules/injection/`)

- **sql-injection.yml**: SQL injection via format strings, concatenation, raw queries
- **command-injection.yml**: OS command injection via os.system, subprocess
- **xss.yml**: XSS via mark_safe, format_html, HttpResponse
- **ssti.yml**: Template injection in Django, Jinja2, Flask

### Access Control Rules (`rules/access-control/`)

- **path-traversal.yml**: Directory traversal in file operations
- **idor.yml**: Insecure direct object reference patterns
- **mass-assignment.yml**: Uncontrolled model attribute assignment

### Cryptography Rules (`rules/crypto/`)

- **hardcoded-secrets.yml**: API keys, passwords, tokens in code
- **weak-crypto.yml**: MD5, SHA1, weak random generators

### Other Rules

- **deserialization/insecure-deser.yml**: pickle, yaml, marshal vulnerabilities
- **ssrf/ssrf.yml**: Server-side request forgery patterns
- **xxe/xxe.yml**: XML external entity injection
- **logging/sensitive-data.yml**: Sensitive data in logs

## Detection Matrix

| Vulnerability | CWE | Rule File | Expected |
|--------------|-----|-----------|----------|
| SQL Injection (Auth) | CWE-89 | sql-injection.yml | ✅ |
| SQL Injection (Search) | CWE-89 | sql-injection.yml | ✅ |
| Reflected XSS | CWE-79 | xss.yml | ✅ |
| Stored XSS | CWE-79 | xss.yml | ⚠️ Partial |
| Command Injection | CWE-78 | command-injection.yml | ✅ |
| Path Traversal | CWE-22 | path-traversal.yml | ✅ |
| IDOR | CWE-639 | idor.yml | ❌ |
| Mass Assignment | CWE-915 | mass-assignment.yml | ⚠️ Partial |
| SSRF | CWE-918 | ssrf.yml | ✅ |
| Insecure Deserialization | CWE-502 | insecure-deser.yml | ✅ |
| SSTI | CWE-1336 | ssti.yml | ✅ |
| Hardcoded Secrets | CWE-798 | hardcoded-secrets.yml | ✅ |
| Vulnerable Dependencies | CWE-1035 | N/A | ❌ |
| Sensitive Logging | CWE-532 | sensitive-data.yml | ⚠️ Partial |
| XXE | CWE-611 | xxe.yml | ✅ |
| Brute Force | CWE-307 | N/A | ❌ |

**Expected Detection Rate: 11/16 (68.75%)**

## GitHub Actions Integration

```yaml
- name: Run Semgrep
  uses: returntocorp/semgrep-action@v1
  with:
    config: analysis/semgrep/rules/
    auditOn: push

# Or manual run
- name: Run Semgrep
  run: |
    pip install semgrep
    semgrep scan \
      --config analysis/semgrep/rules/ \
      --config "p/python" \
      --config "p/django" \
      --sarif \
      --output results.sarif \
      vulnerable-app/

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Comparison with Other Tools

| Aspect | Semgrep | Pysa | CodeQL |
|--------|---------|------|--------|
| Speed | Fast | Medium | Slow |
| Taint Analysis | Basic | Deep | Deep |
| Rule Language | YAML | Python DSL | QL |
| Learning Curve | Low | High | High |
| Precision | Medium | High | Very High |
| Community Rules | Large | Limited | Large |

## Best Practices

1. **Use specific patterns**: More specific patterns reduce false positives
2. **Combine pattern types**: Use `patterns` with `pattern-inside` for context
3. **Add metadata**: Include CWE, OWASP references for reporting
4. **Test rules**: Use `semgrep --test` with test files
5. **Document rules**: Clear messages help developers fix issues

## Troubleshooting

### No findings

1. Check rule syntax: `semgrep --validate --config rules/`
2. Verify patterns match: `semgrep --debug`
3. Check exclusions aren't too broad

### Too many findings

1. Add `pattern-not` exclusions
2. Increase minimum severity
3. Add sanitizer patterns

### Slow analysis

1. Limit file scope with `paths`
2. Use `--jobs` for parallelism
3. Avoid overly broad regex patterns

## References

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Semgrep Registry](https://semgrep.dev/explore)
- [Writing Semgrep Rules](https://semgrep.dev/docs/writing-rules/overview/)
- [Semgrep Playground](https://semgrep.dev/editor)

---

*Part of the Taint Analysis Masterclass project*
