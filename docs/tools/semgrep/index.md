---
title: Semgrep
description: Fast, lightweight static analysis with pattern matching
---

# Semgrep

**Semgrep** is a fast, open-source static analysis tool that finds bugs and security vulnerabilities using pattern matching with a simple YAML-based rule format.

## Overview

| Aspect | Details |
|--------|---------|
| **Developer** | Semgrep Inc. |
| **Website** | [semgrep.dev](https://semgrep.dev/) |
| **License** | LGPL (CLI), Proprietary (Platform) |
| **Language** | YAML rule definitions |
| **Best For** | Fast CI/CD integration and quick pattern detection |

## Key Features

- **Extremely fast** - Typically runs in seconds
- **Simple rule syntax** - YAML-based, easy to learn
- **Large rule registry** - Thousands of community rules
- **Low false positive rate** - Focused patterns reduce noise
- **Taint mode** - Basic dataflow tracking available
- **Multi-language** - Supports 30+ languages

## Quick Start

### Installation

```bash
pip install semgrep
# or
brew install semgrep
```

### Verify Installation

```bash
semgrep --version
```

### Run Analysis

```bash
cd analysis/semgrep
./scripts/run_semgrep.sh
```

Or directly:

```bash
semgrep --config rules/ vulnerable-app/
```

## Configuration Structure

```
analysis/semgrep/
├── .semgrep.yml              # Main configuration
├── rules/
│   ├── injection/
│   │   ├── sql-injection.yml
│   │   ├── command-injection.yml
│   │   ├── xss.yml
│   │   └── ssti.yml
│   ├── access-control/
│   │   ├── path-traversal.yml
│   │   ├── idor.yml
│   │   └── mass-assignment.yml
│   ├── crypto/
│   │   ├── hardcoded-secrets.yml
│   │   └── weak-crypto.yml
│   ├── deserialization/
│   │   └── insecure-deser.yml
│   ├── ssrf/
│   │   └── ssrf.yml
│   ├── xxe/
│   │   └── xxe.yml
│   └── logging/
│       └── sensitive-data.yml
└── scripts/
    └── run_semgrep.sh
```

## How Semgrep Works

### Pattern Matching

Semgrep matches code patterns:

```yaml
rules:
  - id: sql-injection-format-string
    message: SQL injection via format string
    severity: ERROR
    languages: [python]
    pattern: cursor.execute(f"...{$USER_INPUT}...")
```

### Metavariables

Use `$VARIABLE` to match any expression:

```yaml
# Matches: cursor.execute(f"SELECT {anything}")
pattern: cursor.execute(f"...{$X}...")
```

### Pattern Operators

| Operator | Purpose |
|----------|---------|
| `pattern` | Match exact pattern |
| `pattern-either` | Match any of multiple patterns |
| `pattern-not` | Exclude matches |
| `pattern-inside` | Match within context |
| `patterns` | Combine multiple clauses |

### Taint Mode

For dataflow tracking:

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

## VulnShop Results

| Vulnerability | Detected | Rule File |
|---------------|:--------:|:----------|
| SQL Injection (Auth) | ✅ | `sql-injection.yml` |
| SQL Injection (Search) | ✅ | `sql-injection.yml` |
| Command Injection | ✅ | `command-injection.yml` |
| XSS (Reflected) | ✅ | `xss.yml` |
| XSS (Stored) | ⚠️ | `xss.yml` |
| Path Traversal | ✅ | `path-traversal.yml` |
| SSRF | ✅ | `ssrf.yml` |
| Deserialization | ✅ | `insecure-deser.yml` |
| SSTI | ✅ | `ssti.yml` |
| XXE | ✅ | `xxe.yml` |
| Hardcoded Secrets | ✅ | `hardcoded-secrets.yml` |
| IDOR | ❌ | - |

**Detection Rate: 68.75% (11/16)** - Fastest execution (~5s)

## Section Navigation

<div class="grid cards" markdown>

-   :material-file-document:{ .lg .middle } **Writing Rules**

    ---

    Create custom Semgrep rules

    [:octicons-arrow-right-24: Rule Guide](rules.md)

-   :material-graph:{ .lg .middle } **Taint Mode**

    ---

    Dataflow tracking with Semgrep

    [:octicons-arrow-right-24: Taint Mode](taint-mode.md)

-   :material-rocket-launch:{ .lg .middle } **Quick Start**

    ---

    Get running fast

    [:octicons-arrow-right-24: Quick Start](quickstart.md)

</div>

## Using Registry Rules

Semgrep has thousands of pre-built rules:

```bash
# Use official rulesets
semgrep --config "p/python"
semgrep --config "p/django"
semgrep --config "p/owasp-top-ten"
semgrep --config "p/security-audit"

# Combine with custom rules
semgrep --config "p/python" --config "rules/"
```

## CI/CD Integration

```yaml
# GitHub Actions
- name: Semgrep
  uses: semgrep/semgrep-action@v1
  with:
    config: >-
      p/security-audit
      p/python
      analysis/semgrep/rules/
```

## Resources

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Rule Registry](https://semgrep.dev/explore)
- [Rule Playground](https://semgrep.dev/editor)
- [Writing Rules Tutorial](https://semgrep.dev/docs/writing-rules/overview/)
