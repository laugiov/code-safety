---
title: Pysa
description: Meta's Python Static Analyzer for taint tracking
---

# Pysa

**Pysa** (Python Static Analyzer) is Meta's open-source static analysis tool for Python, built on the Pyre type checker. It specializes in deep inter-procedural taint tracking.

## Overview

| Aspect | Details |
|--------|---------|
| **Developer** | Meta (Facebook) |
| **Website** | [pyre-check.org](https://pyre-check.org/) |
| **License** | MIT |
| **Language** | Python, with `.pysa` model files |
| **Best For** | Complex taint flows in Python applications |

## Key Features

- **Inter-procedural analysis** - Tracks taint across function boundaries
- **Type-aware** - Leverages Pyre's type information for precision
- **Configurable models** - Define custom sources, sinks, and sanitizers
- **Production-tested** - Used at Meta scale
- **SARIF output** - Compatible with standard security tooling

## Quick Start

### Installation

```bash
pip install pyre-check
```

### Verify Installation

```bash
pyre --version
```

### Run Analysis

```bash
cd analysis/pysa
./scripts/run_pysa.sh
```

## Configuration Structure

```
analysis/pysa/
├── .pyre_configuration     # Pyre configuration
├── taint.config            # Taint rules (sources, sinks, rules)
├── models/
│   ├── django_sources.pysa # Django HTTP sources
│   ├── django_sinks.pysa   # Security-sensitive sinks
│   ├── django_sanitizers.pysa
│   ├── third_party.pysa    # Third-party libraries
│   └── vulnshop_custom.pysa
├── model_generators/
│   └── generate_django_models.py
├── scripts/
│   ├── run_pysa.sh
│   └── parse_results.py
└── results/
```

## How Pysa Works

### 1. Define Sources

Sources mark where untrusted data enters:

```python
# models/django_sources.pysa
def django.http.request.HttpRequest.GET.__getitem__(
    self,
    key
) -> TaintSource[UserControlled]: ...
```

### 2. Define Sinks

Sinks mark dangerous operations:

```python
# models/django_sinks.pysa
def django.db.connection.cursor.execute(
    self,
    sql: TaintSink[SQL],
    params = ...
): ...
```

### 3. Define Rules

Rules connect sources to sinks:

```json
{
  "name": "SQL Injection",
  "code": 5001,
  "sources": ["UserControlled"],
  "sinks": ["SQL"],
  "message_format": "SQL Injection: {$sources} → {$sinks}"
}
```

### 4. Add Sanitizers

Sanitizers mark functions that clean data:

```python
# models/django_sanitizers.pysa
def int(
    __x: TaintInTaintOut[LocalReturn, NoTaint]
): ...
```

## VulnShop Results

Pysa detects these vulnerabilities in VulnShop:

| Vulnerability | Detected | Rule Code |
|---------------|:--------:|:---------:|
| SQL Injection (Auth) | ✅ | 5001 |
| SQL Injection (Search) | ✅ | 5001 |
| Command Injection | ✅ | 5003 |
| XSS (Reflected) | ✅ | 5006 |
| XSS (Stored) | ✅ | 5006 |
| Path Traversal | ✅ | 5004 |
| SSRF | ✅ | 5005 |
| Deserialization | ✅ | 5007 |
| SSTI | ✅ | 5010 |
| XXE | ✅ | 5009 |
| Sensitive Logging | ✅ | 5008 |
| IDOR | ⚠️ | - |
| Mass Assignment | ❌ | - |
| Hardcoded Secrets | ❌ | - |

**Detection Rate: 75% (12/16)**

## Section Navigation

<div class="grid cards" markdown>

-   :material-cog:{ .lg .middle } **Configuration**

    ---

    Detailed configuration guide

    [:octicons-arrow-right-24: Configuration](configuration.md)

-   :material-file-document:{ .lg .middle } **Writing Models**

    ---

    Create custom .pysa models

    [:octicons-arrow-right-24: Custom Models](models.md)

-   :material-play:{ .lg .middle } **Running Analysis**

    ---

    Execution and result interpretation

    [:octicons-arrow-right-24: Running Pysa](running.md)

-   :material-star:{ .lg .middle } **Advanced**

    ---

    Advanced techniques and optimization

    [:octicons-arrow-right-24: Advanced](advanced.md)

</div>

## Resources

- [Official Documentation](https://pyre-check.org/docs/pysa-basics/)
- [Pysa GitHub](https://github.com/facebook/pyre-check)
- [Meta Security Blog](https://engineering.fb.com/tag/security/)
